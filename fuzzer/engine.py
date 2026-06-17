from __future__ import annotations

import asyncio
import dataclasses
from dataclasses import dataclass
from inspect import isawaitable
from typing import Any, Awaitable, Callable, Iterable, Protocol

import aiohttp
from fuzzer.payload_source import ModulePayloadSource, iter_attack_batches
from fuzzer.request_builder import send_baseline_request, FuzzerResponse
from fuzzer.runtime_config import FuzzerRuntimeConfig, configure_fuzzer_runtime, get_fuzzer_runtime_config

try:
    from core.models import AttackSurface  # type: ignore
except (ImportError, AttributeError):
    # Temporary fallback for bootstrap phase where models are incomplete.
    @dataclass(slots=True)
    class AttackSurface:  # type: ignore[no-redef]
        url: str
        method: str = "GET"
        parameters: dict[str, Any] | list[str] | None = None
        headers: dict[str, str] | None = None
        body: dict[str, Any] | str | None = None


@dataclass(slots=True, frozen=True)
class AttackJob:
    surface: AttackSurface
    parameter: str
    payload: Any


@dataclass(slots=True)
class Finding:
    surface: AttackSurface
    parameter: str
    payload: Any
    response: Any
    module_name: str | None = None
    evidences: list[str] | None = None


@dataclass(slots=True)
class EngineStats:
    queued: int = 0
    completed: int = 0
    failures: int = 0
    findings: int = 0


class AsyncRequestSender(Protocol):
    async def __call__(
        self,
        session: aiohttp.ClientSession,
        surface: AttackSurface,
        parameter: str,
        payload: Any,
        allow_redirects: bool = True,
    ) -> Any: ...


VulnerabilityChecker = Callable[[Any], bool | Awaitable[bool]]
ResultCallback = Callable[[Finding], None | Awaitable[None]]


class AttackModule(Protocol):
    name: str

    def get_payloads(self) -> list[Any]: ...

    def analyze(
        self,
        response: Any,
        payload: Any,
        elapsed_time: float,
        original_res: Any | None = None,
        requester: Callable[[str], Awaitable[Any]] | None = None,
    ) -> tuple[bool, list[str], Any] | Awaitable[tuple[bool, list[str], Any]] | bool | Awaitable[bool]: ...


class FuzzerEngine:
    def __init__(
        self,
        *,
        max_concurrent_requests: int = 20,
        worker_count: int = 10,
        modules: Iterable[AttackModule] | None = None,
        concurrency_per_module: int | None = None,
        session_pool_size: int = 1,
        delay: float = 0.0,
        request_timeout: float = 15.0,
        queue_maxsize: int = 0,
        runtime_config: FuzzerRuntimeConfig | None = None,
    ) -> None:
        if max_concurrent_requests < 1:
            raise ValueError("max_concurrent_requests must be >= 1")
        if worker_count < 1:
            raise ValueError("worker_count must be >= 1")
        if concurrency_per_module is not None and concurrency_per_module < 1:
            raise ValueError("concurrency_per_module must be >= 1")
        if session_pool_size < 1:
            raise ValueError("session_pool_size must be >= 1")
        if delay < 0:
            raise ValueError("delay must be >= 0")

        self.max_concurrent_requests = max_concurrent_requests
        self.worker_count = worker_count
        self.modules = tuple(modules or ())
        self.concurrency_per_module = concurrency_per_module or worker_count
        self.session_pool_size = session_pool_size
        self.delay = delay
        self.request_timeout = request_timeout
        self.runtime_config = runtime_config or get_fuzzer_runtime_config()
        configure_fuzzer_runtime(self.runtime_config)

        self._semaphore = asyncio.Semaphore(max_concurrent_requests)
        self._queue: asyncio.Queue[AttackJob | None] = asyncio.Queue(maxsize=queue_maxsize)
        self._module_queues: dict[str, asyncio.Queue[AttackSurface | None]] = {}
        self._module_payload_sources: dict[str, ModulePayloadSource] = {}
        self._module_stop_events: dict[str, asyncio.Event] = {}
        self._module_workers: list[asyncio.Task[None]] = []
        self._module_runtime_active = False
        self._stats = EngineStats()
        self._stats_lock = asyncio.Lock()
        self._findings: list[Finding] = []

    @staticmethod
    def _chunked(items: list[Any], size: int) -> Iterable[list[Any]]:
        if size <= 0:
            size = 1
        for index in range(0, len(items), size):
            yield items[index : index + size]

    @property
    def stats(self) -> EngineStats:
        return EngineStats(
            queued=self._stats.queued,
            completed=self._stats.completed,
            failures=self._stats.failures,
            findings=self._stats.findings,
        )

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    def consume_findings(self) -> list[Finding]:
        """내부 findings 리스트를 반환하고 즉시 비운다.

        ``findings`` 프로퍼티(복사본 반환)와 달리 추가 복사 없이 원본 리스트를
        호출자에게 넘기고 엔진 내부는 새 빈 리스트로 초기화한다.
        파이프라인 모드에서 모듈 간 메모리 이전 시 사용한다.
        """
        findings = self._findings
        self._findings = []
        return findings

    def _create_session_pool(self) -> list[aiohttp.ClientSession]:
        timeout = aiohttp.ClientTimeout(total=self.request_timeout)
        connector_limit = max(
            2,
            (self.max_concurrent_requests * 2 + self.session_pool_size - 1) // self.session_pool_size,
        )
        return [
            aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(limit=connector_limit),
            )
            for _ in range(self.session_pool_size)
        ]

    async def run(
        self,
        *,
        surfaces: Iterable[AttackSurface],
        payloads: Iterable[Any],
        request_sender: AsyncRequestSender,
        is_vulnerable: VulnerabilityChecker,
        on_finding: ResultCallback | None = None,
    ) -> EngineStats:
        payload_list = list(payloads)
        if not payload_list:
            raise ValueError("payloads must not be empty")

        sessions = self._create_session_pool()
        try:
            workers = [
                asyncio.create_task(
                    self._worker(
                        worker_id=index + 1,
                        session=sessions[index % len(sessions)],
                        request_sender=request_sender,
                        is_vulnerable=is_vulnerable,
                        on_finding=on_finding,
                    )
                )
                for index in range(self.worker_count)
            ]

            await self._enqueue_jobs(surfaces=surfaces, payloads=payload_list)
            await self._queue.join()

            for _ in workers:
                await self._queue.put(None)
            await asyncio.gather(*workers, return_exceptions=False)
        finally:
            await asyncio.gather(*(session.close() for session in sessions))

        return self.stats

    async def _enqueue_jobs(
        self,
        *,
        surfaces: Iterable[AttackSurface],
        payloads: list[Any],
    ) -> None:
        for surface in surfaces:
            for parameter in self._iter_parameters(surface):
                for payload in payloads:
                    await self._queue.put(
                        AttackJob(surface=surface, parameter=parameter, payload=payload)
                    )
                    async with self._stats_lock:
                        self._stats.queued += 1

    async def _worker(
        self,
        *,
        worker_id: int,
        session: aiohttp.ClientSession,
        request_sender: AsyncRequestSender,
        is_vulnerable: VulnerabilityChecker,
        on_finding: ResultCallback | None,
    ) -> None:
        while True:
            job = await self._queue.get()
            if job is None:
                self._queue.task_done()
                return

            try:
                await self._process_job(
                    session=session,
                    job=job,
                    request_sender=request_sender,
                    is_vulnerable=is_vulnerable,
                    on_finding=on_finding,
                )
            except Exception as exc:
                async with self._stats_lock:
                    self._stats.failures += 1
                print(f"[worker:{worker_id}] request failed: {exc}")
            finally:
                async with self._stats_lock:
                    self._stats.completed += 1
                self._queue.task_done()

    async def _process_job(
        self,
        *,
        session: aiohttp.ClientSession,
        job: AttackJob,
        request_sender: AsyncRequestSender,
        is_vulnerable: VulnerabilityChecker,
        on_finding: ResultCallback | None,
    ) -> None:
        async with self._semaphore:
            response = await request_sender(
                session=session,
                surface=job.surface,
                parameter=job.parameter,
                payload=job.payload,
            )

            if self.delay > 0:
                await asyncio.sleep(self.delay)

        verdict = is_vulnerable(response)
        is_hit = await verdict if isawaitable(verdict) else verdict
        if not is_hit:
            return

        finding = Finding(
            surface=job.surface,
            parameter=job.parameter,
            payload=job.payload,
            response=response,
        )
        self._findings.append(finding)
        async with self._stats_lock:
            self._stats.findings += 1

        if on_finding is not None:
            callback_result = on_finding(finding)
            if isawaitable(callback_result):
                await callback_result

    async def run_with_attack_modules(
        self,
        *,
        surfaces: Iterable[AttackSurface],
        request_sender: AsyncRequestSender,
        on_finding: ResultCallback | None = None,
    ) -> EngineStats:
        """
        Module-oriented execution mode.
        - Creates one queue per attack module.
        - Dispatches each incoming surface into every module queue.
        - Loads module payloads once per worker at startup.
        """
        if not self.modules:
            raise ValueError("modules must be configured to run module queue mode")

        sessions = self._create_session_pool()
        try:
            await self.start_module_mode(
                sessions=sessions,
                request_sender=request_sender,
                on_finding=on_finding,
            )

            for surface in surfaces:
                await self.submit_surface(surface)

            await self.stop_module_mode()
        finally:
            await asyncio.gather(*(session.close() for session in sessions))

        return self.stats

    async def start_module_mode(
        self,
        *,
        sessions: list[aiohttp.ClientSession],
        request_sender: AsyncRequestSender,
        on_finding: ResultCallback | None = None,
    ) -> None:
        """
        Start module workers.
        Useful when parser/crawler streams surfaces over time.
        """
        if self._module_runtime_active:
            raise RuntimeError("module mode is already running")
        if not self.modules:
            raise ValueError("modules must be configured before starting module mode")
        if not sessions:
            raise ValueError("sessions must not be empty")

        self._module_queues = {
            module.name: asyncio.Queue()
            for module in self.modules
        }
        self._module_payload_sources = {
            module.name: ModulePayloadSource(
                module,
                cache_enabled=self.runtime_config.cache_module_payloads,
            )
            for module in self.modules
        }
        self._module_stop_events = {
            module.name: asyncio.Event()
            for module in self.modules
        }
        self._module_workers = []

        for module in self.modules:
            queue = self._module_queues[module.name]
            payload_source = self._module_payload_sources[module.name]
            for index in range(self.concurrency_per_module):
                worker = asyncio.create_task(
                    self._module_worker(
                        worker_id=index + 1,
                        session=sessions[index % len(sessions)],
                        module=module,
                        queue=queue,
                        payload_source=payload_source,
                        request_sender=request_sender,
                        on_finding=on_finding,
                    )
                )
                self._module_workers.append(worker)

        self._module_runtime_active = True

    async def submit_surface(self, surface: AttackSurface) -> None:
        """
        Dispatch one parser-provided surface into every module queue.
        """
        if not self._module_runtime_active:
            raise RuntimeError("module mode is not running")

        for module in self.modules:
            stop_event = self._module_stop_events[module.name]
            if stop_event.is_set():
                continue
            payload_source = self._module_payload_sources.get(module.name)
            queue = self._module_queues[module.name]
            params = tuple(self._iter_parameters(surface))
            selector = getattr(module, "get_target_parameters", None)
            if callable(selector):
                selected = selector(surface, params)
                params = tuple(selected) if selected is not None else ()

            await queue.put(surface)
            payload_count = payload_source.count() if payload_source is not None else 0
            async with self._stats_lock:
                self._stats.queued += len(params) * payload_count

    async def stop_module_mode(self) -> None:
        """
        Wait until all module queues drain, then stop workers.
        """
        if not self._module_runtime_active:
            return

        for queue in self._module_queues.values():
            await queue.join()

        for module in self.modules:
            queue = self._module_queues[module.name]
            for _ in range(self.concurrency_per_module):
                await queue.put(None)

        await asyncio.gather(*self._module_workers, return_exceptions=False)
        self._module_workers.clear()
        self._module_queues.clear()
        self._module_payload_sources.clear()
        self._module_stop_events.clear()
        self._module_runtime_active = False

    async def _module_worker(
        self,
        *,
        worker_id: int,
        session: aiohttp.ClientSession,
        module: AttackModule,
        queue: asyncio.Queue[AttackSurface | None],
        payload_source: ModulePayloadSource,
        request_sender: AsyncRequestSender,
        on_finding: ResultCallback | None,
    ) -> None:
        while True:
            surface = await queue.get()
            if surface is None:
                queue.task_done()
                return

            try:
                stop_event = self._module_stop_events.get(module.name)
                if stop_event is not None and stop_event.is_set():
                    continue
                params = tuple(self._iter_parameters(surface))
                selector = getattr(module, "get_target_parameters", None)
                if callable(selector):
                    selected = selector(surface, params)
                    params = tuple(selected) if selected is not None else ()
                if not params or payload_source.count() == 0:
                    continue

                payloads = await payload_source.ensure_cached()
                baseline_response = await send_baseline_request(session, surface)
                batch_size = max(1, self.max_concurrent_requests)
                for batch in iter_attack_batches(params, payloads, batch_size):
                    if stop_event is not None and stop_event.is_set():
                        break
                    tasks = [
                        asyncio.create_task(
                            self._process_module_attack(
                                worker_id=worker_id,
                                module=module,
                                session=session,
                                surface=surface,
                                parameter=parameter,
                                payload=payload,
                                baseline_response=baseline_response,
                                request_sender=request_sender,
                                on_finding=on_finding,
                            )
                        )
                        for parameter, payload in batch
                    ]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for result in results:
                        if isinstance(result, Exception):
                            print(
                                f"[worker:{worker_id}][{module.name}] "
                                f"batch task failed: {result}"
                            )
            finally:
                queue.task_done()

    async def _process_module_attack(
        self,
        *,
        worker_id: int,
        module: AttackModule,
        session: aiohttp.ClientSession,
        surface: AttackSurface,
        parameter: str,
        payload: Any,
        baseline_response: Any,
        request_sender: AsyncRequestSender,
        on_finding: ResultCallback | None,
    ) -> None:
        stop_event = self._module_stop_events.get(module.name)
        allow_redir = getattr(module, "allow_redirects", True)
        try:
            if stop_event is not None and stop_event.is_set():
                return

            bind_hook = getattr(module, "bind_payload", None)
            if callable(bind_hook):
                hook_result = bind_hook(surface, parameter, payload)
                payload = await hook_result if isawaitable(hook_result) else hook_result

            response: Any
            
            payload_value = str(getattr(payload, "value", payload))
            is_serial = getattr(payload, "_is_serial", False)

            if payload_value == "1" and is_serial:
                # 더미 요청 발송을 생략하고 비어있는 FuzzerResponse 객체 생성
                response = FuzzerResponse(
                    status=0,
                    text="",
                    headers={},
                    elapsed_time=0.0,
                    url=surface.url,
                    error="Skipped dummy request"
                )
            else:
                try:
                    async with self._semaphore:
                        response = await request_sender(
                            session=session,
                            surface=surface,
                            parameter=parameter,
                            payload=payload,
                            allow_redirects=allow_redir,
                        )
                except Exception as exc:
                    async with self._stats_lock:
                        self._stats.failures += 1
                    print(f"[worker:{worker_id}][{module.name}] request failed: {exc}")
                    return

                if self.delay > 0:
                    # Sleep outside semaphore so slots are not blocked by throttle waits.
                    await asyncio.sleep(self.delay)

            elapsed_time = float(
                getattr(response, "elapsed_time", getattr(response, "elapsed", 0.0))
            )

            async def module_requester(new_payload_value: str):
                mutated_payload = dataclasses.replace(payload, value=new_payload_value)
                async with self._semaphore:
                    return await request_sender(
                        session=session,
                        surface=surface,
                        parameter=parameter,
                        payload=mutated_payload,
                        allow_redirects=allow_redir,
                    )

            analyze_kwargs = {
                "response": response,
                "payload": payload,
                "elapsed_time": elapsed_time,
                "original_res": baseline_response,
                "requester": module_requester,
            }
            try:
                verdict = module.analyze(**analyze_kwargs, surface=surface)
            except TypeError:
                verdict = module.analyze(**analyze_kwargs)

            if isawaitable(verdict):
                verdict = await verdict

            if isinstance(verdict, tuple):
                if len(verdict) == 3:
                    is_hit, evidences, actual_payload = verdict
                elif len(verdict) == 2:
                    is_hit, evidences = verdict
                    actual_payload = payload
                else:
                    is_hit = verdict[0]
                    evidences = []
                    actual_payload = payload
            else:
                is_hit = bool(verdict)
                evidences = []
                actual_payload = payload

            if not is_hit:
                return

            verify_hook = getattr(module, "verify", None)
            if callable(verify_hook):
                verify_result = verify_hook(
                    session=session,
                    surface=surface,
                    parameter=parameter,
                    payload=actual_payload,
                    response=response,
                    baseline_response=baseline_response,
                )
                is_verified = (
                    await verify_result if isawaitable(verify_result) else bool(verify_result)
                )
                if not is_verified:
                    return

            finding = Finding(
                surface=surface,
                parameter=parameter,
                payload=actual_payload,
                response=response,
                module_name=module.name,
                evidences=evidences
            )
            self._findings.append(finding)
            async with self._stats_lock:
                self._stats.findings += 1

            if on_finding is not None:
                callback_result = on_finding(finding)
                if isawaitable(callback_result):
                    await callback_result

            stop_on_first_hit = bool(getattr(module, "stop_on_first_hit", False))
            if stop_on_first_hit and stop_event is not None and not stop_event.is_set():
                stop_event.set()
                print(f"[*] [{module.name}] stop-on-first-hit triggered; skipping remaining payloads.")
        except Exception as exc:
            async with self._stats_lock:
                self._stats.failures += 1
            print(f"[worker:{worker_id}][{module.name}] attack task failed: {exc}")
        finally:
            async with self._stats_lock:
                self._stats.completed += 1

    @staticmethod
    def _dynamic_token_names(surface: AttackSurface) -> set[str]:
        raw_tokens = getattr(surface, "dynamic_tokens", None)
        if not raw_tokens:
            return set()
        if isinstance(raw_tokens, dict):
            return {str(name) for name in raw_tokens.keys() if str(name)}
        if isinstance(raw_tokens, (list, tuple, set)):
            return {str(name) for name in raw_tokens if str(name)}
        token_name = str(raw_tokens).strip()
        return {token_name} if token_name else set()

    @classmethod
    def _iter_parameters(cls, surface: AttackSurface) -> Iterable[str]:
        params = getattr(surface, "parameters", None)
        dynamic_token_names = cls._dynamic_token_names(surface)
        if params is None:
            return ()
        if isinstance(params, dict):
            return tuple(
                key for key in params.keys()
                if str(key) not in dynamic_token_names
            )
        return tuple(
            str(p) for p in params
            if str(p) not in dynamic_token_names
        )