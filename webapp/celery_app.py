from __future__ import annotations

import os

from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "scanner_worker",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["webapp.tasks"],
)

celery_app.conf.update(
    timezone="Asia/Seoul",
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # 워커가 스캔 중 OOM/크래시로 죽어도 작업을 잃지 않음
    task_acks_late=True,
    # 워커 하나가 무거운 스캔을 한 번에 하나씩만 가져가도록 제한
    worker_prefetch_multiplier=1,
    # 태스크 결과는 1일 보관
    result_expires=86400,
)
