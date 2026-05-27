"""
modules.oob - 독립형 Out-of-Band (OAST) 콜백 탐지 패키지

외부 모듈에서 임포트해 OOB 탐지를 활성화하는 공개 API:

    from modules.oob import OASTClient, OOBModule, OOBPayload

    # OASTClient 단독 사용 (다른 모듈의 analyze()에서 OOB 강화)
    client = OASTClient("https://oob.example.com", poll_retries=3, poll_delay=5.0)
    token, callback_url = client.generate_token()
    await requester(callback_url)
    hit = (await client.wait_for_callback(token)) is not None

    # OOBModule 단독 사용 (--type oob 스캔)
    module = OOBModule(oast_client=client)
"""

from modules.oob.client import OASTCallbackDetail, OASTClient
from modules.oob.module import OOBModule, OOBPayload

__all__ = [
    "OASTClient",
    "OASTCallbackDetail",
    "OOBModule",
    "OOBPayload",
]
