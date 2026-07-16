# [gjc bug] Directed SDK response delivery failure terminates the session through an unhandled rejection

- fingerprint: gjc-internal|unhandled rejection|sdk connection is not available|at sendTo
- severity: high   count: 4   source: central log + active session
- first/last seen: 2026-07-16T04:19:37.758+09:00 / 2026-07-16T04:19:37.766+09:00
- status: draft   (사람이 검토 후 직접 제출)

## 증상 (관측)

```text
sdk: directed response delivery failed for connection:13
Unhandled rejection: Error: SDK connection is not available
    at sendTo (unknown)
    at RL (/$bunfs/root/gjc-linux-x64:13494:22066)
    at #A (/$bunfs/root/gjc-linux-x64:13483:13921)
```

동일 PID에서 directed-delivery 경고 뒤 unhandled rejection이 네 번 발생했고 GJC TUI가 셸로 종료됐다. 세션 복원 명령으로 작업은 복구됐다.

## upstream 중복 확인

GitHub issues/PR 검색에서 정확한 `SDK connection is not available` 및 `directed response delivery failed` 문자열은 0건이었다. upstream dev에서 해당 실패를 해결한 항목도 확인되지 않았다. 재귀 cleanup 로그는 별도 기존 #1462/PR #1465로 해결된 항목이므로 이 초안에서 제외한다.

## 제안 수정

연결이 사라진 directed-response 대상은 SDK transport 소유 경계에서 terminal delivery failure로 settle하고, fire-and-forget 경로의 rejection을 반드시 관측한다. 동일 연결에 대기 중인 응답은 한 번만 실패 처리하며 process-level unhandledRejection과 전역 cleanup을 유발하지 않도록 회귀 테스트를 추가한다.
