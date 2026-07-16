# [gjc bug] Repeated SIGTERM during postmortem cleanup logs a recursive-cleanup error

- fingerprint: gjc-internal|cleanup invoked recursively|at runcleanup (/tmp/gjc-lsp-epipe/packages/utils/src/postmortem.ts:l:c)
- related fingerprint: gjc-internal|cleanup invoked recursively|at tm (/$bunfs/root/gjc-linux-x64:l:c)
- severity: high   count: 5   source: log
- first/last seen: 2026-07-13T03:10:02.805+09:00 / 2026-07-14T08:21:52.439+09:00
- status: draft   (사람이 검토 후 직접 제출)

## 증상 (관측)

`Cleanup invoked recursively`가 총 5회 기록됐다. 소스 실행 표본의 스택 상단은 다음과 같다.

```text
Error
    at runCleanup (/tmp/gjc-lsp-epipe/packages/utils/src/postmortem.ts:59:62)
    at runCleanupAndWait (/tmp/gjc-lsp-epipe/packages/utils/src/postmortem.ts:94:7)
    at <anonymous> (/tmp/gjc-lsp-epipe/packages/utils/src/postmortem.ts:204:10)
```

`postmortem.ts:204`는 `SIGTERM` 핸들러이므로, 기존 #1462/PR #1465가 해결한 `Reason.EXIT` 재진입과는 다른 비-EXIT 재진입이다. upstream 검색에서 SIGTERM 재진입을 추적하는 별도 이슈/PR은 발견되지 않았다.

## 재현 (추정)

1. 종료 콜백이 충분히 오래 걸리도록 등록한다.
2. 프로세스에 `SIGTERM`을 보낸다.
3. 첫 cleanup이 끝나기 전에 두 번째 `SIGTERM`을 보낸다.
4. 두 번째 핸들러가 `cleanupStage === "running"`인 `runCleanup()`에 들어가 error 로그를 남기는지 확인한다.

관측 스택으로 SIGTERM 재진입은 확인됐지만, 첫 cleanup을 시작한 정확한 reason과 신호 발생 주체는 확인되지 않았다.

## 원인 (소스 근거)

`dev` 26bb02e의 `packages/utils/src/postmortem.ts:51-63`에서 cleanup 실행 중 모든 비-EXIT 호출을 오류로 기록하고 즉시 resolve한다. 같은 파일 `:203-205`의 SIGTERM 핸들러는 중복 신호를 coalesce하는 guard 없이 매번 `runCleanupAndWait(Reason.SIGTERM)`을 호출한다. 따라서 첫 SIGTERM cleanup이 진행 중일 때 후속 SIGTERM이 들어오면 이 오류 경로가 그대로 실행된다.

## 제안 수정 (선택)

추정: 현재 실행 중인 cleanup reason을 보존하고, 동일한 종료 신호의 재진입은 기존 `cleanupPromise`에 합류시키되 오류로 기록하지 않는다. 서로 다른 fatal reason의 재진입 진단은 유지하고, 중복 SIGTERM/SIGHUP에 대한 subprocess 회귀 테스트를 추가한다.
