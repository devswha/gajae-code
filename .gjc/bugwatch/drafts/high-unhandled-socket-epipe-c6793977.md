# [gjc bug] Background socket send can surface as an unhandled EPIPE rejection

- fingerprint: gjc-internal|unhandled rejection|at write (unknown)
- severity: high   count: 1   source: log
- first/last seen: 2026-07-12T21:07:44.079+09:00 / 2026-07-12T21:07:44.079+09:00
- status: draft   (사람이 검토 후 직접 제출)

## 증상 (관측)

```text
Unhandled rejection
Error: EPIPE: broken pipe, send
    at write (unknown)
    at ZbD (/$bunfs/root/gjc-linux-x64:8686:4538)
    at processTicksAndRejections (native:7:39)
```

오류 객체는 `code: EPIPE`, `syscall: send`, `fd: 39`였다. upstream 검색에서는 stdout EPIPE를 해결한 #2098/PR #2099와 LSP stdin EPIPE를 해결한 #2138/PR #2210만 확인됐으며, 둘 다 `syscall: send`인 소켓 경로를 수정 범위에서 명시적으로 제외한다.

## 재현 (추정)

1. gjc가 백그라운드 네트워크 전송을 수행하는 동안 상대 peer를 종료한다.
2. 닫힌 소켓에 후속 send가 발생하도록 한다.
3. 전송 소유자가 peer-close를 처리하지 않아 process-level `unhandledRejection`으로 올라오는지 확인한다.

컴파일 바이너리 스택만 남아 있어 구체적인 transport와 최소 재현 절차는 아직 특정하지 못했다.

## 원인 (소스 근거)

`dev` 26bb02e의 소스에서는 이 minified 프레임을 원본 심볼로 확정할 수 없었다. `packages/utils/src/postmortem.ts:194-199`는 소유 transport에서 처리되지 않은 rejection을 최종적으로 fatal 경로에 기록한다. PR #2099의 process-level 정책과 PR #2210의 LSP sink 정책은 각각 stdout 및 LSP stdin에 한정되므로 이 `send` EPIPE의 소유 경계는 확인되지 않은 상태다.

## 제안 수정 (선택)

추정: sourcemap 또는 동일 시나리오의 source-mode 실행으로 `ZbD`의 transport를 먼저 식별한다. 해당 transport가 소유한 socket write/send 경계에서 peer-close EPIPE만 terminalize하고, pending 요청을 안정된 transport-closed 오류로 settle한다. 전역적으로 모든 EPIPE를 숨기면 unrelated sink 오류를 삼키므로 피한다.
