# [gjc bug] Scheduled continuation races with another active agent turn

- fingerprint: warn|agent.continue failed after scheduling|
- severity: low   count: 7   source: log
- first/last seen: 2026-07-08T05:44:24.821+09:00 / 2026-07-15T14:50:52.598+09:00
- status: draft   (사람이 검토 후 직접 제출)

## 증상 (관측)

`agent.continue failed after scheduling`이 7회 기록됐고 표본 오류는 다음과 같다.

```text
Agent is already processing. Use steer() or followUp() to queue messages, or wait for completion.
```

upstream 이슈/PR에서 이 메시지나 logger event를 추적하는 항목은 발견되지 않았다.

## 재현 (추정)

1. compaction, queued continuation 또는 overflow retry가 `#scheduleAgentContinue()`를 예약하게 한다.
2. 예약 작업의 사전 조건 검사 이후 `agent.continue()` 호출 전에 다른 경로가 agent processing을 시작하게 한다.
3. 예약 continuation이 `AgentBusyError`로 실패하고 warning이 남는지 확인한다.

정확히 어떤 continuation source가 7건을 발생시켰는지는 로그 표본에 포함되지 않았다.

## 원인 (소스 근거)

`dev` 26bb02e의 `packages/coding-agent/src/session/agent-session.ts:3215-3259`는 generation, abort, queue 상태를 검사한 뒤 별도의 admission reservation 없이 `this.agent.continue()`를 호출한다. 검사와 호출 사이 또는 별도 continuation 경로와의 경쟁에서 agent가 processing 상태가 되면 catch가 `fail()`로 전달되고, `:3204-3211`이 해당 warning을 기록한다. 이 경로에는 `AgentBusyError`를 정상적인 coalescing/skip으로 분류하는 처리가 없다.

## 제안 수정 (선택)

추정: scheduled continuation들을 session 단위 admission으로 직렬화해 check와 `agent.continue()` 시작을 하나의 예약으로 만든다. 이미 같은 generation의 turn이 processing이면 중복 continuation을 명시적인 skip/coalesce로 terminalize하되, 실제로 필요한 queued work가 유실되지 않았음을 검증하는 경쟁 회귀 테스트를 추가한다.
