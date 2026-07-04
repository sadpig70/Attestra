# AttestraPacks Design @v:0.1

> `DESIGN-Attestra.md`의 `Packs` 노드 `(decomposed)` 분리 트리. 1차 도메인 팩 = HELIX corpus의
> **거버넌스·신뢰 군집**을 `PackContract`(predicate(packet,P)->CheckResult)로 투영한 것.
> 각 팩은 원본 프로젝트(github.com/sadpig70/*)의 predicate 계약만 적재하며 커널 로직을 재정의하지 않는다.
> HandbackPack이 **레퍼런스 팩**(ActionHandbackVerifier 5-predicate와 동일 verdict를 내는 정합성 기준).

---

## 1. Gantree — 1차 팩 (10종)

```
AttestraPacks // 1차 도메인 팩 (governance·trust cluster) (designing) @v:0.1
    HandbackPack // ActionHandbackVerifier 포팅 — 레퍼런스 팩 (designing) #reference
    SpendBoundaryPack // 컨텍스트 경계 지출 재인가 게이트 (designing)
    VetoEscrowPack // 중단 가능 청산 게이트 (거부권·escrow) (designing)
    DelegationPack // 위임 사전심사(trust envelope·liability) (designing)
    WithheldActionPack // 고위험 릴리스 보류 정당성 검증 (designing)
    PolicyDriftPack // 승인 정책 baseline drift 판정 (designing)
    CustodyRelayPack // 오프라인 인계 custody·integrity·relay (designing)
    SlotGatePack // 타임박스 실행 슬롯 재인가 (designing)
    ContextBoundaryPack // cross-scope 컨텍스트 공격경로 랭킹 (designing)
    ActionGovernancePack // pre/in-flight/post 행위 판정 (designing)
    ReproDossierPack // (2차·provenance) 출력해시 일치 재현성 증명 (done)
    GenCertPack // (2차·provenance) 생성기 1회 인증→신뢰 상속 (done)
```

> ReproDossierPack·GenCertPack은 **provenance/trust 서브클러스터**(거버넌스와 다른 계열) 팩으로,
> **커널 무수정**(매니페스트+predicate+스키마만)으로 등록됨 — PackContract 일반성 증명.

> depth ≤ 2 유지 — 팩 predicate 상세는 각 노드 아래 간략 PPR(`#`)로 기술. 커널 계약이 이미
> `predicate(packet, P) -> CheckResult`를 고정하므로 팩은 predicate 목록 + verdict 규칙만 명세하면 된다.

---

## 2. 팩별 명세 (간략 PPR)

### HandbackPack — 레퍼런스 팩 (source: ActionHandbackVerifier)

```
HandbackPack // 위임 행위 handback 경계 검증 (designing) #reference
    # source_project: github.com/sadpig70/ActionHandbackVerifier
    # predicates: authority, custody, route, rollback, trace  (5-predicate)
    # packet_schema: schemas/packet-handback.schema.json
    # authority : delegation.authority_id 유효 + action ∈ allowed_actions + 미만료 → valid, else breach
    # custody   : sender→receiver 확인 + confirmation 존재 → valid, evidence 미비 → thin
    # route     : actual_route ⊆ planned_route 정책 + route_status ok → valid, 이탈 → breach
    # rollback  : required면 completed + restoration_hash 존재 → valid, required∧미완 → breach
    # trace     : public digest + evidence_path 존재, 사적 payload 없음 → valid, digest 결측 → thin
    # criteria: 집계 verdict가 원본 ActionHandbackVerifier evaluate_handback()과 동일 (정합성 기준)
```

### SpendBoundaryPack (source: SpendBoundary = ContextCreep+SpendMesh+VetoEscrow)

```
SpendBoundaryPack // AI 에이전트 컨텍스트 경계 지출 게이트 (designing)
    # source_project: github.com/sadpig70/SpendBoundary
    # predicates: context_boundary, veto_policy
    # context_boundary : spend_context index < current_context index → boundary_crossed(thin/breach by gap)
    #   # 4-level context (session/task/tool/external), gap 클수록 severity 상승
    # veto_policy      : amount+gap combo · blocked_recipients · restricted_tools → vetoed=breach
    # note: 커널 Pipeline으로 3개 원본 팩을 합성할 수도 있음 — 우선 단일 팩으로 포팅 후 Pipeline 재현 검증
```

### VetoEscrowPack (source: VetoEscrow)

```
VetoEscrowPack // 중단 가능 고위험 결정 청산 게이트 (designing)
    # source_project: github.com/sadpig70/VetoEscrow
    # predicates: veto_window, escrow_state, interrupt_bound
    # veto_window   : 결정이 거부권 창(window) 내 재검토 가능 상태인가 → 아니면 breach
    # escrow_state  : escrow 잠금·해제 조건 충족 → valid, 미확정 → thin
    # interrupt_bound: veto 인터럽트가 bound 내 처리 → valid, 초과 → breach
```

### DelegationPack (source: DelegationUnderwriter)

```
DelegationPack // 위임 작업 사전심사 (trust envelope·liability) (designing)
    # source_project: github.com/sadpig70/DelegationUnderwriter
    # predicates: trust_envelope, liability_limit, authority_scope
    # trust_envelope : 위임 작업이 신뢰 봉투 범위 내 → valid, 초과 → breach
    # liability_limit: 예상 손해 ≤ 책임 한도 → valid, 근접 → thin, 초과 → breach
    # authority_scope: 위임된 권한이 위임자 권한의 부분집합 → valid, 상향 위임 → breach
```

### WithheldActionPack (source: WithheldActionWitness)

```
WithheldActionPack // 고위험 릴리스 보류 정당성 검증 (designing)
    # source_project: github.com/sadpig70/WithheldActionWitness
    # predicates: duty, exposure, rollback, authority
    # duty     : 보류가 명시된 duty 근거를 가지는가 → 없으면 thin
    # exposure : 보류로 회피된 노출이 문서화 → valid, 미비 → thin
    # rollback : 보류 상태가 rollback 가능 → valid, 불가 → breach
    # authority: 보류 권한자가 유효 → valid, 무권한 보류 → breach
```

### PolicyDriftPack (source: PolicyDriftDossier)

```
PolicyDriftPack // 승인 정책 baseline drift 판정 (designing)
    # source_project: github.com/sadpig70/PolicyDriftDossier
    # predicates: baseline_match, drift_magnitude, approval_trace
    # baseline_match : 현재 배포가 승인 baseline과 대조 가능 → 아니면 thin
    # drift_magnitude: drift ≤ 허용 임계 → valid, 근접 → thin, 초과 → breach
    # approval_trace : 변경에 승인 추적 존재 → valid, 무승인 변경 → breach
```

### CustodyRelayPack (source: CustodyRelayDocket)

```
CustodyRelayPack // 오프라인 아티팩트 인계 custody·integrity·relay (designing)
    # source_project: github.com/sadpig70/CustodyRelayDocket
    # predicates: custody_chain, integrity_hash, relay_policy
    # custody_chain : sender→relay→receiver 연속성 → 단절 시 breach
    # integrity_hash: 아티팩트 digest 송수신 일치 → valid, 결측 → thin, 불일치 → breach
    # relay_policy  : relay 경로가 정책 내 → valid, 이탈 → breach
```

### SlotGatePack (source: SlotGate / SlotSettleGate)

```
SlotGatePack // 타임박스 실행 슬롯 재인가 게이트 (designing)
    # source_project: github.com/sadpig70/SlotGate
    # predicates: slot_authorization, slot_expiry, reauth_trace
    # slot_authorization: 실행이 인가된 슬롯 내 → 아니면 breach
    # slot_expiry       : 슬롯 미만료 → valid, 만료 임박 → thin, 만료 → breach
    # reauth_trace      : 슬롯 연장 시 재인가 추적 존재 → valid, 무재인가 연장 → breach
```

### ContextBoundaryPack (source: ContextCreep)

```
ContextBoundaryPack // cross-memory-scope 컨텍스트 공격경로 랭킹 (designing)
    # source_project: github.com/sadpig70/ContextCreep
    # predicates: scope_crossing, policy_gap, path_rank
    # scope_crossing: 컨텍스트가 memory scope 경계를 넘는가 → 넘으면 평가 진행
    # policy_gap    : 원 scope와 대상 tool의 정책 차이 존재 → 크면 breach
    # path_rank     : 공격경로 위험 점수 ≤ 임계 → valid, 초과 → breach (랭킹은 결정론 점수)
```

### ActionGovernancePack (source: AgentActionGovernanceOS)

```
ActionGovernancePack // 에이전트 행위 pre/in-flight/post 판정 (designing)
    # source_project: github.com/sadpig70/AgentActionGovernanceOS
    # predicates: pre_approval, in_flight_safety, post_justification
    # pre_approval      : 행위 사전 승인 존재 → 없으면 breach
    # in_flight_safety  : 실행 중 안전 불변식 유지 → 위반 시 breach
    # post_justification: 사후 정당화 증거 존재 → valid, 미비 → thin
```

---

## 3. 팩 확장 규칙 (다음 파도)

corpus 거버넌스·신뢰 군집에서 2차 파도 후보 (동일 계약으로 적재 가능):
`GenCert · MethodBond · ReproDossier · AfferentCore · AfferentInterrupt · LoopKit · PnR · AgentPACT · ADPR`.
clearing 군집(vertical B)은 별도 `PackContract` 확장(bid pool → clearing)으로 후속 설계.

```text
PackExpansionRule
    SameContract // predicate(packet,P)->CheckResult 준수하면 팩 추가 = 매니페스트 + predicate 파일만
    NoKernelChange // 커널 수정 없이 팩 등록 (플랫폼성의 증거)
    DedupByFingerprint // 중복 재조합 팩은 PackLoader가 거부 (SpendBoundary류 방지)
    ProvenanceTagged // 각 팩은 source_project로 원본 저장소 추적 가능 (federate)
```
