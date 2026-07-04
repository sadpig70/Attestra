# WORKPLAN-Attestra-Roadmap — 남은 작업 단계별 실행 계획 (anti-drift)

> 긴 작업에서 방향 손실을 막기 위한 **거버넌스 계획서**. 남은 모든 작업을 페이즈로 고정하고,
> 각 페이즈마다 검증 게이트로 "제 위치"를 확인하며 진행한다. 완료 시 이 파일의 status와
> `status-Attestra-Roadmap.json`을 갱신한다. 본 계획은 이미 done인 커널·팩·audit·생애주기 위에서 출발한다.
>
> **현 기준선(2026-07-05):** 커널 + 13팩(3클러스터) + schema 강제 + pipeline + 닫힌 audit 루프 +
> attestation 생애주기(issue/verify/revoke). 64 unittests green, determinism clean(27 files), 39 노드 done.

## POLICY

```yaml
POLICY:
  max_verify_cycles: 2
  stdlib_only: true               # 외부 의존 금지 (기준선 계승)
  determinism: strict             # 커널·팩 시계/네트워크/AI 금지 (now/sim 주입)
  helix_read_only: true           # ★ HELIX(부모 repo)는 읽기만 — 한 줄도 수정 금지
  attestra_standalone: true       # ★ Attestra 독립 자립 구동성 유지 (브리지는 선택적 어댑터)
  kernel_change_only_when_capability: true  # 팩/브리지 추가는 커널 무수정 원칙, 커널 능력 추가 시에만 커널 수정
  gate_each_phase: true           # 각 페이즈 종료 = 검증 게이트 통과 필수
  on_blocked: report_and_hold     # user-gated(공개 등)는 blocked로 대기
```

## Gantree — 남은 작업 (페이즈)

```
AttestraRoadmap // 남은 작업 단계별 실행 계획 (in-progress) @v:0.1
    R1_HelixBridge // HELIX corpus 산출물을 Attestra가 증언 (read-only 어댑터) (done) #bridge
        BridgeIngest // HELIX handback packet + registry 발견·로드 (read-only) (done)
            # input: helix_root; 발견: examples/exploit_state/*.json + .recreate/registry.json
            # is_handback_packet: {handback_id,delegation,custody,route,rollback,trace} ⊆ keys
        BridgeMap // HELIX artifact -> Attestra 처리 (매핑 0 — 형식 동일 확인됨) (done) @dep:BridgeIngest
            # 검증됨: HELIX handback packet == Attestra handback 형식 (직접 소비)
            # registry.generated_projects(dict) -> inventory(project·status·family·archetype·verdict_scheme)
        BridgeAudit // handback 팩으로 평가 -> verdict + verifiable attestation + 원장 (done) @dep:BridgeMap
            # ledger/attestation은 Attestra-side 경로에 기록 (helix_root에 쓰지 않음)
        BridgeCLI // `attestra helix-audit --helix-root ...` 서브커맨드 (done) @dep:BridgeAudit
        BridgeTests // 합성 helix_root 유닛테스트 + 실 D:/HELIX 스모크 (done) @dep:BridgeAudit
    R2_Docs // 외부 확장 문서 — Docs 노드 폐쇄 (designing) #docs @dep:R1_HelixBridge
        ArchitectureDoc // ARCHITECTURE.md — 커널·팩·경계·3클러스터 매핑 (designing)
        PackContractDoc // PACK-CONTRACT.md — 팩 작성법(외부 확장 규격) (designing)
        DeterminismDoc // DETERMINISM.md — 결정론 경계 계약 (designing)
    R3_ReleaseReady // 릴리스 준비 (polish) (designing) #release @dep:R2_Docs
        AttLedgerCLIVerify // `verify --att-ledger` CLI 갭 보완 (designing)
        SmokeScript // scripts/smoke.sh — 전 기능 결정론 스모크 1커맨드 (designing)
        Changelog // CHANGELOG.md + version 0.1.0 확정 (designing)
        FinalVerify // 전체 재검증 (unittest+determinism+audit+bridge) (designing)
    R4_Publish // github.com/sadpig70/Attestra 공개 (blocked) #publish @dep:R3_ReleaseReady
        # user-gated: gh auth + remote create + push — 사용자 명시 승인 필요 (blocked 유지)
```

## 페이즈별 검증 게이트

```text
R1 게이트: 브리지가 실 D:/HELIX handback packet을 verdict=valid로 증언 + 발행 attestation이
          verify_attestation=valid. helix_root 파일 개수 불변(read-only 증명). 커널 무수정
          (git diff attestra_core/ 비어있음). 유닛테스트 green.
R2 게이트: 3개 문서가 실제 코드/노드와 일치(파일명·함수·경계). PACK-CONTRACT로 제3자가 팩
          작성 가능한 수준(handback을 예제로).
R3 게이트: verify --att-ledger 동작. smoke.sh가 unittest+determinism+audit+helix-audit를 순차
          통과. determinism clean 유지. 전체 unittest green.
R4 게이트: (blocked) 사용자 승인 시에만 — remote 생성 + push + 태그.
```

## 페이즈 전이 조건

```text
R1 → R2: 브리지 게이트 통과 (실 HELIX 증언 + attestation 검증 + read-only + 커널 무수정)
R2 → R3: 3개 문서 저장 + 코드 일치 검토 통과 → Docs 노드 done
R3 → R4: FinalVerify green + smoke.sh 통과
R4:     blocked — 사용자 승인 대기 (helix_read_only·attestra_standalone POLICY 무관, 외부 공개 판단)
```

## 진행 규율 (anti-drift)

```text
1. 각 페이즈 시작 시 이 파일 + status-Attestra-Roadmap.json 로드 → 현재 페이즈 확인
2. 페이즈 내 노드를 순서대로 done 처리, status JSON 동시 갱신
3. 페이즈 종료 = 위 검증 게이트 통과 확인 → 보고 → 다음 페이즈 (또는 정지)
4. 범위 밖 아이디어 발생 시 → 이 Gantree에 노드로 append (즉흥 실행 금지) → drift 방지
5. 커널 수정이 필요해지면 → "capability 추가인가" 자문 → 아니면 팩/어댑터로 해결
```

## 검토 (3관점 — 저장 전 self-review)

```text
- 완전성(completeness): 남은 작업(브리지·문서·릴리스·공개)을 모두 포함. 기준선 done 항목은 제외.
  R3에 발견된 실제 갭(verify --att-ledger CLI 부재)을 명시 반영.
- 실현성(feasibility): R1은 HELIX 형식 동일 확인으로 매핑 리스크 0. R2·R3 stdlib·in-repo.
  R4만 외부 의존(gh) → blocked로 격리(정직).
- 순서(ordering): 연결(R1) → 외부화(R2) → 릴리스(R3) → 공개(R4). 의존 @dep 위상 정렬됨,
  순환 없음. R1을 최우선에 둔 근거: 플랫폼 자기완결 후 남은 최고가치는 '연결'(원 비전 증명).
```
