# WORKPLAN-Attestra — 실행 계획 (PGF plan)

> DESIGN-Attestra.md + DESIGN-AttestraPacks.md → 실행 가능한 작업 계획.
> POLICY + 노드 위상정렬 + 검증 게이트. 이 저장소만으로 자립 구동(독립 repo).

## POLICY

```yaml
POLICY:
  max_verify_cycles: 2
  stdlib_only: true              # HELIX/ProjectGenome CI 철학 계승 — 외부 의존 금지
  determinism: strict            # 커널·팩 predicate 시계/네트워크/AI 금지 (now/sim 주입)
  federate_not_fuse: true        # 원본 프로젝트 복사·포크 금지 — predicate 계약만 적재
  single_source_of_truth: true   # verdict/ledger/attestation 커널에 1회만 정의
  reference_pack_parity: true    # HandbackPack verdict == ActionHandbackVerifier (정합성 강제)
  on_blocked: skip_and_continue
  completion: all_done_or_blocked
```

## 노드 순서 (의존 위상정렬)

```text
# ── Phase 1: 커널 (AttestraCore) ──
1.  AttestraCore.Packet         — 증거 패킷 모델 + private-payload 거부
2.  AttestraCore.Verdict        — valid/thin/breach severity 대수
3.  AttestraCore.GateRuntime    @dep:1,2 — predicate 실행 + verdict 집계
4.  AttestraCore.Ledger         — hash-chain append-only 원장 (ActionHandbackVerifier 승격)
5.  AttestraCore.Fingerprint    — 정체성 primitive (HELIX-Core 승격)
6.  AttestraCore.Provenance     @dep:5 — 계보 추적 + attestation trace
7.  AttestraCore.Attestation    @dep:2,4,6 — warrant 발행
8.  AttestraCore.Determinism    @dep:3,4 — stdlib·주입 경계 검증기

# ── Phase 2: 팩 계약 (PackContract) ──
9.  PackContract.PackManifest   @dep:1 — 팩 메타 스키마
10. PackContract.PredicateAPI   @dep:3 — predicate 시그니처 계약
11. PackContract.PackLoader     @dep:9,5 — 발견·로드·dedup
12. PackContract.PackRegistry   @dep:11 — 레지스트리 + lookup

# ── Phase 3: 팩 (Packs) — HandbackPack 우선(레퍼런스) ──
13. Packs.HandbackPack          @dep:10 — 레퍼런스 팩 (parity 검증 대상)
14. Packs.[나머지 9종]          @dep:13 — SpendBoundary/VetoEscrow/Delegation/Withheld/
                                          PolicyDrift/CustodyRelay/SlotGate/ContextBoundary/ActionGovernance
                                          [parallel] — 계약 동일, 독립 포팅

# ── Phase 4: 합성 · 인터페이스 ──
15. Pipeline.Compose            @dep:12 — 다중 팩 순차 적용
16. Pipeline.Aggregate          @dep:15 — 팩 간 verdict 집계
17. Schemas                     @dep:1,2,4,7,9 — JSON Schema 5종
18. CLI                         @dep:3,12 — sample/run/verify/report/attest/pack/ledger
19. Docs                        @dep:8 — README/ARCHITECTURE/PACK-CONTRACT/DETERMINISM

# ── Phase 5: 검증 ──
20. Tests                       @dep:13,16 — 커널 + 팩 parity + 파이프라인 unittest
21. VERIFY                      @dep:20 — 3관점 (acceptance/quality/architecture)
```

## 검증 게이트

```text
- 커널·팩 predicate 전부 stdlib import만 (외부 패키지 0)
- 커널·팩 predicate 전부 now/sim 주입식 (Date.now·random·embedding·socket 호출 0)
- hash 입력에서 now/*_at 메타 제외 확인 (시간 무관 재현)
- ★ reference_pack_parity: HandbackPack verdict == ActionHandbackVerifier evaluate_handback() (샘플 3종: valid/thin/breach)
- ★ Pipeline이 SpendBoundary 수동 재조합 결과를 재현 (3-pack 합성 == 원본 단일 verdict)
- PackLoader dedup: 동일 fingerprint 팩 등록 거부 확인
- unittest green + Determinism 검증기 PASS
- 3관점: acceptance(완료기준) · quality(커널/팩 중복 0) · architecture(federate 유지)
```

## 페이즈 전이

```text
Phase1(커널) → Phase2(계약): 커널 8노드 done + Determinism PASS
Phase2 → Phase3(팩): PredicateAPI 계약 확정 + PackRegistry 동작
Phase3 → Phase4: HandbackPack parity 통과 (레퍼런스 검증 선행)
Phase4 → Phase5(검증): 모든 노드 terminal
Phase5 → 완료: VERIFY passed (rework ≤ max_verify_cycles)
```
