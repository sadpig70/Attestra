# Attestra Design @v:0.1

> PGF design mode 산출. **Attestra = 위임된 자율 행위에 대해 authority·custody·route·rollback·trace
> 증거를 검증하고, 구속력 있는 verdict(valid/thin/breach)를 hash-chain으로 발행하는 결정론 attestation
> 플랫폼.** HELIX corpus의 거버넌스·신뢰 군집(~30개 프로젝트)이 도메인만 다를 뿐 **동일한 기계**
> (packet → predicate 게이트 → verdict → 감사 원장)를 반복한다는 관찰에서 출발한다. Attestra는 그
> 공통 기계를 **커널(attestra-core)** 로 한 번만 정의하고, 각 HELIX 프로젝트를 **팩(pack)** 으로
> 얹는 플랫폼이다. 표기는 `pg`·`pgf`·`pgxf` 스킬 정본. 계보: HELIX → Attestra (자식 저장소, 독립 구동).

---

## 0. 핵심 명제

> **하나의 결정론 verdict 커널 + N개 도메인 팩.** corpus의 각 프로젝트(handback·spend·veto·delegation…)는
> "compact 증거 패킷을 받아 → 독립 predicate 게이트를 돌려 → valid/thin/breach를 판정하고 → hash-chain
> 원장에 남긴다"는 **같은 substrate**를 도메인만 바꿔 재구현한 것이다. Attestra는 그 substrate를 단일
> 출처로 승격하고(desync 제거), 팩은 predicate + 패킷 스키마 확장만 기여한다.

설계 원칙 (HELIX 계승):
1. **커널 단일 출처(single source of truth)** — verdict 대수·원장·provenance·fingerprint는 `attestra-core`에
   한 번만 정의. 팩은 이를 재정의하지 않고 predicate만 제공.
2. **팩은 연합(federate), 흡수 아님** — 각 HELIX 프로젝트는 원본 저장소(github.com/sadpig70/*)에 그대로 있고,
   Attestra는 그 predicate 계약만 `PackContract`로 투영한다. 복사·포크가 아니라 계약 적재.
3. **결정론 경계** — 커널·팩 predicate 경로는 순수 stdlib(시계·네트워크·AI 없음). 시간은 주입(`now`),
   의미 유사도는 주입(`sim`). 임베딩·LLM은 팩 밖(메타층).
4. **증거만, 페이로드 금지** — 패킷은 공개 가능한 증거 digest만 담는다. `payload`/`secret` 등 사적 필드는 거부.

---

## 1. HELIX 기계 → Attestra 매핑

| HELIX corpus 반복 요소 | Attestra 커널 요소 | 결정론 클래스 |
|---|---|---|
| 각 프로젝트의 `evaluate_*(packet)` | **GateRuntime** — predicate 집합 실행 | 순수 결정론 |
| 각 프로젝트의 `valid/thin/breach` | **Verdict** — severity 대수 | 순수 결정론 |
| 각 프로젝트의 `ledger.jsonl` hash-chain | **Ledger** — append-only 감사 원장 | 순수 결정론 (now 주입) |
| ActionHandbackVerifier 5-predicate | **HandbackPack** (레퍼런스 팩) | 순수 결정론 |
| SpendBoundary = 3개 프로젝트 수동 재조합 | **Pipeline** — 다중 팩 합성 (일반화) | 순수 결정론 |
| ExclusiveGrantWarrant "provenance warrant" | **Attestation** — valid verdict → 발행 가능한 warrant | 순수 결정론 |
| HELIX-Core fingerprint | **Fingerprint** (승격) | 순수 결정론 |
| 팩 간 중복 탐지 | **PackLoader** dedup (fingerprint) | 순수 결정론 |

> 핵심 차이: HELIX는 프로젝트를 *생성*하는 창조 루프(explore⊕exploit)다. Attestra는 그 산출물을
> *운영*하는 런타임 플랫폼이다 — corpus를 소재로 하되, 창조가 아니라 통합·구동이 목적이다.

---

## 2. Gantree — Attestra 구조

```
Attestra // 결정론 attestation/verdict 플랫폼 (designing) @v:0.1
    AttestraCore // 커널 — 단일 출처 결정론 verdict substrate (designing) #core
        Packet // 증거 패킷 모델 + private-payload 거부 (designing) #core
        Verdict // valid/thin/breach severity 대수 (designing) #core
        GateRuntime // predicate 게이트 실행 + verdict 집계 (designing) @dep:Packet,Verdict #core
        Ledger // hash-chain append-only 감사 원장 (designing) #core
        Fingerprint // 정체성 primitive (HELIX-Core 승격) (designing) #core
        Provenance // 계보 추적 + attestation trace (designing) @dep:Fingerprint #core
        Attestation // valid verdict → 발행 가능한 warrant (designing) @dep:Verdict,Ledger,Provenance #core
        Determinism // stdlib-only · now/sim 주입 경계 검증기 (designing) #core
    PackContract // 팩 확장 규격 — 모든 도메인 팩의 계약 (designing) @dep:AttestraCore #contract
        PackManifest // 팩 메타(name/version/predicates/schema/fingerprint) (designing) #contract
        PredicateAPI // predicate(packet, P) -> CheckResult 시그니처 (designing) @dep:AttestraCore #contract
        PackLoader // 팩 발견·로드·dedup(fingerprint) (designing) @dep:PackManifest #contract
        PackRegistry // 등록된 팩 레지스트리 + lookup (designing) @dep:PackLoader #contract
    Packs // 1차 도메인 팩 (governance·trust) — see DESIGN-AttestraPacks.md (decomposed) @dep:PackContract #packs
    Pipeline // 다중 팩 합성 게이트 (SpendBoundary 일반화) (designing) @dep:PackContract #pipeline
        Compose // 여러 팩을 한 패킷에 순차 적용 (designing) #pipeline
        Aggregate // 팩 간 verdict 집계 (highest severity) (designing) @dep:Compose #pipeline
    CLI // sample/run/verify/report/attest/pack/ledger (designing) @dep:AttestraCore,PackRegistry #cli
    Schemas // JSON Schema (packet/verdict/ledger/attestation/manifest) (designing) #schema
    Docs // README/ARCHITECTURE/PACK-CONTRACT/DETERMINISM (designing) #docs
    Tests // 결정론 unittest (커널 + 팩 + 파이프라인) (designing) @dep:AttestraCore,Packs #test
```

> `Packs`는 6레벨 진입을 피하고 팩별 predicate 상세를 담기 위해 `DESIGN-AttestraPacks.md`로 분리
> (`(decomposed)`). pgxf 인덱스가 파일 경계를 넘어 트리를 재구성한다.

---

## 3. PPR — 커널 핵심 함수 (계약)

### 3.1 Packet — 증거 패킷 모델 (private-payload 거부)

```python
PRIVATE_FIELDS = {"payload", "private_payload", "raw_payload", "secret", "secrets", "credential"}

def validate_packet(packet: dict) -> dict:
    """공개 증거 패킷을 검증. 사적 페이로드가 있으면 즉시 거부(breach 소재)."""
    # input: {packet_id, packet_time, subject, evidence: {gate_key: {...digest, evidence_path}}}
    leaked = find_private_fields(packet, PRIVATE_FIELDS)   # 결정론 재귀 스캔
    if leaked:
        return {"ok": False, "reason": "private_payload_present", "fields": leaked}
    missing = [k for k in ("packet_id", "subject", "evidence") if k not in packet]
    return {"ok": not missing, "reason": "missing:" + ",".join(missing) if missing else "", "fields": []}
    # acceptance_criteria:
    #   - payload/secret 계열 필드 하나라도 존재 → ok=False (curl로 유출 차단)
    #   - packet_id·subject·evidence 필수
    #   - 결정론: 동일 입력 → 동일 출력 (시계/네트워크/AI 없음)
```

### 3.2 Verdict — severity 대수 (valid < thin < breach)

```python
SEVERITY = {"valid": 0, "thin": 1, "breach": 2}   # 높을수록 심각

def aggregate_verdict(checks: list[dict]) -> dict:
    """개별 CheckResult verdict들을 최고 severity로 집계 (HELIX 규율 계승)."""
    # input: checks = [{"gate": str, "verdict": Literal["valid","thin","breach"], "reason": str}, ...]
    if not checks:
        return {"verdict": "thin", "reason": "no_checks", "worst": None}
    worst = max(checks, key=lambda c: SEVERITY[c["verdict"]])
    return {"verdict": worst["verdict"], "reason": worst["reason"], "worst": worst["gate"]}
    # acceptance_criteria:
    #   - 집계 verdict = 개별 verdict 중 최고 severity
    #   - breach 하나라도 있으면 breach, 아니면 thin 하나라도 있으면 thin, 전부 valid면 valid
    #   - 결정론: 순수 max, 임의성 없음
```

### 3.3 GateRuntime — predicate 게이트 실행 (커널의 심장)

```python
def run_gates(packet: dict, predicates: list, P: dict, now: str) -> dict:
    """검증된 패킷에 predicate 집합을 적용하고 verdict를 집계·기록.
       predicate는 팩이 제공하는 순수 함수 predicate(packet, P) -> CheckResult."""
    pv = validate_packet(packet)
    if not pv["ok"]:
        return {"verdict": "breach", "reason": pv["reason"], "checks": [], "packet_ok": False}
    checks = []
    for pred in predicates:                       # 팩 predicate — 순수 결정론
        result = pred(packet, P)                  # CheckResult: {gate, verdict, reason, evidence_ok}
        checks.append(result)
    agg = aggregate_verdict(checks)
    return {
        "verdict": agg["verdict"], "reason": agg["reason"], "worst": agg["worst"],
        "checks": checks, "packet_ok": True, "evaluated_at": now,   # now 주입 (Date.now 금지)
    }
    # acceptance_criteria:
    #   - packet 거부 시 predicate 미실행, verdict=breach
    #   - 모든 predicate는 부작용 없는 순수 함수 (원장 기록은 별도 actuator)
    #   - 결정론: predicate 순서 무관하게 집계 결과 동일 (max 기반)
```

### 3.4 Ledger — hash-chain append-only 감사 원장 (ActionHandbackVerifier 승격)

```python
def canonical_json(obj: dict) -> str:
    """정규 JSON — sort_keys=True, separators=(',',':'), 타임스탬프 없음."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def append_record(ledger_path: str, result: dict, pack: str, now: str) -> dict:
    """verdict 결과를 결정론 hash-chain 레코드로 append. now는 메타(digest 제외)."""
    prev = last_record_hash(ledger_path)          # 없으면 ""
    result_hash = sha256(canonical_json(strip_volatile(result)))   # evaluated_at 제외
    record = {
        "index": next_index(ledger_path),
        "packet_id": result_subject_id(result),
        "pack": pack, "verdict": result["verdict"],
        "result_hash": result_hash, "prev_hash": prev, "recorded_at": now,
    }
    record["record_hash"] = sha256(canonical_json({k: v for k, v in record.items()
                                                   if k not in ("record_hash", "recorded_at")}))
    append_line(ledger_path, canonical_json(record))
    return record
    # acceptance_criteria:
    #   - record_hash = sha256(record - {record_hash, recorded_at})  → 시간 무관 재현
    #   - 다음 레코드 prev_hash = 이전 record_hash (체인)
    #   - now/recorded_at 은 메타데이터 — hash 입력에서 제외 (결정론 불변)

def verify_ledger(ledger_path: str) -> dict:
    """체인 무결성 검사 — 변조 탐지."""
    # acceptance_criteria: 각 레코드 record_hash 재계산 일치 + prev_hash 연결 → valid
```

### 3.5 Attestation — valid verdict → 발행 가능한 warrant (provenance warrant 일반화)

```python
def issue_attestation(result: dict, chain: dict, now: str) -> Optional[dict]:
    """verdict가 breach가 아니면 attestation(증명서)을 발행. breach면 None(발행 거부)."""
    if result["verdict"] == "breach":
        return None
    trace = trace_provenance(result, chain)       # 결정론 walk (Provenance)
    body = {
        "subject": result_subject_id(result), "pack": result.get("pack"),
        "verdict": result["verdict"], "checks_digest": digest_checks(result["checks"]),
        "provenance": trace, "grade": "full" if result["verdict"] == "valid" else "conditional",
    }
    body["attestation_id"] = "ATT-" + sha256(canonical_json(body))[:16]
    body["issued_at"] = now                        # 메타 (id digest 제외)
    return body
    # acceptance_criteria:
    #   - breach → 발행 불가(None)
    #   - valid → grade=full, thin → grade=conditional
    #   - attestation_id = body digest 기반 → 동일 결과 재발행 시 동일 id (idempotent)
```

### 3.6 PackContract — 팩 확장 규격 (플랫폼 확장 척추)

```python
PackManifest = dict = {
    "name": str,              # 팩 고유명 (예: "handback")
    "version": str,
    "predicates": list[str],  # gate_key 목록 (예: ["authority","custody","route","rollback","trace"])
    "packet_schema": str,     # 이 팩이 요구하는 패킷 evidence 스키마 (schemas/ 참조)
    "source_project": str,    # HELIX 원본 프로젝트 (github.com/sadpig70/*)
    "fingerprint": str,       # 팩 정체성 지문 (PackLoader dedup 키)
}

def predicate(packet: dict, P: dict) -> dict:
    """모든 팩 predicate가 구현하는 계약. 순수 함수 — 부작용·시계·네트워크 금지."""
    # returns CheckResult = {"gate": str, "verdict": "valid|thin|breach",
    #                        "reason": str, "evidence_ok": bool}

def load_packs(pack_dir: str, ledger_fingerprints: dict) -> dict:
    """팩 디렉토리를 스캔·검증·dedup하여 레지스트리를 만든다."""
    manifests = scan_manifests(pack_dir)
    registry, dropped = {}, []
    for m in manifests:
        fp = fingerprint_pack(m)                   # 결정론 (Fingerprint 승격)
        if fp in {r["fingerprint"] for r in registry.values()}:
            dropped.append({"name": m["name"], "reason": "duplicate_fingerprint"})
            continue                               # SpendBoundary류 중복 재조합 차단
        registry[m["name"]] = {**m, "fingerprint": fp}
    return {"registry": registry, "dropped": dropped}
    # acceptance_criteria:
    #   - fingerprint 충돌 팩은 등록 거부(중복 방지) + dropped 기록
    #   - predicate 시그니처 미준수 팩은 로드 실패로 보고
    #   - 결정론: 동일 팩 디렉토리 → 동일 레지스트리
```

### 3.7 Pipeline — 다중 팩 합성 (SpendBoundary 일반화)

```python
def run_pipeline(packet: dict, pack_names: list[str], registry: dict, P: dict, now: str) -> dict:
    """한 패킷에 여러 팩을 적용하고 팩 간 verdict를 최고 severity로 집계.
       SpendBoundary가 손으로 한 (ContextCreep+SpendMesh+VetoEscrow) 합성을 1급 기능으로."""
    pack_results = []
    for name in pack_names:
        preds = load_predicates(registry[name])
        r = run_gates(packet, preds, P, now)       # 각 팩 독립 실행 (결정론)
        pack_results.append({"pack": name, **r})
    agg = aggregate_verdict([{"gate": pr["pack"], "verdict": pr["verdict"],
                              "reason": pr["reason"]} for pr in pack_results])
    return {"verdict": agg["verdict"], "worst_pack": agg["worst"],
            "pack_results": pack_results, "evaluated_at": now}
    # acceptance_criteria:
    #   - 파이프라인 verdict = 팩 verdict 중 최고 severity
    #   - 팩 실행 순서 무관 (집계 max) → 결정론
    #   - 어느 팩이든 breach → 파이프라인 breach (게이트 실패)
```

---

## 4. 결정론 경계 (지배 제약)

```text
AttestraCore + PackContract  → 순수 결정론 (stdlib only, 시계/네트워크/AI 없음)
  - 시간은 주입(now 인자), 의미유사도는 주입(sim), 임베딩·LLM은 팩 밖(메타층)
  - hash 입력에서 now/*_at 메타 제외 → 시간 무관 재현
팩 predicate 경로          → 순수 결정론 (부작용 금지, packet→CheckResult)
팩 내부 LLM/휴리스틱 단계    → 메타층 (Attestra 경계 밖, 원본 프로젝트 소관)
```

---

## 5. 완료 기준 (acceptance)

```text
AttestraAcceptance
    SingleSourceKernel // verdict/ledger/attestation을 커널에 한 번만 정의 (팩 중복 0)
    PackContractStable // predicate(packet,P)->CheckResult 계약으로 팩 무한 확장
    ReferencePackPorted // HandbackPack이 ActionHandbackVerifier 5-predicate 재현 (동일 verdict)
    PipelineGeneralizes // SpendBoundary를 Pipeline 합성으로 재현 (수동 재조합 불요)
    DeterministicCore // 커널·팩 predicate 전부 stdlib·주입식·시계 없음
    Federated // 팩은 원본 predicate 계약만 적재 (복사·포크 아님)
    AttestationIssued // valid/thin verdict → warrant 발행, breach → 발행 거부
    Tested // 커널 unittest green + 팩 verdict 동등성 검증
```
