"""
Shadow Guard 2.0 — Canonical 69-Feature Schema, Audit & Leak-Free Dataset Validator
====================================================================================

Provides:
1. Canonical 69-feature extraction (`extract_69_features`) matching
   `flow-feature-extraction-service/index.js` (`generateExtendedFeatures`) IEEE-754 float-for-float.
2. Explicit technical audit (`audit_69_feature_mathematics`) documenting that all 69 features
   are derived from only 3 raw flow measurements (`packets`, `bytes`, `duration`), identifying
   exact duplicate polynomial columns (`f_25..f_39`) and rank-1 collinear padding (`f_55..f_68`).
3. Flow eligibility validator (`validate_event_for_69_features`) that checks whether an event
   actually contains valid raw flow measurements without fabricating missing values.
4. Full-identity deduplication, corrupted-record quarantine & feature-collision auditor
   (`deduplicate_and_audit_records`):
   - Never deduplicates solely on `(packets, bytes, duration)`.
   - Preserves legitimate distinct network flows that share `(packets, bytes, duration)` even when
     they carry different ground-truth labels (`normal` vs. `attack`), reporting them as
     feature-collision / label-ambiguity cases that bound 3-scalar flow model accuracy.
   - Quarantines only genuinely corrupted records (negative/NaN measurements) or contradictory
     source records where the *same* flow identity (`flow_id` / 5-tuple+timestamp) is assigned
     conflicting labels.
"""

from __future__ import annotations

import hashlib
import json
import math
import sys
from typing import Any, Dict, List, Tuple

FEATURE_SCHEMA_VERSION = "v2.0-69dim"
EXPECTED_FEATURE_COUNT = 69

# Canonical ordered 69 feature names matching flow-feature-extraction-service/index.js
FEATURE_NAMES_69: List[str] = [
    # Indices 0..3: Basic flow stats (4 features)
    "f_00_packets",
    "f_01_bytes",
    "f_02_duration",
    "f_03_bytes_per_sec",
    # Indices 4..9: Packet/byte rate & log-scale features (6 features)
    "f_04_packets_per_sec",
    "f_05_avg_bytes_per_packet",
    "f_06_packets_times_bytes",
    "f_07_log_packets",
    "f_08_log_bytes",
    "f_09_log_duration",
    # Indices 10..24: Sinusoidal statistical projections (15 features)
    *[f"f_{10 + i:02d}_sin_proj_{i}" for i in range(15)],
    # Indices 25..39: Polynomial interaction ratios (15 features)
    *[f"f_{25 + i:02d}_poly_ratio_{i}" for i in range(15)],
    # Indices 40..54: Damped cosine harmonics (15 features)
    *[f"f_{40 + i:02d}_cos_damp_{i}" for i in range(15)],
    # Indices 55..68: Harmonic padding terms (14 features)
    *[f"f_{55 + i:02d}_harmonic_pad_{55 + i}" for i in range(14)],
]

assert len(FEATURE_NAMES_69) == EXPECTED_FEATURE_COUNT


def _js_truthy_number(val: Any, fallback: float) -> float:
    """
    Replicates JavaScript `const x = val || fallback;` semantics for numeric inputs:
    In JS, `0`, `None`, `""`, `False`, and `NaN` are falsy and evaluate to `fallback`.
    """
    if val is None or val is False or val == "":
        return float(fallback)
    try:
        num = float(val)
    except (ValueError, TypeError):
        return float(fallback)
    if math.isnan(num) or num == 0.0:
        return float(fallback)
    return num


def extract_69_features(traffic_data: Dict[str, Any]) -> List[float]:
    """
    Deterministic 69-feature extraction matching `generateExtendedFeatures(trafficData)`
    in `flow-feature-extraction-service/index.js` bit-for-bit.
    """
    packets = _js_truthy_number(traffic_data.get("packets"), 0.0)
    bytes_val = _js_truthy_number(traffic_data.get("bytes"), 0.0)
    duration = _js_truthy_number(traffic_data.get("duration"), 0.001)

    features: List[float] = []

    # 1. Basic stats (4 features: indices 0..3)
    features.append(float(packets))
    features.append(float(bytes_val))
    features.append(float(duration))
    features.append(float(bytes_val / duration))

    # 2. Packet-based features (6 features: indices 4..9)
    features.append(float(packets / duration))
    avg_bpp = (bytes_val / packets) if packets != 0.0 else 0.0
    if math.isnan(avg_bpp) or avg_bpp == 0.0:
        avg_bpp = 0.0
    features.append(float(avg_bpp))
    features.append(float(packets * bytes_val))
    features.append(float(math.log(packets + 1.0)))
    features.append(float(math.log(bytes_val + 1.0)))
    features.append(float(math.log(duration + 1.0)))

    # 3. Statistical sinusoidal features (15 features: indices 10..24)
    for i in range(15):
        features.append(float(math.sin(packets * (i + 1)) * bytes_val / (duration + 1.0)))

    # 4. Polynomial features (15 features: indices 25..39)
    for i in range(15):
        exp_p = 2 - (i % 2)
        exp_b = i % 2
        num = (packets ** exp_p) * (bytes_val ** exp_b)
        den = (duration ** 2) + 1.0
        features.append(float(num / den))

    # 5. Trigonometric & exponential features (15 features: indices 40..54)
    for i in range(15):
        val = (packets + bytes_val + duration) / 3.0
        features.append(float(math.cos(i * val) * math.exp(-duration)))

    # 6. Padding to reach exactly 69 features (14 features: indices 55..68)
    while len(features) < 69:
        idx = len(features)
        features.append(float((packets + bytes_val) / (duration + 1.0) * math.sin(idx)))

    return features[:69]


def audit_69_feature_mathematics(sample_vectors: List[List[float]]) -> Dict[str, Any]:
    """
    Empirically audits a matrix of 69-feature vectors to document mathematical redundancies,
    collinearity, and dynamic range skew inherent in the legacy 3-input -> 69-feature formula.
    """
    if not sample_vectors:
        raise ValueError("sample_vectors cannot be empty")

    n_rows = len(sample_vectors)
    n_cols = len(sample_vectors[0])
    if n_cols != EXPECTED_FEATURE_COUNT:
        raise ValueError(f"Expected {EXPECTED_FEATURE_COUNT} features, got {n_cols}")

    # Detect exact duplicate columns across all sample vectors
    duplicate_groups: Dict[int, List[int]] = {}
    assigned = set()
    for c1 in range(n_cols):
        if c1 in assigned:
            continue
        group = [c1]
        for c2 in range(c1 + 1, n_cols):
            if c2 in assigned:
                continue
            if all(abs(sample_vectors[r][c1] - sample_vectors[r][c2]) <= 1e-9 for r in range(n_rows)):
                group.append(c2)
                assigned.add(c2)
        if len(group) > 1:
            duplicate_groups[c1] = group

    # Verify collinearity of padding features f_55..f_68
    padding_collinear = True
    for r in range(n_rows):
        base_ratios = [
            sample_vectors[r][idx] / math.sin(idx)
            for idx in range(55, 69)
        ]
        max_diff = max(base_ratios) - min(base_ratios)
        if max_diff > 1e-6 * (abs(base_ratios[0]) + 1.0):
            padding_collinear = False
            break

    max_abs_poly = max(abs(sample_vectors[r][c]) for r in range(n_rows) for c in range(25, 40))
    max_abs_cos = max(abs(sample_vectors[r][c]) for r in range(n_rows) for c in range(40, 55))

    return {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "total_features": EXPECTED_FEATURE_COUNT,
        "raw_independent_inputs": ["packets", "bytes", "duration"],
        "intrinsic_dimensionality_upper_bound": 3,
        "meaningful_base_and_rate_features": {
            "indices": list(range(0, 10)),
            "names": FEATURE_NAMES_69[0:10],
            "count": 10,
        },
        "synthetic_derived_features": {
            "indices": list(range(10, 69)),
            "count": 59,
        },
        "exact_duplicate_feature_groups": {
            FEATURE_NAMES_69[leader]: [FEATURE_NAMES_69[idx] for idx in grp]
            for leader, grp in duplicate_groups.items()
        },
        "duplicate_columns_count": sum(len(g) - 1 for g in duplicate_groups.values()),
        "padding_f55_to_f68_rank1_collinear": padding_collinear,
        "max_abs_polynomial_feature_value": max_abs_poly,
        "max_abs_cosine_feature_value": max_abs_cos,
        "scientific_limitations_note": (
            "All 69 features in flow-feature-extraction-service are deterministic functions of only "
            "three raw flow measurements (packets, bytes, duration). Features f_25..f_39 contain 13 "
            "exact duplicate columns (8 identical even-index columns and 7 identical odd-index columns), "
            "and features f_55..f_68 are 14 collinear scalar multiples of a single ratio. Because "
            "identical (packets, bytes, duration) triples map to identical 69-dimensional vectors "
            "regardless of payload, ports, or protocol state, distinct flows with identical volume/duration "
            "but different ground-truth labels produce irreducible feature collisions."
        ),
    }


def validate_event_for_69_features(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Inspects a normalized security event or flow record to determine whether it contains
    genuine, non-fabricated flow measurements (`packets`, `bytes`, `duration`) sufficient
    to compute a valid 69-dimensional feature vector.
    Never fabricates or guesses missing flow measurements.
    """
    if not isinstance(event, dict):
        return {"eligible": False, "reason": "not_a_dict"}

    telemetry = event.get("telemetry") if isinstance(event.get("telemetry"), dict) else {}

    raw_packets = (
        event.get("packets")
        if event.get("packets") is not None
        else telemetry.get("packets", telemetry.get("packet_count"))
    )
    raw_bytes = (
        event.get("bytes")
        if event.get("bytes") is not None
        else event.get("bytes_sent", telemetry.get("bytes", telemetry.get("byte_count")))
    )
    raw_duration = (
        event.get("duration")
        if event.get("duration") is not None
        else telemetry.get("duration", telemetry.get("flow_duration_seconds"))
    )

    try:
        p_val = float(raw_packets) if raw_packets is not None else 0.0
        b_val = float(raw_bytes) if raw_bytes is not None else 0.0
        d_val = float(raw_duration) if raw_duration is not None else 0.0
    except (ValueError, TypeError):
        return {"eligible": False, "reason": "non_numeric_flow_measurements"}

    if any(math.isnan(v) or math.isinf(v) for v in (p_val, b_val, d_val)):
        return {"eligible": False, "reason": "nan_or_infinite_flow_measurements"}

    if p_val <= 0.0 and b_val <= 0.0:
        return {
            "eligible": False,
            "reason": "missing_or_zero_packet_and_byte_counts",
            "packets": p_val,
            "bytes": b_val,
            "duration": d_val,
        }

    return {
        "eligible": True,
        "reason": "valid_flow_measurements_present",
        "packets": p_val,
        "bytes": b_val,
        "duration": d_val if d_val > 0.0 else 0.001,
    }


def compute_record_identity_hash(record: Dict[str, Any]) -> str:
    """
    Computes a stable identity hash for a flow record using full source-record identity:
      (flow_id / event_id, src_ip, dst_ip, src_port, dst_port, protocol, timestamp, packets, bytes, duration)
    Never deduplicates solely on (packets, bytes, duration) so distinct network flows
    with identical transfer sizes are preserved as distinct events.
    """
    identity_tuple = (
        str(record.get("flow_id") or record.get("event_id") or ""),
        str(record.get("src_ip") or record.get("source_ip") or ""),
        str(record.get("dst_ip") or record.get("destination_ip") or ""),
        int(record.get("src_port") or record.get("source_port") or 0),
        int(record.get("dst_port") or record.get("destination_port") or 0),
        str(record.get("protocol") or "TCP").upper(),
        str(record.get("timestamp") or ""),
        round(float(record.get("packets") or 0.0), 6),
        round(float(record.get("bytes") or 0.0), 6),
        round(float(record.get("duration") or 0.0), 6),
    )
    payload = json.dumps(identity_tuple, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_pbd_triple(record: Dict[str, Any]) -> Tuple[float, float, float]:
    """
    Returns the 3-scalar measurement tuple (packets, bytes, duration) that deterministically
    generates all 69 features in `extract_69_features`.
    """
    return (
        round(float(record.get("packets") or 0.0), 6),
        round(float(record.get("bytes") or 0.0), 6),
        round(float(record.get("duration") or 0.0), 6),
    )


def deduplicate_and_audit_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Performs full-record-identity deduplication, corrupted/contradictory source-record quarantine,
    and 3-scalar feature-collision reporting:
      1. Quarantines genuinely corrupted source records (negative/NaN/zero packet & byte counts)
         or contradictory source records where the *same* record identity (`_record_hash` or `flow_id`)
         appears multiple times with conflicting labels (`normal` vs. `attack`).
      2. Removes exact duplicate source records (same full record identity hash AND same label).
      3. Preserves legitimate distinct flows that share `(packets, bytes, duration)`—both when
         they share the same label and when they have different labels (`normal` vs. `attack`).
         Distinct flows with identical `(packets, bytes, duration)` and opposite labels produce
         identical 69-dimensional feature vectors; they are preserved in `clean_records` and
         explicitly cataloged in `feature_collision_ambiguity_records` to document the intrinsic
         discriminative limit of the 3-measurement feature schema.
    """
    seen_record_hashes: Dict[str, Dict[str, Any]] = {}
    seen_flow_ids: Dict[str, str] = {}
    contradictory_record_hashes: set = set()
    contradictory_flow_ids: set = set()

    unique_records: List[Dict[str, Any]] = []
    quarantined_records: List[Dict[str, Any]] = []
    exact_duplicates_removed = 0

    # Pass 1: Validate measurements, detect exact duplicates & same-source-record label contradictions
    for rec in records:
        try:
            pkt = float(rec.get("packets") or 0.0)
            byt = float(rec.get("bytes") or 0.0)
            dur = float(rec.get("duration") or 0.0)
        except (ValueError, TypeError):
            bad = dict(rec)
            bad["quarantine_reason"] = "non_numeric_flow_measurements"
            quarantined_records.append(bad)
            continue

        if any(math.isnan(v) or math.isinf(v) for v in (pkt, byt, dur)) or pkt <= 0.0 or byt <= 0.0 or dur < 0.0:
            bad = dict(rec)
            bad["quarantine_reason"] = "corrupted_or_non_positive_flow_measurements"
            quarantined_records.append(bad)
            continue

        rec_hash = compute_record_identity_hash(rec)
        flow_id = str(rec.get("flow_id") or rec.get("event_id") or "")
        label_norm = (
            "normal"
            if str(rec.get("label", "normal")).lower() in ("normal", "benign", "normal_traffic")
            else "attack"
        )

        # Check if the exact same source record identity appeared before
        if rec_hash in seen_record_hashes:
            prev_label = seen_record_hashes[rec_hash]["_normalized_binary_label"]
            if prev_label == label_norm:
                exact_duplicates_removed += 1
            else:
                # Contradictory label on the exact same source record identity!
                contradictory_record_hashes.add(rec_hash)
                bad = dict(rec)
                bad["_record_hash"] = rec_hash
                bad["_normalized_binary_label"] = label_norm
                bad["quarantine_reason"] = "contradictory_labels_on_same_source_record_identity"
                quarantined_records.append(bad)
            continue

        # Check if the same flow_id was reused with contradictory labels
        if flow_id and flow_id in seen_flow_ids and seen_flow_ids[flow_id] != label_norm:
            contradictory_flow_ids.add(flow_id)
            bad = dict(rec)
            bad["_record_hash"] = rec_hash
            bad["_normalized_binary_label"] = label_norm
            bad["quarantine_reason"] = "contradictory_labels_on_same_flow_id"
            quarantined_records.append(bad)
            continue

        enriched = dict(rec)
        enriched["_record_hash"] = rec_hash
        enriched["_normalized_binary_label"] = label_norm
        seen_record_hashes[rec_hash] = enriched
        if flow_id:
            seen_flow_ids[flow_id] = label_norm
        unique_records.append(enriched)

    # Remove the initial occurrence of any record whose source identity or flow_id had a contradictory duplicate
    surviving_records: List[Dict[str, Any]] = []
    for rec in unique_records:
        if rec["_record_hash"] in contradictory_record_hashes or (
            rec.get("flow_id") in contradictory_flow_ids
        ):
            rec["quarantine_reason"] = "contradictory_labels_on_same_source_record_identity"
            quarantined_records.append(rec)
        else:
            surviving_records.append(rec)

    # Pass 2: Analyze (packets, bytes, duration) collisions across legitimate distinct flows
    pbd_to_labels: Dict[Tuple[float, float, float], set] = {}
    pbd_to_count: Dict[Tuple[float, float, float], int] = {}

    for rec in surviving_records:
        pbd = compute_pbd_triple(rec)
        pbd_to_labels.setdefault(pbd, set()).add(rec["_normalized_binary_label"])
        pbd_to_count[pbd] = pbd_to_count.get(pbd, 0) + 1

    same_measurement_distinct_flows_count = sum(
        count - 1 for count in pbd_to_count.values() if count > 1
    )

    clean_records: List[Dict[str, Any]] = []
    feature_collision_ambiguity_records: List[Dict[str, Any]] = []

    for rec in surviving_records:
        pbd = compute_pbd_triple(rec)
        has_cross_label_collision = len(pbd_to_labels.get(pbd, set())) > 1
        rec["_is_feature_collision_ambiguity"] = has_cross_label_collision
        if has_cross_label_collision:
            rec["_feature_collision_note"] = (
                "Legitimate distinct flow sharing identical (packets, bytes, duration) with a flow of "
                "the opposite label; produces an identical 69-feature vector."
            )
            feature_collision_ambiguity_records.append(
                {
                    "flow_id": rec.get("flow_id"),
                    "src_ip": rec.get("src_ip"),
                    "dst_ip": rec.get("dst_ip"),
                    "src_port": rec.get("src_port"),
                    "dst_port": rec.get("dst_port"),
                    "protocol": rec.get("protocol"),
                    "timestamp": rec.get("timestamp"),
                    "packets": rec.get("packets"),
                    "bytes": rec.get("bytes"),
                    "duration": rec.get("duration"),
                    "label": rec.get("label"),
                    "attack_category": rec.get("attack_category"),
                }
            )
        # Preserve ALL legitimate distinct flows (including cross-label feature collisions)
        clean_records.append(rec)

    return {
        "input_records_count": len(records),
        "exact_duplicates_removed": exact_duplicates_removed,
        "distinct_flows_sharing_pbd_preserved": same_measurement_distinct_flows_count,
        "feature_collision_ambiguity_flows_preserved": len(feature_collision_ambiguity_records),
        "corrupted_or_contradictory_source_records_quarantined": len(quarantined_records),
        "clean_records_count": len(clean_records),
        "clean_records": clean_records,
        "feature_collision_ambiguity_records": feature_collision_ambiguity_records,
        "quarantined_records": quarantined_records,
    }


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--extract-json":
        payload = json.loads(sys.argv[2])
        if isinstance(payload, list):
            out = [extract_69_features(item) for item in payload]
        else:
            out = extract_69_features(payload)
        print(json.dumps(out))
