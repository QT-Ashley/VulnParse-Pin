from vulnparse_pin.core.passes.TopN.workers import _infer_exposure_worker


def _base_inference_cfg() -> dict:
    return {
        "thresholds": {"medium": 2, "high": 4},
        "public_service_ports": (),
        "finding_text_min_token_matches": 2,
        "finding_text_title_weight": 3,
        "finding_text_description_weight": 2,
        "finding_text_plugin_output_weight": 1,
        "finding_text_max_weighted_hits": 4,
        "finding_text_conflict_tokens": ("internal only", "localhost"),
        "finding_text_conflict_penalty": 2,
        "finding_text_diminishing_factors": (1.0, 0.6, 0.4),
        "rules": [
            {
                "rule_id": "finding_text_exposure_hint",
                "enabled": True,
                "tag": "externally_facing",
                "weight": 4,
                "predicate_name": "finding_text_contains_any",
                "predicate_ports": (),
                "predicate_tokens": ("internet", "public", "exposed", "remote service"),
                "evidence": "Finding text suggests network exposure",
            }
        ],
    }


def test_finding_text_weighting_applies_diminishing_returns_and_emits_trace() -> None:
    cfg = _base_inference_cfg()
    obs = {
        "asset_id": "A1",
        "ip": "10.0.0.10",
        "hostname": "app-1",
        "criticality": "high",
        "open_ports": (),
        "finding_text_blob": "internet exposed remote service public",
        "finding_title_blob": "internet exposed",
        "finding_description_blob": "public remote service",
        "finding_plugin_output_blob": "",
    }

    inferred = _infer_exposure_worker(obs, cfg)

    assert inferred["exposure_score"] >= 2
    assert inferred["confidence"] in {"medium", "high"}
    assert inferred["externally_facing_inferred"] is True
    assert any("source_hits=title:" in ev for ev in inferred["evidence"])
    assert any("applied_weight=" in ev for ev in inferred["evidence"])
    assert "finding_text_exposure_hint" in inferred["evidence_rule_ids"]


def test_finding_text_conflict_tokens_reduce_weight_to_non_external() -> None:
    cfg = _base_inference_cfg()
    obs = {
        "asset_id": "A2",
        "ip": "10.0.0.11",
        "hostname": "app-2",
        "criticality": "high",
        "open_ports": (),
        "finding_text_blob": "internet exposed but internal only localhost",
        "finding_title_blob": "internet exposed",
        "finding_description_blob": "internal only localhost",
        "finding_plugin_output_blob": "",
    }

    inferred = _infer_exposure_worker(obs, cfg)

    assert inferred["exposure_score"] <= 1
    assert inferred["confidence"] == "low"
    assert inferred["externally_facing_inferred"] is False
    assert any("conflict_hits=" in ev for ev in inferred["evidence"])
    assert "finding_text_exposure_hint" in inferred["evidence_rule_ids"]
