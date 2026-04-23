from vulnparse_pin.core.passes.TopN.workers import _infer_exposure_worker


def _cfg() -> dict:
    return {
        "thresholds": {"medium": 2, "high": 4},
        "public_service_ports": (),
        "finding_text_min_token_matches": 2,
        "finding_text_title_weight": 3,
        "finding_text_description_weight": 2,
        "finding_text_plugin_output_weight": 1,
        "finding_text_max_weighted_hits": 4,
        "finding_text_conflict_tokens": ("internal only", "localhost", "loopback"),
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


def _obs(text: str, title: str = "", description: str = "", plugin_output: str = "") -> dict:
    return {
        "asset_id": "A1",
        "ip": "10.0.0.10",
        "hostname": "host-a1",
        "criticality": "high",
        "open_ports": (),
        "finding_text_blob": text,
        "finding_title_blob": title,
        "finding_description_blob": description,
        "finding_plugin_output_blob": plugin_output,
    }


def test_reliability_benchmark_positive_vs_negative_separation() -> None:
    cfg = _cfg()
    positives = [
        _obs(
            text="internet exposed public remote service",
            title="public internet exposure",
            description="remote service is exposed",
        ),
        _obs(
            text="public internet endpoint exposed",
            title="internet exposed",
            description="remote service visible",
        ),
    ]
    negatives = [
        _obs(
            text="internet exposed but internal only localhost",
            title="internal only",
            description="localhost loopback",
        ),
        _obs(
            text="internal only localhost remote service not externally accessible",
            title="internal only",
            description="loopback localhost",
        ),
    ]

    pos_external = sum(1 for o in positives if _infer_exposure_worker(o, cfg)["externally_facing_inferred"])
    neg_external = sum(1 for o in negatives if _infer_exposure_worker(o, cfg)["externally_facing_inferred"])

    assert pos_external >= 1
    assert neg_external == 0


def test_reliability_benchmark_drift_guard_conflict_penalty_effect() -> None:
    cfg = _cfg()
    control = _obs(
        text="internet exposed public remote service",
        title="internet exposed",
        description="public remote service",
    )
    contradicted = _obs(
        text="internet exposed public remote service internal only localhost",
        title="internet exposed",
        description="internal only localhost",
    )

    control_out = _infer_exposure_worker(control, cfg)
    contradicted_out = _infer_exposure_worker(contradicted, cfg)

    assert control_out["exposure_score"] >= contradicted_out["exposure_score"]
    assert any("conflict_hits=" in ev for ev in contradicted_out["evidence"])
