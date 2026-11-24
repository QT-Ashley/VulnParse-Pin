-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 Quashawn Ashley
-- VulnParse-Pin (vpp) v2.0.0 DuckDB Workspace Schema

CREATE TABLE IF NOT EXISTS runs (
    run_id VARCHAR PRIMARY KEY,
    created_at_utc VARCHAR NOT NULL,
    vpp_version VARCHAR,
    profile VARCHAR,
    config_sha256 VARCHAR,
    assets_sha256 VARCHAR,
    decisions_sha256 VARCHAR,
    intel_metadata_json VARCHAR,
    manifest_digest VARCHAR,
    input_files_json VARCHAR,
    baseline_run_id VARCHAR
);

CREATE TABLE IF NOT EXISTS assets (
    run_id VARCHAR NOT NULL,
    asset_id VARCHAR NOT NULL,
    canonical_key VARCHAR NOT NULL,
    hostname VARCHAR,
    ip_address VARCHAR,
    target_uri VARCHAR,
    image_or_repo VARCHAR,
    os VARCHAR,
    declared_criticality VARCHAR,
    derived_criticality VARCHAR,
    internet_facing BOOLEAN,
    owner VARCHAR,
    env_tags_json VARCHAR,
    inventory_status VARCHAR,
    matched_rule_id VARCHAR,
    open_ports_json VARCHAR,
    PRIMARY KEY (run_id, asset_id)
);

CREATE TABLE IF NOT EXISTS asset_aliases (
    run_id VARCHAR NOT NULL,
    asset_id VARCHAR NOT NULL,
    alias_type VARCHAR NOT NULL,
    alias_value VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    run_id VARCHAR NOT NULL,
    finding_id VARCHAR NOT NULL,
    asset_id VARCHAR NOT NULL,
    scoring_track VARCHAR NOT NULL,
    primary_cve VARCHAR,
    cves_json VARCHAR,
    cwes_json VARCHAR,
    ghsa_ids_json VARCHAR,
    title VARCHAR NOT NULL,
    description VARCHAR,
    solution VARCHAR,
    plugin_output VARCHAR,
    affected_port INTEGER,
    protocol VARCHAR,
    service_name VARCHAR,
    location_uri VARCHAR,
    line_number INTEGER,
    package_purl VARCHAR,
    scanner_severity VARCHAR,
    scanner_cvss_score DOUBLE,
    scanner_cvss_vector VARCHAR,
    detection_mode VARCHAR,
    signal_reliability DOUBLE,
    ingestion_confidence DOUBLE,
    fidelity_tier VARCHAR,
    source_format VARCHAR,
    references_json VARCHAR,
    tags_json VARCHAR,
    exploit_evidence BOOLEAN,
    is_deduplicated BOOLEAN NOT NULL DEFAULT FALSE,
    source_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (run_id, finding_id)
);

CREATE TABLE IF NOT EXISTS finding_evidence (
    run_id VARCHAR NOT NULL,
    finding_id VARCHAR NOT NULL,
    evidence_idx INTEGER NOT NULL,
    source_format VARCHAR,
    scanner_sig VARCHAR,
    raw_severity VARCHAR,
    raw_cvss DOUBLE,
    raw_location VARCHAR,
    evidence_excerpt VARCHAR
);

CREATE TABLE IF NOT EXISTS finding_cves (
    run_id VARCHAR NOT NULL,
    finding_id VARCHAR NOT NULL,
    cve_id VARCHAR NOT NULL,
    PRIMARY KEY (run_id, finding_id, cve_id)
);

CREATE TABLE IF NOT EXISTS enrichment_snapshots (
    run_id VARCHAR NOT NULL,
    cve_id VARCHAR NOT NULL,
    cvss_score DOUBLE,
    cvss_vector VARCHAR,
    cvss_version VARCHAR,
    cvss_provenance VARCHAR,
    epss_score DOUBLE,
    epss_percentile DOUBLE,
    epss_model_version VARCHAR,
    epss_date VARCHAR,
    in_kev BOOLEAN,
    kev_date_added VARCHAR,
    kev_due_date VARCHAR,
    kev_ransomware VARCHAR,
    kev_required_action VARCHAR,
    verified_exploit BOOLEAN,
    heuristic_exploit_mention BOOLEAN,
    exploit_refs_json VARCHAR,
    ghsa_ids_json VARCHAR,
    osv_ids_json VARCHAR,
    enrichment_confidence DOUBLE,
    sources_json VARCHAR,
    PRIMARY KEY (run_id, cve_id)
);

CREATE TABLE IF NOT EXISTS aci_signals (
    run_id VARCHAR NOT NULL,
    finding_id VARCHAR NOT NULL,
    asset_id VARCHAR NOT NULL,
    capabilities_json VARCHAR,
    chains_json VARCHAR,
    matched_tokens_json VARCHAR,
    confidence DOUBLE,
    uplift_score DOUBLE,
    PRIMARY KEY (run_id, finding_id)
);

CREATE TABLE IF NOT EXISTS scores (
    run_id VARCHAR NOT NULL,
    finding_id VARCHAR NOT NULL,
    asset_id VARCHAR NOT NULL,
    scoring_track VARCHAR NOT NULL,
    raw_risk_score DOUBLE,
    operational_score DOUBLE,
    risk_band VARCHAR,
    score_trace_json VARCHAR,
    PRIMARY KEY (run_id, finding_id)
);

CREATE TABLE IF NOT EXISTS triage_decisions (
    run_id VARCHAR NOT NULL,
    finding_id VARCHAR NOT NULL,
    asset_id VARCHAR NOT NULL,
    profile VARCHAR,
    priority_tier VARCHAR,
    oal_compat VARCHAR,
    ssvc_action VARCHAR,
    sla_bucket VARCHAR,
    sla_days INTEGER,
    decision_status VARCHAR,
    decision_id VARCHAR,
    assumed_state_json VARCHAR,
    rationale_summary VARCHAR,
    PRIMARY KEY (run_id, finding_id)
);

CREATE TABLE IF NOT EXISTS diff_events (
    diff_id VARCHAR NOT NULL,
    base_run_id VARCHAR NOT NULL,
    target_run_id VARCHAR NOT NULL,
    category VARCHAR NOT NULL,
    finding_id VARCHAR,
    asset_id VARCHAR,
    cve_id VARCHAR,
    details_json VARCHAR
);

CREATE TABLE IF NOT EXISTS ledger_events (
    run_id VARCHAR NOT NULL,
    seq INTEGER NOT NULL,
    ts VARCHAR NOT NULL,
    component VARCHAR NOT NULL,
    event_type VARCHAR NOT NULL,
    subject_ref VARCHAR NOT NULL,
    why VARCHAR,
    evidence_digest VARCHAR,
    prev_hash VARCHAR,
    entry_hash VARCHAR,
    PRIMARY KEY (run_id, seq)
);
