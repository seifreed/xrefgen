from modules.domain.results import Finding, ResultStore


def test_result_store_exports_only_valid_control_flow_and_deduplicates():
    store = ResultStore(
        source_is_control_flow=lambda ea: ea == 0x1000,
        target_is_executable=lambda ea: ea == 0x2000,
    )

    assert store.add(0x1000, 0x2000, "indirect_call", 0.7, evidence=("graph",))
    assert store.add(0x1000, 0x2000, "indirect_call", 0.9, evidence=("dataflow",))
    assert not store.add(0x3000, 0x4000, "indirect_call", 1.0)
    assert not store.add(0x1000, 0x2000, "ml_similarity", 1.0)
    assert not store.add(0x1000, 0x2000, "ml_similarity", 0.8)

    assert store.xrefs() == [(0x1000, 0x2000, "indirect_call", 0.9)]
    assert store.evidence() == {(0x1000, 0x2000): {"graph", "dataflow"}}
    assert store.xref_types() == {(0x1000, 0x2000): {"indirect_call"}}
    assert len(store.relationships) == 1
    assert store.rejections[0]["reason"] == "source_not_control_flow"
    assert store.findings[0].kind.startswith("rejected_")


def test_result_store_keeps_multiple_control_flow_types():
    store = ResultStore(
        source_is_control_flow=lambda _ea: True,
        target_is_executable=lambda _ea: True,
    )

    assert store.add(1, 2, "indirect_call", 0.7)
    assert store.add(1, 2, "callback_arg", 0.8)
    assert store.xref_types() == {(1, 2): {"indirect_call", "callback_arg"}}
    assert store.xrefs() == [(1, 2, "indirect_call", 0.8)]


def test_result_store_accepts_explicit_findings():
    store = ResultStore()
    assert not store.add_result(Finding(1, 2, "arm64_adrp_add", 0.9))
    assert store.findings[0].kind == "arm64_adrp_add"
