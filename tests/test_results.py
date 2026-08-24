from modules.domain.results import ResultStore


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
    assert len(store.relationships) == 1
    assert store.rejections[0]["reason"] == "source_not_control_flow"
