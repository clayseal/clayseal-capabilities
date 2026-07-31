"""The AML peer-deviation sensor separates real fraud (grounding the mechanism)."""
def test_peer_deviation_beats_chance_on_ulb():
    import pytest
    from benchmarks.fraud_validation import evaluate
    try:
        result = evaluate()
    except RuntimeError:
        pytest.skip("ULB dataset not present")
    assert result["auc"] > 0.8, result  # the mechanism discriminates fraud


def test_peer_z_score_is_the_aml_sensor_function():
    from agentauth.capabilities.monitor.aml import peer_z_score
    z, key = peer_z_score({"a": 5.0, "b": 0.0}, {"a": 0.0, "b": 0.0}, {"a": 1.0, "b": 1.0})
    assert z == 5.0 and key == "a"
