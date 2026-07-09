from spark_ai_soc.orchestrator import Orchestrator

def test_orchestrator_placeholder():
    result = Orchestrator().run("intel_to_hunt", "sample.json", platform="crowdstrike")
    assert "intel_to_hunt" in result
