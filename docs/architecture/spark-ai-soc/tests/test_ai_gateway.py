from spark_ai_soc.ai_gateway.base import AIGateway

def test_ai_gateway_interface_exists():
    assert hasattr(AIGateway, "complete")
