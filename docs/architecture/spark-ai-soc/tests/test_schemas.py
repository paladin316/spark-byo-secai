from pathlib import Path
import json

def test_schemas_are_json():
    for schema in Path("spark_ai_soc/schemas").glob("*.json"):
        assert json.loads(schema.read_text())["type"] == "object"
