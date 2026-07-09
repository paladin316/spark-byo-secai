class ThreatHunterAgent:
    purpose = "Convert intelligence into hunt hypotheses and telemetry logic."

    def run(self, context: dict) -> dict:
        return {"agent": "threat_hunter", "purpose": self.purpose, "status": "placeholder", "context": context}
