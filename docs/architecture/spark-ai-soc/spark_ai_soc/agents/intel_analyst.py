class IntelAnalystAgent:
    purpose = "Convert raw intelligence into structured operational context."

    def run(self, context: dict) -> dict:
        return {"agent": "intel_analyst", "purpose": self.purpose, "status": "placeholder", "context": context}
