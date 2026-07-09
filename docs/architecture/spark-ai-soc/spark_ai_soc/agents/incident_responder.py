class IncidentResponderAgent:
    purpose = "Turn hunt output into operational response."

    def run(self, context: dict) -> dict:
        return {"agent": "incident_responder", "purpose": self.purpose, "status": "placeholder", "context": context}
