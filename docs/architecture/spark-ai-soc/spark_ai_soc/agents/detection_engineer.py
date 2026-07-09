class DetectionEngineerAgent:
    purpose = "Convert hunts into durable detection candidates."

    def run(self, context: dict) -> dict:
        return {"agent": "detection_engineer", "purpose": self.purpose, "status": "placeholder", "context": context}
