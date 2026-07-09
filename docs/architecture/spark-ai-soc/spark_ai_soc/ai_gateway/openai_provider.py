from .base import AIGateway

class OpenaiProvider(AIGateway):
    def complete(self, task_type, system_prompt, user_prompt, context, model_profile):
        # Phase 0 placeholder. Implement SDK/API call here.
        return "Provider placeholder response"
