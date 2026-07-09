from abc import ABC, abstractmethod
from typing import Any, Dict

class AIGateway(ABC):
    @abstractmethod
    def complete(self, task_type: str, system_prompt: str, user_prompt: str, context: Dict[str, Any], model_profile: Dict[str, Any]) -> str:
        """Return a model completion using the configured provider profile."""
        raise NotImplementedError
