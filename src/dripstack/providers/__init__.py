"""External-service providers: email (ESP), AI explainer, channel stubs."""

from .ai import AiExplainerService, build_explainer_prompt
from .channels import get_stub_sender
from .email import SendArgs, SendResult, get_email_provider

__all__ = [
    "AiExplainerService",
    "build_explainer_prompt",
    "get_stub_sender",
    "SendArgs",
    "SendResult",
    "get_email_provider",
]
