"""
Unified AI provider interface supporting Gemini and OpenRouter.
"""
import logging
from typing import Optional
from tenacity import retry, stop_after_attempt, wait_exponential
from app.config import settings

logger = logging.getLogger(__name__)


class AIProvider:
    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.provider = provider or settings.default_ai_provider
        self.model = model or settings.default_ai_model
        self.api_key = api_key

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def complete(self, prompt: str, system: Optional[str] = None) -> str:
        """Send a completion request and return the text response."""
        if self.provider == "gemini":
            return await self._gemini_complete(prompt, system)
        elif self.provider == "openrouter":
            return await self._openrouter_complete(prompt, system)
        else:
            raise ValueError(f"Unknown AI provider: {self.provider}")

    async def _gemini_complete(self, prompt: str, system: Optional[str]) -> str:
        import google.generativeai as genai

        key = self.api_key or settings.gemini_api_key
        if not key:
            raise ValueError("Gemini API key not configured")
        genai.configure(api_key=key)

        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        model = genai.GenerativeModel(self.model)
        response = await model.generate_content_async(full_prompt)
        return response.text.strip()

    async def _openrouter_complete(self, prompt: str, system: Optional[str]) -> str:
        from openai import AsyncOpenAI

        key = self.api_key or settings.openrouter_api_key
        if not key:
            raise ValueError("OpenRouter API key not configured")

        client = AsyncOpenAI(api_key=key, base_url=settings.openrouter_base_url)
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = await client.chat.completions.create(
            model=self.model,
            messages=messages,
        )
        return response.choices[0].message.content.strip()
