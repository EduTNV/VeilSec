from __future__ import annotations

import json

import anthropic
import structlog
from openai import AsyncOpenAI

from packages.domain.exceptions import LLMUnavailableError
from packages.infra.ai.prompts import SAST_RESPONSE_SCHEMA, SAST_SYSTEM_PROMPT
from packages.shared.settings import get_settings

settings = get_settings()
log = structlog.get_logger(__name__)


class AnthropicLLM:
    """
    Adaptador para o LLM principal da Camada 3 da pipeline de IA.

    Utiliza Claude (Anthropic) como provedor principal com fallback
    automático para OpenAI em caso de indisponibilidade.

    O prompt é blindado contra Prompt Injection via tags <UNTRUSTED_INPUT>
    e o input sempre chega como JSON estruturado — nunca como texto livre.

    Referência: claude.md — Invariante 3 (Pipeline de IA Rigorosa)
    """

    def __init__(self) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        self._fallback = AsyncOpenAI(api_key=settings.openai_api_key)

    async def analyze(self, structured_input: dict) -> str:
        """
        Analisa o subgrafo AST estruturado e retorna findings em JSON.

        O input é sempre um dict estruturado gerado pela Camada 1 (AST parser)
        e validado pela Camada 2 (classificador). Nunca recebe código raw.

        Tenta o provedor principal (Anthropic) e faz fallback para OpenAI
        automaticamente em caso de falha.

        Returns:
            String JSON com findings no formato SAST_RESPONSE_SCHEMA.

        Raises:
            LLMUnavailableError: se ambos os provedores estiverem indisponíveis.
        """
        user_message = (
            "<UNTRUSTED_INPUT>\n"
            f"{json.dumps(structured_input, ensure_ascii=True)}\n"
            "</UNTRUSTED_INPUT>\n\n"
            "Analyze and respond with this exact JSON schema:\n"
            f"{SAST_RESPONSE_SCHEMA}"
        )
        try:
            return await self._call_anthropic(user_message)
        except Exception as e:
            log.warning(
                "llm.anthropic.failed",
                error=str(e),
                error_type=type(e).__name__,
            )
            try:
                return await self._call_openai_fallback(user_message)
            except Exception as e2:
                log.error(
                    "llm.fallback.failed",
                    error=str(e2),
                    error_type=type(e2).__name__,
                )
                raise LLMUnavailableError("LLM principal e fallback indisponíveis.") from e2

    async def _call_anthropic(self, user_message: str) -> str:
        """Executa a chamada ao modelo Claude via API Anthropic."""
        response = await self._client.messages.create(
            model=settings.anthropic_model,
            max_tokens=1000,
            temperature=0.1,
            system=SAST_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        return response.content[0].text

    async def _call_openai_fallback(self, user_message: str) -> str:
        """Executa a chamada ao modelo OpenAI como fallback."""
        response = await self._fallback.chat.completions.create(
            model=settings.openai_fallback_model,
            max_tokens=1000,
            temperature=0.1,
            messages=[
                {"role": "system", "content": SAST_SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
        )
        return response.choices[0].message.content or ""
