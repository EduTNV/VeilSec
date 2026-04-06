from __future__ import annotations

import asyncio
from uuid import UUID

import redis.asyncio as aioredis

from packages.domain.exceptions import (
    ConsecutiveErrorsExceededError,
    TargetDegradationDetectedError,
)
from packages.shared.settings import get_settings

settings = get_settings()
_redis_client = None

# TTL padrão para todas as chaves de estado do scan no Redis
_TTL_SECONDS = 3600


async def get_redis() -> aioredis.Redis:
    """Retorna o cliente Redis singleton para a aplicação."""
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(
            str(settings.redis_url),
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis_client


class TokenBucketRedis:
    """
    Implementa rate limiting adaptativo via Token Bucket para o módulo DAST.

    O estado do bucket (tokens disponíveis, erros consecutivos e baseline
    de response time) é mantido no Redis para ser compartilhado entre
    workers que processam o mesmo scan.

    Hard stops automáticos:
    - Response time > 2x baseline → TargetDegradationDetectedError
    - Erros consecutivos >= max_consecutive_errors → ConsecutiveErrorsExceededError

    Referência: claude.md — Invariante 1 (Zero DAST sem Ownership) e
    proteção anti-DoS acidental da aplicação alvo.
    """

    def __init__(self, redis: aioredis.Redis, scan_id: UUID) -> None:
        self._redis = redis
        self._scan_id = str(scan_id)
        self._tokens_key = f"dast:tokens:{scan_id}"
        self._errors_key = f"dast:errors:{scan_id}"
        self._baseline_key = f"dast:baseline:{scan_id}"
        self._capacity = settings.dast_bucket_capacity

    async def initialize(self, baseline_ms: float) -> None:
        """
        Inicializa o estado do Token Bucket no Redis para este scan.

        Deve ser chamado após measure_baseline() e antes de acquire().
        Define a capacidade inicial de tokens, zera o contador de erros
        e persiste o baseline de response time medido.
        """
        pipe = self._redis.pipeline()
        # Capacidade inicial de tokens
        pipe.set(self._tokens_key, self._capacity, ex=_TTL_SECONDS)
        # Contador de erros começa zerado
        pipe.set(self._errors_key, 0, ex=_TTL_SECONDS)
        # Baseline de response time medido da aplicação alvo
        pipe.set(self._baseline_key, baseline_ms, ex=_TTL_SECONDS)
        await pipe.execute()

    async def acquire(self, current_response_ms: float) -> None:
        """
        Tenta consumir um token do bucket aplicando os hard stops de segurança.

        Verifica degradação da aplicação alvo e erros consecutivos antes
        de consumir o token. Bloqueia (sleep) se o bucket estiver vazio,
        aguardando o refill configurado em settings.dast_refill_rate.

        Raises:
            TargetDegradationDetectedError: se response time > 2x baseline
            ConsecutiveErrorsExceededError: se erros consecutivos >= limite
        """
        baseline_raw: str | None = await self._redis.get(self._baseline_key)
        baseline: float = float(baseline_raw) if baseline_raw else 0.0

        errors_raw: str | None = await self._redis.get(self._errors_key)
        errors: int = int(errors_raw) if errors_raw else 0

        # Hard stop 1 — degradação detectada na aplicação alvo
        if baseline > 0 and current_response_ms > baseline * settings.dast_degradation_multiplier:
            raise TargetDegradationDetectedError(
                f"Response {current_response_ms:.0f}ms > " f"2x baseline {baseline:.0f}ms."
            )

        # Hard stop 2 — erros consecutivos acima do limite
        if errors >= settings.dast_max_consecutive_errors:
            raise ConsecutiveErrorsExceededError(f"{errors} erros consecutivos. Scan interrompido.")

        # Consome token; bloqueia e aguarda refill se bucket vazio
        tokens_raw: str | None = await self._redis.get(self._tokens_key)
        tokens: int = int(tokens_raw) if tokens_raw else 0

        if tokens <= 0:
            await asyncio.sleep(1.0 / settings.dast_refill_rate)
            await self._redis.set(self._tokens_key, 1, ex=_TTL_SECONDS)

        await self._redis.decr(self._tokens_key)

        # Delay mínimo entre requisições para não sobrecarregar o alvo
        await asyncio.sleep(settings.dast_min_delay_ms / 1000)

    async def record_error(self) -> None:
        """Incrementa o contador de erros consecutivos para este scan."""
        await self._redis.incr(self._errors_key)

    async def record_success(self) -> None:
        """Zera o contador de erros consecutivos após uma requisição bem-sucedida."""
        await self._redis.set(self._errors_key, 0, ex=_TTL_SECONDS)

    async def cleanup(self) -> None:
        """
        Remove todas as chaves de estado deste scan do Redis.

        Deve ser chamado ao final do scan (sucesso ou falha) para
        liberar memória no Redis.
        """
        pipe = self._redis.pipeline()
        pipe.delete(self._tokens_key)
        pipe.delete(self._errors_key)
        pipe.delete(self._baseline_key)
        await pipe.execute()
