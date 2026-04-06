from __future__ import annotations

import json

import structlog

from packages.shared.settings import get_settings

settings = get_settings()
log = structlog.get_logger(__name__)

# Limite de caracteres para truncamento do input antes da classificação.
# Modelos de classificação não precisam de contexto longo para detectar injeção.
_CLASSIFIER_INPUT_MAX_CHARS = 512


class InjectionClassifier:
    """
    Camada 2 da pipeline de IA — classificador local de Prompt Injection.

    Analisa o subgrafo AST estruturado em busca de padrões de injeção
    antes de qualquer chamada ao LLM principal. Opera completamente offline
    e sem acesso à rede externa.

    Modos de operação:
    - 'mock': usa heurística de keywords para desenvolvimento local.
      Detecta padrões óbvios de injeção sem necessidade de modelo baixado.
    - 'local': usa modelo fine-tuned (DeBERTa-v3-small ou Llama Guard)
      carregado do caminho configurado em settings.ai_classifier_model_path.

    Um score > settings.ai_classifier_threshold indica injeção detectada
    e deve resultar em bloqueio do scan.

    Referência: claude.md — Invariante 3 (Pipeline de IA Rigorosa)
    """

    # Keywords de injeção usados pelo modo mock (desenvolvimento)
    _INJECTION_KEYWORDS: list[str] = [
        "ignore previous",
        "ignore all",
        "system prompt",
        "you are now",
        "disregard",
        "forget your instructions",
        "new instructions",
        "act as",
    ]

    def __init__(self) -> None:
        self._mode = settings.ai_classifier_mode
        self._pipeline = None
        if self._mode == "local":
            self._load_model()

    def _load_model(self) -> None:
        """
        Carrega o modelo de classificação local em memória.

        O import de transformers é lazy e intencional — a biblioteca
        só é necessária no modo 'local' e tem footprint de importação alto.

        Raises:
            Qualquer exceção do transformers (ImportError, OSError, etc.)
            é logada e re-levantada — falha no carregamento é fatal.
        """
        try:
            # Import lazy intencional: transformers só é necessário no modo 'local'
            from transformers import pipeline as hf_pipeline

            self._pipeline = hf_pipeline(
                "text-classification",
                model=settings.ai_classifier_model_path,
                device="cpu",
                truncation=True,
                max_length=_CLASSIFIER_INPUT_MAX_CHARS,
            )
            log.info("classifier.model.loaded", path=settings.ai_classifier_model_path)
        except Exception as e:
            log.error("classifier.model.load_failed", error=str(e), error_type=type(e).__name__)
            raise

    async def score(self, structured_input: dict) -> float:
        """
        Calcula o score de Prompt Injection para o input estruturado.

        Returns:
            Float entre 0.0 e 1.0. Valores acima de
            settings.ai_classifier_threshold indicam injeção detectada.
        """
        if self._mode == "mock":
            return await self._mock_score(structured_input)
        return await self._local_score(structured_input)

    async def _mock_score(self, structured_input: dict) -> float:
        """
        Classificação por heurística de keywords para desenvolvimento.

        Detecta padrões óbvios de Prompt Injection sem modelo baixado.
        NÃO usar em produção — usa apenas para desenvolvimento local.
        """
        text = json.dumps(structured_input).lower()
        for keyword in self._INJECTION_KEYWORDS:
            if keyword in text:
                log.warning("classifier.mock.injection_detected", keyword=keyword)
                return 0.95
        return 0.05

    async def _local_score(self, structured_input: dict) -> float:
        """
        Classificação via modelo local fine-tuned.

        Trunca o input em _CLASSIFIER_INPUT_MAX_CHARS antes da inferência —
        modelos de classificação não precisam de contexto completo.
        """
        text = json.dumps(structured_input, ensure_ascii=True)[:_CLASSIFIER_INPUT_MAX_CHARS]
        result = self._pipeline(text)[0]
        score: float = result["score"] if result["label"] == "INJECTION" else 1 - result["score"]
        log.debug("classifier.scored", score=score)
        return score
