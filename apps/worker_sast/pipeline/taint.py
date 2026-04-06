from __future__ import annotations

import structlog

log = structlog.get_logger(__name__)

PII_SOURCES = {
    "request.form",
    "request.json",
    "request.json()",
    "request.args",
    "request.cookies",
    "request.data",
    "jwt.decode",
    "db.query",
    "session.get",
    "os.environ",
    "getenv",
}
PII_FIELD_NAMES = {
    "cpf",
    "cnpj",
    "rg",
    "email",
    "phone",
    "telefone",
    "nome",
    "name",
    "endereco",
    "address",
    "nascimento",
    "birth",
    "senha",
    "password",
    "token",
    "credit_card",
    "cartao",
    "ip_address",
    "user_id",
    "usuario",
}
PII_SINKS = {
    "logging.info",
    "logging.debug",
    "logging.warning",
    "logging.error",
    "log.info",
    "log.debug",
    "print",
    "response.json",
    "jsonify",
    "requests.post",
    "requests.get",
    "httpx.post",
    "open(",
    "json.dumps",
    "db.execute",
    "session.add",
}


class TaintAnalyzer:
    def find_pii_flows(self, ast_data: dict) -> list[dict]:
        flows = []
        calls = ast_data.get("calls", [])
        assignments = ast_data.get("assignments", [])
        for assignment in assignments:
            target = assignment.get("target", "").lower()
            for field in PII_FIELD_NAMES:
                if field in target:
                    flows.append(
                        {
                            "type": "pii_assignment",
                            "variable": target,
                            "line": assignment.get("line"),
                            "risk": "Variável com nome semântico de PII detectada.",
                        }
                    )
        for call in calls:
            func = call.get("function", "")
            for source in PII_SOURCES:
                if source in func:
                    flows.append(
                        {
                            "type": "pii_source",
                            "function": func,
                            "line": call.get("line"),
                            "risk": f"Fonte de PII: {source}",
                        }
                    )
        for call in calls:
            func = call.get("function", "")
            for sink in PII_SINKS:
                if sink in func:
                    flows.append(
                        {
                            "type": "pii_sink",
                            "function": func,
                            "line": call.get("line"),
                            "risk": f"Sink de PII: {sink}",
                            "lgpd_hint": self._get_lgpd_hint(func),
                        }
                    )
        return flows

    def build_subgraphs(self, pii_flows: list[dict]) -> dict:
        return {
            "pii_flows": pii_flows[:20],
            "total_flows": len(pii_flows),
            "has_sources": any(f["type"] == "pii_source" for f in pii_flows),
            "has_sinks": any(f["type"] == "pii_sink" for f in pii_flows),
            "lgpd_hints": list({f["lgpd_hint"] for f in pii_flows if f.get("lgpd_hint")}),
        }

    def _get_lgpd_hint(self, sink_func: str) -> str:
        if any(s in sink_func for s in ["log", "print"]):
            return "Art. 46 — PII em log viola medidas de segurança adequadas."
        if any(s in sink_func for s in ["requests", "httpx", "post", "get"]):
            return "Art. 7º — Envio de PII para API externa exige base legal."
        if "response" in sink_func or "jsonify" in sink_func:
            return "Art. 6º — Minimização: retornar apenas dados necessários."
        return "Art. 46 — Verificar tratamento adequado de dados pessoais."
