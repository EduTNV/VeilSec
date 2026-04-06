from __future__ import annotations

import pytest

from apps.worker_sast.pipeline.taint import TaintAnalyzer


@pytest.fixture
def analyzer():
    return TaintAnalyzer()


def make_ast(calls=None, assignments=None):
    return {
        "language": "python",
        "functions": [],
        "imports": [],
        "assignments": assignments or [],
        "calls": calls or [],
    }


def test_detects_pii_source_request_form(analyzer):
    ast = make_ast(calls=[{"function": "request.form.get", "line": 1}])
    flows = analyzer.find_pii_flows(ast)
    assert any(f["type"] == "pii_source" for f in flows)


def test_detects_pii_sink_logging(analyzer):
    ast = make_ast(calls=[{"function": "logging.info", "line": 5}])
    flows = analyzer.find_pii_flows(ast)
    assert any(f["type"] == "pii_sink" for f in flows)


def test_detects_pii_sink_external_api(analyzer):
    ast = make_ast(calls=[{"function": "requests.post", "line": 10}])
    flows = analyzer.find_pii_flows(ast)
    sinks = [f for f in flows if f["type"] == "pii_sink"]
    assert len(sinks) > 0
    assert "Art. 7º" in sinks[0]["lgpd_hint"]


def test_detects_pii_field_names(analyzer):
    ast = make_ast(assignments=[{"target": "cpf_usuario", "value_type": "call", "line": 2}])
    flows = analyzer.find_pii_flows(ast)
    assert any(f["type"] == "pii_assignment" for f in flows)


def test_no_flows_for_clean_code(analyzer):
    ast = make_ast(
        calls=[{"function": "math.sqrt", "line": 1}],
        assignments=[{"target": "result", "value_type": "number", "line": 2}],
    )
    flows = analyzer.find_pii_flows(ast)
    assert len(flows) == 0


def test_build_subgraphs_never_exceeds_limit(analyzer):
    flows = [{"type": "pii_source", "function": f"source_{i}", "line": i} for i in range(50)]
    subgraphs = analyzer.build_subgraphs(flows)
    assert len(subgraphs["pii_flows"]) <= 20


def test_subgraphs_contain_no_raw_code(analyzer):
    ast = make_ast(
        calls=[{"function": "request.form.get", "line": 1}, {"function": "logging.info", "line": 5}]
    )
    flows = analyzer.find_pii_flows(ast)
    subgraphs = analyzer.build_subgraphs(flows)
    subgraph_str = str(subgraphs)
    assert "def " not in subgraph_str
    assert "import " not in subgraph_str
