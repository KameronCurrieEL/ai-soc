from soc.ai.llm import OllamaLLM


def test_request_has_messages_no_stream_and_temperature():
    body = OllamaLLM("http://x:11434", "qwen2.5:3b").build_request("sys", "usr")
    assert body["model"] == "qwen2.5:3b" and body["stream"] is False
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert body["options"] == {"temperature": 0.0, "num_predict": 400}
    assert "format" not in body


def test_schema_is_sent_as_format():
    schema = {"type": "object"}
    body = OllamaLLM("http://x", "m").build_request("s", "u", schema)
    assert body["format"] == schema


def test_name_identifies_backend_and_model():
    assert OllamaLLM("http://x", "qwen2.5:3b").name == "ollama:qwen2.5:3b"


def test_stream_parses_ndjson_chunks(monkeypatch):
    import io
    import json as _json

    import pytest

    from soc.ai import llm as llm_mod
    lines = [{"message": {"content": "Hel"}, "done": False}, {"message": {"content": "lo"}, "done": False},
             {"message": {"content": ""}, "done": True, "done_reason": "stop"}]
    sent = {}

    class Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout):
        sent["body"] = _json.loads(req.data)
        return Resp(b"\n".join(_json.dumps(x).encode() for x in lines) + b"\n")

    monkeypatch.setattr(llm_mod.urllib.request, "urlopen", fake_urlopen)
    m = llm_mod.OllamaLLM(url="http://x", model="m")
    assert "".join(m.stream([{"role": "user", "content": "hi"}])) == "Hello"
    assert sent["body"]["stream"] is True and sent["body"]["options"]["num_ctx"] == 4096
    assert m.last_stop_reason == "stop"

    monkeypatch.setattr(llm_mod.urllib.request, "urlopen",
                        lambda req, timeout: Resp(b'{"error": "model not found"}\n'))
    with pytest.raises(RuntimeError, match="model not found"):
        list(m.stream([]))
