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
