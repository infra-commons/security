"""The `app` chunk's codebase dump must cover every module under `src/llm/`.

The LLM gateway was listed as `src/llm/client.py` + `src/llm/providers` only, so
sibling modules (`classify_call.py`, `spend_guard.py`, ...) were never sent to
the reviewer. The whole directory is listed now; credential/key material and
compiled files inside it must still be skipped.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_ACTION_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("security_scan", _ACTION_DIR / "security-scan.py")
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


def test_app_dump_covers_all_llm_modules_and_skips_unsafe_files(tmp_path, monkeypatch):
    llm = tmp_path / "src" / "llm"
    (llm / "providers").mkdir(parents=True)
    for rel in ("client.py", "providers/example.py", "classify_call.py", "spend_guard.py"):
        (llm / rel).write_text(f"# marker: {rel}\n")
    (llm / ".env").write_text("SECRET=do-not-send\n")
    (llm / "cached.pyc").write_bytes(b"\x00bytecode")
    monkeypatch.chdir(tmp_path)

    dump = scan.build_codebase_dump("app")

    for rel in ("client.py", "providers/example.py", "classify_call.py", "spend_guard.py"):
        assert f"src/llm/{rel} ===" in dump
        assert f"# marker: {rel}" in dump
    assert "src/llm/.env" not in dump
    assert "do-not-send" not in dump
    assert "cached.pyc" not in dump
