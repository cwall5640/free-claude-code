import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from free_claude_code.assignments import live
from free_claude_code.assignments.errors import Forbidden


def _config(tmp_path: Path, **extra: object) -> Path:
    raw = {
        "allowed_command": ["python", "check.py"],
        "owner": "owner",
        "repo": "game",
        "operator_id": "operator",
        "reviewer_id": "reviewer",
        "audience": "worker",
        "source_repo": str(tmp_path),
        **extra,
    }
    (tmp_path / "runtime.json").write_text(json.dumps(raw), encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("prefixes", [[".gitignore", "changes"], ["src"]])
def test_runtime_prefixes_reach_candidate(tmp_path, monkeypatch, prefixes):
    config = _config(tmp_path, allowed_path_prefixes=prefixes)
    monkeypatch.setattr(live, "load_worker_identity", lambda *_: SimpleNamespace(enabled=True))
    monkeypatch.setattr(live, "load_manager_config", lambda *_: [SimpleNamespace(principal_id="manager")])
    monkeypatch.setattr(live, "load_secret_file", lambda *_: {"github_read": "test"})
    monkeypatch.setattr(live, "GitHubHttpClient", lambda *args, **kwargs: None)
    monkeypatch.setattr(live, "_verifier", lambda *args: None)
    monkeypatch.setattr(live, "AssignmentCandidate", lambda **kwargs: SimpleNamespace(**kwargs))
    candidate = live._candidate(tmp_path / "state", config, live._runtime(config))
    assert candidate.allowed_path_prefixes == tuple(prefixes)


def test_runtime_prefix_default(tmp_path):
    assert live._runtime(_config(tmp_path))["allowed_path_prefixes"] == ("src",)


@pytest.mark.parametrize(
    "prefixes",
    [None, "changes", {}, [], [1], [True], ["changes", None], [""], ["."],
     [".."], ["changes/../src"], ["/"], ["C:/src"], ["changes\\src"],
     ["changes/"], [".github/workflows"], [".github/workflows/check.yml"]],
)
def test_runtime_rejects_malformed_or_widening_prefixes(tmp_path, prefixes):
    with pytest.raises(Forbidden):
        live._runtime(_config(tmp_path, allowed_path_prefixes=prefixes))
