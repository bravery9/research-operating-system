import subprocess

from invariant_os.patchdiff.gitdiff import collect_git_diff


def test_collect_git_diff_uses_safe_git_diff_arguments(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    calls = []

    def fake_run(command, cwd, capture_output, text, timeout, check):
        calls.append(
            {
                "command": command,
                "cwd": cwd,
                "capture_output": capture_output,
                "text": text,
                "timeout": timeout,
                "check": check,
            }
        )
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="diff --git a/app.py b/app.py\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    diff_text = collect_git_diff(repo, "main", "feature")

    assert diff_text == "diff --git a/app.py b/app.py\n"
    command = calls[0]["command"]
    assert command[:4] == ["git", "-C", str(repo.resolve()), "diff"]
    assert "--no-ext-diff" in command
    assert "--no-color" in command
    assert "--no-textconv" in command
    assert "--unified=3" in command
    assert "main" in command
    assert "feature" in command
    assert command[-1] == "--"
    assert calls[0]["cwd"] is None
    assert calls[0]["capture_output"] is True
    assert calls[0]["text"] is True
    assert calls[0]["check"] is False


def test_collect_git_diff_rejects_missing_repo(tmp_path):
    try:
        collect_git_diff(tmp_path / "missing", "main", "feature")
    except ValueError as error:
        assert "local repository" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_collect_git_diff_rejects_url_like_refs(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    try:
        collect_git_diff(repo, "https://example.com/main", "feature")
    except ValueError as error:
        assert "local refs" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_collect_git_diff_rejects_shell_metacharacter_refs(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    try:
        collect_git_diff(repo, "main;echo", "feature")
    except ValueError as error:
        assert "local refs" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_collect_git_diff_wraps_git_failure(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_run(command, cwd, capture_output, text, timeout, check):
        return subprocess.CompletedProcess(command, 128, stdout="", stderr="bad ref")

    monkeypatch.setattr(subprocess, "run", fake_run)

    try:
        collect_git_diff(repo, "main", "missing")
    except ValueError as error:
        assert "local refs" in str(error)
    else:
        raise AssertionError("expected ValueError")
