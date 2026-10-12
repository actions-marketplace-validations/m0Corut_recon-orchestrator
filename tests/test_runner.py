from recon.runner import TOOLS, DockerRunner, NativeRunner, get_runner


def test_tools_mapping_complete():
    for image, binary in TOOLS.values():
        assert image and binary


def test_native_can_run_checks_path(monkeypatch):
    r = NativeRunner()
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/" + b)
    assert r.can_run("nmap") is True
    monkeypatch.setattr("shutil.which", lambda b: None)
    assert r.can_run("nmap") is False


def test_get_runner_explicit():
    assert get_runner("docker").name == "docker"
    assert get_runner("native").name == "native"


def test_get_runner_auto_prefers_native_when_all_present(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/" + b)
    assert get_runner("auto").name == "native"


def test_get_runner_auto_falls_back_to_docker(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: None)
    assert get_runner("auto").name == "docker"


def test_native_run_capture_missing_binary_returns_empty(monkeypatch):
    monkeypatch.setattr("subprocess.run",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no binary")))
    assert NativeRunner().run_capture("nmap", ["-v"], 5) == ""


def test_docker_runner_name():
    assert DockerRunner().name == "docker"


def test_native_run_capture_with_input_substitutes_and_cleans(monkeypatch):
    import os
    seen = {}

    class R:
        stdout = "ok"

    def fake_run(cmd, **kw):
        path = cmd[cmd.index("-l") + 1]
        seen["path"] = path
        with open(path, encoding="utf-8") as fh:
            seen["content"] = fh.read()
        return R()
    monkeypatch.setattr("subprocess.run", fake_run)
    out = NativeRunner().run_capture_with_input("nuclei", ["-l", "{in}"], 5, "{}", "s.json")
    assert out == "ok" and seen["content"] == "{}"
    assert not os.path.exists(seen["path"])
