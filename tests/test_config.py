import pytest

from recon.config import TEMPLATE, ConfigError, load_config, write_template


def test_load_valid(tmp_path):
    p = tmp_path / "recon.yaml"
    p.write_text(
        "targets:\n  - https://example.com\nmodules: all\nrate: 10\n"
        "options:\n  top_ports: 50\n", encoding="utf-8")
    cfg = load_config(str(p))
    assert cfg["targets"] == ["https://example.com"]
    assert cfg["rate"] == 10
    assert cfg["options"]["top_ports"] == 50


def test_unknown_top_key(tmp_path):
    p = tmp_path / "recon.yaml"
    p.write_text("targetz:\n  - x\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(p))


def test_unknown_option_key(tmp_path):
    p = tmp_path / "recon.yaml"
    p.write_text("options:\n  bogus: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(p))


def test_targets_must_be_list(tmp_path):
    p = tmp_path / "recon.yaml"
    p.write_text("targets: https://x\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(p))


def test_missing_file():
    with pytest.raises(ConfigError):
        load_config("/no/such/recon.yaml")


def test_write_template_and_reload(tmp_path):
    p = tmp_path / "recon.yaml"
    write_template(str(p))
    assert p.exists()
    # the emitted template must itself be valid config
    cfg = load_config(str(p))
    assert cfg["targets"] == ["https://example.com"]
    # writing over an existing file is refused
    with pytest.raises(ConfigError):
        write_template(str(p))


def test_template_is_nonempty():
    assert "targets:" in TEMPLATE
