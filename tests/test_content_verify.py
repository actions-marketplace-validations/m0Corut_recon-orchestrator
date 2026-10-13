from recon.modules.content import host_candidates, judge_body


def test_host_candidates():
    c = host_candidates("shop.example.com")
    assert "shop.example.com.zip" in c and "shop.zip" in c and "backup-shop.zip" in c
    assert "shop.example.com.sql" in c


def test_judge_git_head():
    assert judge_body(".git/HEAD", 200, b"ref: refs/heads/main\n") == ("sensitive", "confirmed")
    # soft-404: 200 but HTML, not a git ref
    assert judge_body(".git/HEAD", 200, b"<html>not found</html>") == ("sensitive", "plausible")
    assert judge_body(".git/HEAD", 403, b"") == ("sensitive", "reject")


def test_judge_env():
    assert judge_body(".env", 200, b"DB_PASSWORD=secret\nFOO=1") == ("sensitive", "confirmed")
    assert judge_body(".env", 200, b"# nothing sensitive here") == ("sensitive", "plausible")


def test_judge_zip_and_sql():
    assert judge_body("backup.zip", 200, b"PK\x03\x04rest") == ("sensitive", "confirmed")
    assert judge_body("db.sql", 200, b"CREATE TABLE users (...)") == ("sensitive", "confirmed")


def test_judge_panels():
    assert judge_body("phpinfo.php", 200, b"<title>PHP 8.2</title>") == ("panel", "confirmed")
    assert judge_body("server-status", 200, b"Apache Server Status for x") == ("panel", "confirmed")
    assert judge_body("swagger.json", 200, b'{"openapi":"3.0.0"}') == ("panel", "confirmed")


def test_judge_generic_path():
    assert judge_body("admin", 200, b"<html>login</html>") == ("path", "generic")


def test_ds_store_magic():
    assert judge_body(".DS_Store", 200, b"\x00\x00\x00\x01Bud1xxxx")[1] == "confirmed"
    assert judge_body(".DS_Store", 200, b"<html>")[1] == "plausible"


def test_content_unreachable(monkeypatch):
    import requests

    import recon.modules.content as content
    from recon.context import ScanContext

    def boom(*a, **k):
        raise requests.ConnectionError("down")
    monkeypatch.setattr(content, "scoped_get", boom)
    f = {x.rule_id for x in content.run("https://t", ScanContext())}
    assert f == {"content.unreachable"}      # no false "clean"
