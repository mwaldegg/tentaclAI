"""egress gateway – pure functions, loaded from egress/gw.py without starting it."""
import importlib.machinery
import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("EGRESS_DEFAULT_LIST", os.path.join(ROOT, "lib", "egress-default.txt"))
os.environ.setdefault("DATA_DIR", os.environ.get("DATA_DIR", "/tmp"))
_loader = importlib.machinery.SourceFileLoader("gw", os.path.join(ROOT, "egress", "gw.py"))
gw = importlib.util.module_from_spec(importlib.util.spec_from_loader("gw", _loader))
_loader.exec_module(gw)


def test_prune_drops_old_and_caps():
    now = 1_000_000_000
    entries = {f"h{i}:443": {"last": now - i} for i in range(gw.SEEN_MAX + 50)}
    entries["old:443"] = {"last": now - (gw.SEEN_DAYS + 1) * 86400}
    kept = gw.prune(entries, now)
    assert len(kept) == gw.SEEN_MAX and "old:443" not in kept
    assert "h0:443" in kept and f"h{gw.SEEN_MAX + 49}:443" not in kept  # the most recent stay


def test_short_outage_of_tentacontrol_stays_quiet(monkeypatch, capsys):
    """a restart of tentacontrol (a failed fetch or two) logs nothing; a longer outage one line, and its end one more"""
    monkeypatch.setitem(gw.pol, "ok", True)
    monkeypatch.setattr(gw, "failing", {"n": 0, "since": 0})
    monkeypatch.setattr(gw, "POLICY_CACHE", os.devnull + "-x")  # writing the cache may fail – ignored

    def down(*a, **k):
        raise OSError("Connection refused")
    monkeypatch.setattr(gw, "control", down)
    gw.refresh()
    gw.refresh()
    assert capsys.readouterr().out == ""
    gw.refresh()
    gw.refresh()
    out = capsys.readouterr().out
    assert out.count("policy refresh failing since") == 1 and "Connection refused" in out
    monkeypatch.setattr(gw, "control", lambda *a, **k: dict(gw.pol, tentacles=[], grants={}))
    gw.refresh()
    assert "works again" in capsys.readouterr().out and gw.failing["n"] == 0


def test_tentacontrol_and_loopback_are_no_destination(monkeypatch):
    """its /internal/egress endpoints trust the gateway – through the gateway, Claude would be the gateway"""
    monkeypatch.setattr(gw, "_control", [gw.time.time(), {"10.200.0.5"}])
    assert gw.own_target(["10.200.0.5"]) and gw.own_target(["::ffff:10.200.0.5"])
    assert gw.own_target(["127.0.0.1"]) and gw.own_target(["::1"]) and gw.own_target(["::ffff:127.0.0.1"])
    assert not gw.own_target(["93.184.215.14"]) and not gw.own_target([])


import pytest  # noqa: E402


@pytest.mark.parametrize("target,ok", [
    ("example.com:443", ("example.com", 443)), ("[2001:db8::1]:22", ("2001:db8::1", 22)), ("10.0.0.1:22", ("10.0.0.1", 22)),
    ("example.com:0", None), ("example.com:99999", None), ("2130706433:22", None), ("127.1:22", None), ("0x7f.1:443", None),
    (":443", None), ("1password.com:443", ("1password.com", 443)), ("123.example:443", ("123.example", 443)),
])
def test_split_hostport_refuses_odd_targets(target, ok):
    if ok:
        assert gw.split_hostport(target, 443) == ok
    else:
        with pytest.raises(ValueError):
            gw.split_hostport(target, 443)
