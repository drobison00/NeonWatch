"""The models the dashboard sets: the overlay and secrets files, their checks, and a save."""

from __future__ import annotations

import dataclasses
import json
import os
import stat
from pathlib import Path

import pytest

from neonwatch import models
from neonwatch.config import Analyst, Config, JudgeServer
from neonwatch.models import Keys, Models, ModelsError

ME = os.getuid()
LOCAL_LLM = {"provider": "openai-compatible", "base_url": "http://127.0.0.1:8888/v1",
             "model": "qwen", "reach": "local", "reasoning_effort": ""}


def private(path: Path, data) -> Path:
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return path


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class Applied:
    def __init__(self):
        self.calls: list[tuple[Config, Keys]] = []

    def __call__(self, config, keys):
        self.calls.append((config, keys))
        return f"applied {len(self.calls)}"


def make(tmp_path, base: Config | None = None, environ=None):
    applied = Applied()
    return Models(base or Config(), tmp_path, ME, environ or {}, applied), applied


# --- the files -----------------------------------------------------------------------------------


def test_the_files_sit_beside_the_config_or_in_the_default_config_directory(tmp_path):
    assert models.directory(tmp_path / "c.toml", Path("/home/a")) == tmp_path
    assert models.directory(None, Path("/home/a")) == Path("/home/a/.config/neonwatch")


def test_missing_files_mean_nothing_set(tmp_path):
    assert models.read_overlay(tmp_path, ME) == {}
    assert models.read_keys(tmp_path, ME) == Keys()


def test_both_files_are_read(tmp_path):
    private(tmp_path / models.SETTINGS, {"judge": {"model": "m2"}, "analyst": LOCAL_LLM})
    private(tmp_path / models.SECRETS, {"analyst": "sk-abc"})
    assert models.read_overlay(tmp_path, ME) == {"judge": {"model": "m2"}, "analyst": LOCAL_LLM}
    assert models.read_keys(tmp_path, ME) == Keys(analyst="sk-abc")


@pytest.mark.parametrize("prepare, why", [
    (lambda p: (p.write_text("{}"), p.chmod(0o644)), "group or others"),
    (lambda p: (p.write_text("x" * (models.MAX_BYTES + 1)), p.chmod(0o600)), "more than"),
    (lambda p: (p.write_text("{nope"), p.chmod(0o600)), "not readable JSON"),
    (lambda p: (p.write_text("[]"), p.chmod(0o600)), "not a JSON object"),
    (lambda p: p.mkdir(), "not a regular file"),
])
def test_an_unsafe_or_unreadable_file_is_refused(tmp_path, prepare, why):
    prepare(tmp_path / models.SECRETS)
    with pytest.raises(ModelsError, match=why):
        models.read_keys(tmp_path, ME)


def test_a_symlink_or_someone_elses_file_is_refused(tmp_path):
    target = private(tmp_path / "elsewhere.json", {})
    (tmp_path / models.SETTINGS).symlink_to(target)
    with pytest.raises(ModelsError, match="not a regular file"):
        models.read_overlay(tmp_path, ME)
    with pytest.raises(ModelsError, match="owned by uid"):
        models._read_private(target, ME + 1)


@pytest.mark.parametrize("data, why", [
    ({"web": {}}, "unknown section"),
    ({"judge": {"concurrency": "4"}}, "cannot set"),
    ({"judge": []}, "must be an object"),
    ({"analyst": {"model": 7}}, "must be text"),
    ({"analyst": {"model": "x" * (models.MAX_VALUE + 1)}}, "must be text"),
])
def test_the_overlay_sets_only_the_model_fields_as_text(tmp_path, data, why):
    private(tmp_path / models.SETTINGS, data)
    with pytest.raises(ModelsError, match=why):
        models.read_overlay(tmp_path, ME)


@pytest.mark.parametrize("data, why", [
    ({"web": "x"}, "unknown key"),
    ({"analyst": ""}, "non-empty"),
    ({"analyst": "has space"}, "without spaces"),
    ({"analyst": "line\nbreak"}, "without spaces"),
    ({"analyst": "k" * (models.MAX_KEY + 1)}, "at most"),
])
def test_keys_are_one_printable_token_each(tmp_path, data, why):
    private(tmp_path / models.SECRETS, data)
    with pytest.raises(ModelsError, match=why):
        models.read_keys(tmp_path, ME)


def test_keys_never_show_in_their_repr():
    assert "sk-secret" not in repr(Keys(judge="sk-secret", analyst="sk-secret"))
    assert repr(Keys(analyst="x")) == "Keys(judge=unset, analyst=set)"


def test_write_private_replaces_a_symlink_and_leaves_nothing_staged(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (tmp_path / "f").symlink_to(victim)
    models.write_private(tmp_path / "f", "new\n")
    assert victim.read_text() == "keep" and (tmp_path / "f").read_text() == "new\n"
    assert mode(tmp_path / "f") == 0o600
    (tmp_path / "dir").mkdir()
    with pytest.raises(OSError):
        models.write_private(tmp_path / "dir", "x")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dir", "f", "victim"]


# --- what is in force ------------------------------------------------------------------------


def test_the_overlay_wins_over_the_config_field_by_field():
    base = Config(judge=JudgeServer(model="from-toml", timeout_s=9.0))
    config = models.effective(base, {"judge": {"model": "from-dashboard"}})
    assert config.judge.model == "from-dashboard" and config.judge.timeout_s == 9.0
    assert config.judge.url == base.judge.url


def test_the_analysts_key_is_the_dashboards_else_the_named_environment_variable():
    config = Config(analyst=Analyst(api_key_env="MY_KEY"))
    assert models.analyst_key(config, Keys(analyst="dash"), {"MY_KEY": "env"}) == "dash"
    assert models.analyst_key(config, Keys(), {"MY_KEY": "env"}) == "env"
    assert models.analyst_key(config, Keys(), {}) == ""
    assert models.analyst_key(Config(), Keys(), {"MY_KEY": "env"}) == ""


def test_the_configs_own_rules_decide_what_is_usable():
    lan = Config(analyst=Analyst(provider="openai-compatible", model="m",
                                 base_url="http://10.1.2.3/v1", reach="lan"))
    models.check(lan, Keys(), {})
    with pytest.raises(ModelsError, match="must use https"):
        models.check(lan, Keys(analyst="k"), {})        # a key over http beyond loopback
    with pytest.raises(ModelsError, match="must be loopback"):
        models.check(Config(judge=JudgeServer(url="http://10.0.0.9:8200/")), Keys(), {})


# --- loading at startup --------------------------------------------------------------------------


def test_loading_reads_both_files_and_returns_the_config_in_force(tmp_path):
    private(tmp_path / models.SETTINGS, {"analyst": LOCAL_LLM})
    private(tmp_path / models.SECRETS, {"judge": "ek"})
    m, _ = make(tmp_path)
    config, problems = m.load()
    assert problems == [] and config.analyst.model == "qwen" and m.keys == Keys(judge="ek")


def test_an_unusable_file_or_overlay_is_left_out_and_named_rather_than_stopping_the_service(
        tmp_path):
    (tmp_path / models.SECRETS).write_text("{}")   # 0644 by umask: refused
    private(tmp_path / models.SETTINGS, {"judge": {"url": "http://10.0.0.9:8200/"}})
    m, _ = make(tmp_path)
    config, problems = m.load()
    assert config == Config() and m.overlay == {} and m.keys == Keys()
    assert any("group or others" in p for p in problems)
    assert any("is not used" in p and "must be loopback" in p for p in problems)
    (tmp_path / models.SETTINGS).write_text("not json")
    (tmp_path / models.SETTINGS).chmod(0o600)
    assert any("not readable JSON" in p for p in make(tmp_path)[0].load()[1])


# --- what the dashboard shows ----------------------------------------------------------------


def test_the_view_says_where_each_value_comes_from_and_never_shows_a_key(tmp_path):
    base = Config(analyst=Analyst(provider="anthropic", model="claude", reach="remote",
                                  api_key_env="ANTHROPIC_API_KEY"))
    m, _ = make(tmp_path, base, environ={"ANTHROPIC_API_KEY": "env-secret"})
    m.overlay = {"judge": {"model": "e2"}}
    m.keys = Keys(judge="dash-secret")
    view = m.view(editable=True)
    assert view["judge"]["fields"]["model"] == {"value": "e2", "source": "dashboard"}
    assert view["judge"]["fields"]["url"]["source"] == "default"
    assert view["analyst"]["fields"]["provider"] == {"value": "anthropic", "source": "config.toml"}
    assert view["judge"]["key"] == {"set": True, "source": "dashboard"}
    assert view["analyst"]["key"] == {"set": True, "source": "environment",
                                      "env": "ANTHROPIC_API_KEY"}
    assert view["judge"]["overridden"] and not view["analyst"]["overridden"]
    assert view["choices"]["reach"] == ["local", "lan", "remote"]
    text = json.dumps(view)
    assert "dash-secret" not in text and "env-secret" not in text
    shut = m.view(editable=False, why_not="LAN mode")
    assert shut["editable"] is False and shut["why_not"] == "LAN mode"
    assert m.view(editable=True, why_not="ignored")["why_not"] == ""


def test_without_a_key_anywhere_the_view_says_so(tmp_path):
    m, _ = make(tmp_path, Config(analyst=Analyst(api_key_env="UNSET_VAR")))
    assert m.view(editable=True)["analyst"]["key"] == {"set": False, "source": None,
                                                       "env": "UNSET_VAR"}


# --- saving --------------------------------------------------------------------------------------


def test_saving_writes_only_what_differs_from_the_config_and_applies_it(tmp_path):
    m, applied = make(tmp_path)
    judge = {"url": Config().judge.url, "model": "judge-2"}   # the url is config.toml's own
    config, result = m.save({"judge": judge, "analyst": LOCAL_LLM, "keys": {"analyst": "sk-new"}})
    assert result == "applied 1"   # what the service's callback built
    assert config.judge.model == "judge-2" and config.analyst.model == "qwen"
    on_disk = json.loads((tmp_path / models.SETTINGS).read_text())
    # reach "local" and an empty reasoning_effort are the defaults, so they are not kept.
    assert on_disk == {"judge": {"model": "judge-2"},
                       "analyst": {"provider": "openai-compatible",
                                   "base_url": "http://127.0.0.1:8888/v1", "model": "qwen"}}
    assert json.loads((tmp_path / models.SECRETS).read_text()) == {"analyst": "sk-new"}
    assert mode(tmp_path / models.SETTINGS) == mode(tmp_path / models.SECRETS) == 0o600
    assert applied.calls == [(config, Keys(analyst="sk-new"))]
    assert m.config == config


def test_reverting_a_section_and_removing_a_key(tmp_path):
    m, applied = make(tmp_path)
    m.save({"judge": {"model": "e2"}, "analyst": LOCAL_LLM, "keys": {"judge": "ek"}})
    config, _ = m.save({"judge": None, "keys": {"judge": ""}})
    assert config.judge == Config().judge and config.analyst.model == "qwen"
    assert "judge" not in json.loads((tmp_path / models.SETTINGS).read_text())
    assert json.loads((tmp_path / models.SECRETS).read_text()) == {}
    assert applied.calls[-1][1] == Keys()


def test_a_section_set_back_to_the_configs_values_leaves_the_overlay(tmp_path):
    m, _ = make(tmp_path)
    m.save({"judge": {"model": "e2"}})
    m.save({"judge": {"model": Config().judge.model}})
    assert m.overlay == {}


def test_nothing_is_written_or_applied_when_any_part_is_refused(tmp_path):
    m, applied = make(tmp_path)
    # A name, not a documentation IP address: Python counts 203.0.113.0/24 as private.
    remote_http = dict(LOCAL_LLM, base_url="http://llm.example.com/v1", reach="remote")
    for change, why in [
        ({"analyst": remote_http}, "must use https"),
        ({"judge": {"url": "http://10.0.0.9:8200/"}, "keys": {"analyst": "k"}}, "loopback"),
        ({"web": {}}, "unknown part"),
        ({"keys": {"web": "k"}}, "unknown key"),
        ({"keys": "k"}, "keys must be an object"),
        ({"keys": {"analyst": "two words"}}, "without spaces"),
        ({"analyst": {"api_key_env": "X"}}, "cannot set"),
        (["not", "an", "object"], "JSON object"),
    ]:
        with pytest.raises(ModelsError, match=why):
            m.save(change)
    assert list(tmp_path.iterdir()) == [] and applied.calls == []


def test_the_judges_name_is_checked_by_the_configs_rule(tmp_path):
    m, applied = make(tmp_path)
    with pytest.raises(ModelsError, match=r"judge\.name"):
        m.save({"judge": {"name": "!no"}})
    config, _ = m.save({"judge": {"name": "Qwen 7B judge"}})
    assert config.judge.name == "Qwen 7B judge" and len(applied.calls) == 1


def test_unchanged_files_are_not_rewritten(tmp_path):
    m, _ = make(tmp_path)
    m.save({"keys": {"analyst": "k1"}})
    assert not (tmp_path / models.SETTINGS).exists()   # no overlay to write
    before = (tmp_path / models.SECRETS).stat().st_mtime_ns
    m.save({"judge": {"model": "e2"}})
    assert (tmp_path / models.SECRETS).stat().st_mtime_ns == before
    assert dataclasses.asdict(m.keys) == {"judge": "", "analyst": "k1"}
