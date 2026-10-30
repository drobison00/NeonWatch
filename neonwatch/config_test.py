"""No file is a valid config; everything a file says is held to a type and a few principles."""

from __future__ import annotations

import dataclasses
import os
import typing

import pytest

from neonwatch.config import (
    MAX_CONFIG_BYTES,
    Analyst,
    Config,
    ConfigError,
    check_analyst,
    creds_file,
    judge_url_problem,
    load,
)


def written(tmp_path, text: str):
    path = tmp_path / "neonwatch.toml"
    path.write_text(text)
    return path


def test_no_file_means_the_defaults():
    config = load(None)
    assert config == Config()
    assert config.retention.max_age_s == 7 * 86400
    assert config.retention.max_bytes == 10 * 1024**3
    assert config.web.host == "127.0.0.1" and config.budget.cpu_fraction == 0.01


def test_durations_sizes_and_numbers_are_read(tmp_path):
    config = load(written(tmp_path, """
[retention]
max_age_s = "2w"
max_bytes = "512MiB"
[cadence]
fast = 30
slow = "2h"
[judge]
concurrency = 12
timeout_s = 20.5
[notify]
enabled = false
min_severity = "warn"
rate_limit_s = "10m"
[web]
host = "localhost"
port = 9000
"""))
    assert config.retention.max_age_s == 14 * 86400
    assert config.retention.max_bytes == 512 * 1024**2
    assert (config.cadence.fast, config.cadence.slow, config.cadence.medium) == (30, 7200, 300)
    assert (config.judge.concurrency, config.judge.timeout_s) == (12, 20.5)
    assert (config.notify.enabled, config.notify.min_severity, config.notify.rate_limit_s) == (
        False, "warn", 600)
    assert (config.web.host, config.web.port) == ("localhost", 9000)


def test_retention_bytes_may_be_a_plain_integer(tmp_path):
    assert load(written(tmp_path, "[retention]\nmax_bytes = 1000\n")).retention.max_bytes == 1000


@pytest.mark.parametrize("text, message", [
    ("[nope]\n", "unknown section"),
    ("retention = 3\n", "must be a table"),
    ("[web]\nbind = '0.0.0.0'\n", "unknown key"),
    ("[web]\nhost = '0.0.0.0'\n", "refused on the network without TLS"),
    ("[web]\nhost = 'example.com'\n", "IP address or localhost"),
    ("[web]\nport = 80.5\n", "whole number"),
    ("[web]\nport = 70000\n", "1-65535"),
    ("[budget]\ncpu_fraction = 0.2\n", r"\(0, 0.05\]"),
    ("[broker]\nurl = 'nats://203.0.113.9:4222'\n", "nats://127.0.0.1"),
    ("[broker]\nurl = 'nats://localhost:4222'\n", "nats://127.0.0.1"),
    ("[broker]\nurl = 'tls://127.0.0.1:4222'\n", "nats://127.0.0.1"),
    ("[broker]\nurl = 'nats://127.0.0.1'\n", "nats://127.0.0.1"),
    ("[broker]\nurl = 'nats://u:p@127.0.0.1:4222'\n", "nats://127.0.0.1"),
    ("[budget]\ncpu_fraction = -1\n", "positive number"),
    ("[budget]\ncpu_fraction = true\n", "positive number"),
    ("[judge]\nconcurrency = 32\n", "1-16"),
    ("[judge]\nurl = ''\n", "non-empty string"),
    ("[judge]\nname = ' leading'\n", "judge.name"),
    ("[judge]\nname = 'a<b>'\n", "judge.name"),
    ("[judge]\nname = '" + "x" * 41 + "'\n", "judge.name"),
    ("[notify]\nmin_severity = 'loud'\n", "min_severity"),
    ("[notify]\nenabled = 'yes'\n", "true or false"),
    ("[cadence]\nfast = 'soon'\n", "duration"),
    ("[cadence]\nfast = 0\n", "positive"),
    ("[cadence]\nfast = 0.01\n", "at least 10 s"),
    ("[cadence]\ncollate = 5\n", "at least 60 s"),
    ("[cadence]\nfast = true\n", "duration"),
    ("[retention]\nmax_bytes = 'lots'\n", "size like"),
    ("not toml = = =\n", "not valid TOML"),
])
def test_what_the_file_may_not_say_is_refused(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        load(written(tmp_path, text))


def test_the_analyst_is_disabled_by_default_and_local_only(tmp_path):
    assert load(None).analyst.provider == ""
    local = load(written(tmp_path, """
[analyst]
provider = "openai-compatible"
base_url = "http://127.0.0.1:8000/v1"
model = "local-model"
"""))
    assert local.analyst.model == "local-model" and local.analyst.reach == "local"
    remote = load(written(tmp_path, """
[analyst]
provider = "anthropic"
model = "claude-sonnet-5-5"
api_key_env = "ANTHROPIC_API_KEY"
reach = "remote"
"""))
    assert remote.analyst.provider == "anthropic"
    lan = load(written(tmp_path, """
[analyst]
provider = "openai-compatible"
base_url = "http://192.0.2.5:8888/v1"
model = "qwen"
reach = "lan"
reasoning_effort = "low"
"""))
    assert lan.analyst.reach == "lan" and lan.analyst.reasoning_effort == "low"


@pytest.mark.parametrize("text, message", [
    ('[analyst]\nprovider = "gpt"\n', "analyst.provider"),
    ('[analyst]\nprovider = "anthropic"\n', "model is required"),
    ('[analyst]\nprovider = "openai-compatible"\nmodel = "m"\n', "base_url is required"),
    ('[analyst]\nprovider = "anthropic"\nmodel = "m"\n', "not loopback"),
    ('[analyst]\nprovider = "openai-compatible"\nmodel = "m"\n'
     'base_url = "https://api.example.com/v1"\n', "not loopback"),
    ('[analyst]\nprovider = "anthropic"\nmodel = "m"\n'
     'api_key_env = "sk-ant-abc123"\nreach = "remote"\n', "looks like a key"),
    ('[analyst]\nmodel = 3\n', "must be a string"),
    ('[analyst]\nprovider = "openai-compatible"\nmodel = "m"\n'
     'base_url = "http://api.example.com/v1"\nreach = "remote"\n', "must use https"),
    ('[analyst]\nprovider = "openai-compatible"\nmodel = "m"\n'
     'base_url = "http://10.1.2.3/v1"\nreach = "lan"\napi_key_env = "LAN_KEY"\n', "must use https"),
    ('[analyst]\nprovider = "openai-compatible"\nmodel = "m"\n'
     'base_url = "http://gpubox:8888/v1"\nreach = "lan"\n', "not a private IP address"),
    ('[analyst]\nprovider = "openai-compatible"\nmodel = "m"\n'
     'base_url = "https://api.example.com/v1"\nreach = "lan"\n', "not a private IP address"),
    ('[analyst]\nprovider = "openai-compatible"\nmodel = "m"\n'
     'base_url = "http://10.1.2.3/v1"\n', 'reach is "local"'),
    ('[analyst]\nprovider = "openai-compatible"\nmodel = "m"\n'
     'base_url = "http://127.0.0.1/v1"\nreach = "cloud"\n', "analyst.reach must be one of"),
    ('[analyst]\nprovider = "openai-compatible"\nmodel = "m"\n'
     'base_url = "http://127.0.0.1/v1"\nreasoning_effort = "max"\n', "reasoning_effort must be"),
    ('[analyst]\nprovider = "anthropic"\nmodel = "m"\nreach = "remote"\n'
     'reasoning_effort = "low"\n', "openai-compatible provider only"),
    ('[analyst]\nprovider = "openai-compatible"\nmodel = "m"\nbase_url = "file:///x"\n',
     "http\\(s\\) URL"),
])
def test_what_the_analyst_section_may_not_say_is_refused(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        load(written(tmp_path, text))


def test_a_key_set_elsewhere_counts_as_keyed_for_the_analysts_endpoint():
    # The dashboard keeps keys in a secrets file, so whether a key is sent is passed in, not
    # read from api_key_env alone.
    lan = Analyst(provider="openai-compatible", model="m", base_url="http://10.1.2.3/v1",
                  reach="lan")
    check_analyst(lan, keyed=False)
    with pytest.raises(ConfigError, match="must use https"):
        check_analyst(lan, keyed=True)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8200/v1/systemone", "http://localhost:9000/x",
                                 "http://[::1]:8200/"])
def test_the_judge_is_plain_http_to_loopback(url):
    assert judge_url_problem(url) == ""


@pytest.mark.parametrize("url, why", [
    ("https://127.0.0.1:8200/", "plain http"),
    ("http://192.168.1.5:8200/", "must be loopback"),
    ("http://judge.example.com/", "must be loopback"),
    ("http://user:pw@127.0.0.1:8200/", "plain http"),
    ("http://127.0.0.1:99999/", "invalid port"),
    ("not a url", "plain http"),
])
def test_a_judge_anywhere_but_loopback_over_plain_http_is_refused(url, why):
    assert why in judge_url_problem(url)


def test_a_config_naming_a_remote_judge_is_refused_when_loaded(tmp_path):
    with pytest.raises(ConfigError, match="must be loopback"):
        load(written(tmp_path, '[judge]\nurl = "http://10.0.0.9:8200/v1/systemone"\n'))


def test_a_missing_file_is_an_error_not_the_defaults(tmp_path):
    with pytest.raises(ConfigError, match="no such file"):
        load(tmp_path / "absent.toml")


def test_a_symlinked_config_is_refused(tmp_path):
    real = written(tmp_path, "[web]\nport = 9000\n")
    link = tmp_path / "link.toml"
    link.symlink_to(real)
    with pytest.raises(ConfigError, match="cannot open safely"):
        load(link)


def test_a_fifo_is_refused_without_hanging(tmp_path):
    fifo = tmp_path / "fifo.toml"
    os.mkfifo(fifo)
    with pytest.raises(ConfigError, match="not a regular file"):
        load(fifo)


def test_an_oversized_or_non_utf8_config_is_refused(tmp_path):
    big = tmp_path / "big.toml"
    big.write_text("# " + "x" * (MAX_CONFIG_BYTES + 10))
    with pytest.raises(ConfigError, match="over"):
        load(big)
    bad = tmp_path / "bad.toml"
    bad.write_bytes(b"\xff\xfe")
    with pytest.raises(ConfigError, match="not UTF-8"):
        load(bad)


def test_a_config_owned_by_someone_else_is_refused(tmp_path):
    path = written(tmp_path, "[web]\nport = 9000\n")
    mine = os.stat(path).st_uid
    assert load(path, owner=mine).web.port == 9000
    with pytest.raises(ConfigError, match="owned by uid"):
        load(path, owner=mine + 12345)


def test_an_unopenable_directory_is_refused(tmp_path):
    with pytest.raises(ConfigError):
        load(tmp_path)


def test_creds_file_names_one_file_per_role_and_refuses_paths(tmp_path):
    from pathlib import Path
    assert creds_file(tmp_path, "agent") == tmp_path / "agent.creds.json"
    assert creds_file(Path("/x"), "evaluator-hb") == Path("/x/evaluator-hb.creds.json")
    for bad in ("../agent", "a/b", "Agent", "", "agent.x"):
        with pytest.raises(ConfigError, match="not a broker role name"):
            creds_file(tmp_path, bad)


#: A real scrypt hash of a throwaway password, made the way `neonwatch hash-password` makes one.
HASH = "scrypt$16384$8$1$Ct+UCz9wHe02xX4OvdYPKA==$eef57/uRJaiuoFJ9ZM9O3Gqi8A+I9EnanyAP2PLBK+g="


def lan(tmp_path, extra: str = "", host: str = "192.168.1.50", port: int = 8765):
    return written(tmp_path, f"""
[web]
host = "{host}"
port = {port}
tls_cert = "/etc/neonwatch/cert.pem"
tls_key = "/etc/neonwatch/key.pem"
password_hash = "{HASH}"
allowed_hosts = ["monitor.local:{port}", "192.168.1.50:{port}"]
{extra}""")


def test_a_lan_dashboard_with_tls_a_password_and_hosts_loads(tmp_path):
    web = load(lan(tmp_path)).web
    assert web.host == "192.168.1.50" and web.password_hash == HASH
    assert web.allowed_hosts == ("monitor.local:8765", "192.168.1.50:8765")
    assert web.session_s == 12 * 3600


@pytest.mark.parametrize("drop, message", [
    ("tls_cert", "set together"),
    ("tls_key", "set together"),
    ("password_hash", "web.password_hash"),
    ("allowed_hosts", "allowed_hosts must list"),
])
def test_a_lan_dashboard_missing_any_protection_is_refused(tmp_path, drop, message):
    text = lan(tmp_path).read_text()
    text = "\n".join(line for line in text.splitlines() if not line.startswith(drop))
    with pytest.raises(ConfigError, match=message):
        load(written(tmp_path, text))


def test_without_tls_and_password_the_lan_is_refused_entirely(tmp_path):
    with pytest.raises(ConfigError, match="refused on the network without TLS"):
        load(written(tmp_path, '[web]\nhost = "0.0.0.0"\nallowed_hosts = ["monitor.local:8765"]\n'))


@pytest.mark.parametrize("value, message", [
    ('"plaintext-password"', "not an scrypt hash"),
    ('"scrypt$32768$8$1$AAAAAAAAAAAAAAAA$' + "A" * 43 + '="', "not an scrypt hash"),
    ('"scrypt$1024$8$1$AAAAAAAAAAAAAAAAAAAAAA==$' + "A" * 43 + '="', "too weak"),
    ('"scrypt$16383$8$1$AAAAAAAAAAAAAAAAAAAAAA==$' + "A" * 43 + '="', "too weak"),
    ('"scrypt$16384$4$1$AAAAAAAAAAAAAAAAAAAAAA==$' + "A" * 43 + '="', "too weak"),
    ('"scrypt$16777216$8$1$AAAAAAAAAAAAAAAAAAAAAA==$' + "A" * 43 + '="', "too costly"),
    ('"scrypt$32768$8$17$AAAAAAAAAAAAAAAAAAAAAA==$' + "A" * 43 + '="', "too costly"),
])
def test_a_password_hash_must_be_a_strong_scrypt_hash(tmp_path, value, message):
    with pytest.raises(ConfigError, match=message):
        load(written(tmp_path, f"[web]\npassword_hash = {value}\n"))


@pytest.mark.parametrize("hosts, message", [
    ('["monitor.local:9999"]', "must be name:8765"),
    ('["monitor.local"]', "must be name:8765"),
    ('["http://monitor.local:8765"]', "must be name:8765"),
    ('["monitor local:8765"]', "must be name:8765"),
    ('["Monitor.local:8765"]', "must be lower-case"),
    ('[""]', "list of non-empty strings"),
    ('"monitor.local:8765"', "list of non-empty strings"),
])
def test_allowed_hosts_are_exact_name_port_entries(tmp_path, hosts, message):
    text = lan(tmp_path).read_text().replace(
        'allowed_hosts = ["monitor.local:8765", "192.168.1.50:8765"]', f"allowed_hosts = {hosts}")
    with pytest.raises(ConfigError, match=message):
        load(written(tmp_path, text))


def test_loopback_may_still_run_with_no_protections_and_ipv6_hosts_are_named(tmp_path):
    assert load(written(tmp_path, "[web]\nport = 9000\n")).web.password_hash == ""
    web = load(written(tmp_path, f"""[web]
password_hash = "{HASH}"
allowed_hosts = ["[::1]:8765", "localhost:8765"]
""")).web
    assert web.allowed_hosts == ("[::1]:8765", "localhost:8765")


@pytest.mark.parametrize("text, message", [
    ('[web]\nhost = "monitor.local"\n', "IP address or localhost"),
    ('[web]\nboard = " "\n', "non-empty string"),
    ("[web]\nsession_s = 60\n", "between 5 minutes and 7 days"),
    ('[web]\nsession_s = "30d"\n', "between 5 minutes and 7 days"),
])
def test_web_host_and_session_limits(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        load(written(tmp_path, text))


@pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
@pytest.mark.parametrize("key", ["cadence.fast", "cadence.collate", "budget.cpu_fraction",
                                 "judge.timeout_s"])
def test_a_non_finite_number_is_refused(tmp_path, key, value):
    section, name = key.split(".")
    with pytest.raises(ConfigError, match="finite"):
        load(written(tmp_path, f"[{section}]\n{name} = {value}\n"))


def test_a_deeply_nested_file_is_a_config_error_not_a_crash(tmp_path):
    with pytest.raises(ConfigError, match="nested too deeply"):
        load(written(tmp_path, "x = " + "[" * 5000 + "]" * 5000 + "\n"))


def test_the_judge_has_a_display_name(tmp_path):
    assert load(None).judge.name == "Judge"
    text = '[judge]\nname = "Local judge (GPU 0)"\nmodel = "judge-v2"\n'
    judge = load(written(tmp_path, text)).judge
    assert (judge.name, judge.model) == ("Local judge (GPU 0)", "judge-v2")


def test_the_configuration_reference_documents_every_key_and_no_other():
    """docs/configuration.md lists each section's keys in table rows; they must match the code."""
    import re
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "docs" / "configuration.md").read_text()
    documented: dict[str, set[str]] = {}
    section = None
    for line in text.splitlines():
        if heading := re.match(r"## `\[(\w+)\]`", line):
            section = heading[1]
            documented[section] = set()
        elif section and (row := re.match(r"\| (`[\w`, ]+`) \|", line)):
            documented[section] |= set(re.findall(r"`(\w+)`", row[1]))
    hints = typing.get_type_hints(Config)
    actual = {name: {f.name for f in dataclasses.fields(hints[name])} for name in hints}
    assert documented == actual
