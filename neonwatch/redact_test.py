"""Token shapes and secret-named values are cut, and counted; ordinary text is left alone."""

from __future__ import annotations

import pytest

from neonwatch.redact import MASK, SHAPES, redact, redact_mapping


@pytest.mark.parametrize("secret", [
    "Authorization: Bearer abc.def-ghi_jkl",
    "fg_0123456789abcdef0123456789abcdef0123",
    "sk-proj-abcdefghijklmnop1234",
    "ghp_abcdefghijklmnopqrstuvwxyz0123",
    "AKIAIOSFODNN7EXAMPLE",                      # AWS's documented example key
    # Built here, so a scanner does not take the test value for a leaked token.
    "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dozjgNryP4J3jVmNHl0w5N",
    "OPENAI_API_KEY=sk_live_value_here",
    "DB_PASSWORD: hunter2hunter2",
    "--password=hunter2",
    "-dev-root-token-id=kind-vault-dev-root",
    "postgres://app:s3cret@db:5432/app",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\n-----END OPENSSH PRIVATE KEY-----",
])
def test_token_shapes_are_cut_and_counted(secret):
    text, count = redact(f"before {secret} after")
    assert count == 1 and MASK in text and text.startswith("before ")


#: Command and env shapes from crontabs and unit files: (text, what must survive).
COMMAND_SECRETS = [
    ("curl -u admin:hunter2hunter2 https://nas.lan/backup", "curl "),
    ("curl --user admin:hunter2hunter2 https://nas.lan/", "curl "),
    ("curl --user=admin:hunter2hunter2 https://nas.lan/", "curl "),
    ("mysqldump -uroot -phunter2hunter2 db > /var/b/db.sql", "mysqldump -uroot "),
    ("mysql -h db -phunter2hunter2 app", "mysql -h db "),
    ("mariadb-dump --all-databases -p'hunter2hunter2'", "mariadb-dump --all-databases "),
    ("sshpass -p hunter2hunter2 rsync -a /srv nas:/b", "sshpass "),
    ("sshpass -phunter2hunter2 ssh nas", "sshpass "),
    ("smbclient //nas/b -U admin%hunter2hunter2 -c ls", "smbclient //nas/b "),
    ("curl -H 'Authorization: Token abcd1234abcd1234' https://api.example/x",
     "curl -H 'Authorization: "),
    ("curl -H 'X-API-Key: v' https://api.example/x", "curl -H '"),
    ("curl -H 'Token: abcd1234' https://api.example/x", "curl -H '"),
    ("curl 'https://api.example/x?key=abcd1234abcd1234&sig=ffeeddccbbaa'",
     "curl 'https://api.example/x?key="),
    ("wget https://h/x?page=2&access_token=abcd", "wget https://h/x?page=2&access_token="),
    ("redis-cli -u redis://:hunter2hunter2@10.0.0.5:6379/0 ping", "redis-cli -u redis"),
    ("MYSQL_PWD=hunter2hunter2", ""),
]


@pytest.mark.parametrize(("text", "kept"), COMMAND_SECRETS)
def test_command_line_secret_shapes_are_cut(text, kept):
    cleaned, count = redact(text)
    assert "hunter2" not in cleaned and "abcd1234" not in cleaned and count >= 1, cleaned
    assert cleaned.startswith(kept) and MASK in cleaned


def test_a_secret_query_parameter_is_cut_and_the_others_are_not():
    cleaned, count = redact("curl 'https://h/x?key=abcd1234&sig=ffeeddcc&page=2'")
    assert cleaned == f"curl 'https://h/x?key={MASK}&sig={MASK}&page=2'" and count == 2


@pytest.mark.parametrize("text", [
    "cd /home/user && ./run -p 8080",
    "ps -u root",
    "docker run -u 1000:1000 img",
    "curl 'https://h/x?page=2&sort=name'",
    "mysql -p",
    "mysql -p db",
    "ssh -p 2222 nas",
    "PWD=/srv/app",
    "OLDPWD=/srv",
    "rsync -a user@host:/srv /b",
    "http://host:8080/path",
    "tar -U -x",
])
def test_lookalikes_are_left_alone(text):
    assert redact(text) == (text, 0)


def test_pwd_named_keys_are_secret_names():
    cleaned, count = redact_mapping({"MYSQL_PWD": "x", "PWD": "/srv"})
    assert cleaned == {"MYSQL_PWD": MASK, "PWD": "/srv"} and count == 1


def test_ordinary_text_is_left_alone():
    line = "kernel: nvme0: temperature 54C, token budget sixty-four thousand"
    assert redact(line) == (line, 0)


def test_secret_named_values_are_masked_whole_at_any_depth():
    data = {"cmdline": "python app.py --token=abcdef123456",
            "env": {"HOME": "/root", "GITHUB_TOKEN": "anything-at-all", "Password": "x"},
            "units": [{"name": "a.service", "api_key": "k"}],
            "pair": ("safe", "Bearer abcdefgh12345678"),
            "empty_token": "",
            "count": 3}
    cleaned, count = redact_mapping(data)
    assert cleaned["env"] == {"HOME": "/root", "GITHUB_TOKEN": MASK, "Password": MASK}
    assert cleaned["units"][0]["api_key"] == MASK
    assert MASK in cleaned["cmdline"] and cleaned["pair"][0] == "safe"
    assert isinstance(cleaned["pair"], tuple) and MASK in cleaned["pair"][1]
    assert cleaned["empty_token"] == "" and cleaned["count"] == 3
    assert count == 5
    assert data["env"]["GITHUB_TOKEN"] == "anything-at-all"  # the input is not modified


def test_a_long_unbroken_word_is_linear_not_quadratic():
    """A user controls word length in journal messages and argv; the root agent redacts them."""
    import time
    start = time.perf_counter()
    for _ in range(5):
        redact("a" * 20000 + "token=abcdefgh")
    assert time.perf_counter() - start < 0.5


#: A hostile repetition of every shape in `SHAPES`, by name: text a user can put in a journal
#: message, a process argument or a model's answer, built to make that shape rescan. Each runs
#: well under the bound when the shape is linear and far over it when it is not.
HOSTILE = {
    "private_key": ("-----BEGIN PRIVATE KEY----- " * 2000,
                    "-----BEGIN RSA PRIVATE KEY-----\n" * 2000),
    "bearer": ("basic " * 4000, "bearer\t" * 4000),
    "forge_gate": ("fg_" * 8000, "fga_" * 6000),
    "api_key": ("sk-" * 8000, "-sk-a" * 5000),
    "github": ("ghp_" * 6000,),
    "github_pat": ("github_pat_" * 2000, "github_pat-" * 2000),
    "slack": ("xoxb-" * 5000, "xoxb" * 6000),
    "aws": ("AKIA" * 6000, "AKIA-" * 5000),
    "jwt": ("eyJ-" * 8000, "eyJaaaaaaaaaa." * 2000),
    "assignment": ("atoken" * 4000, "a_pwd" * 4000, "xsecret" * 3000),
    "flag": ("--password" * 3000, "--token" * 4000),
    "url": ("://" + ":" * 20000, "://" + "a:" * 10000),
    # A fresh -u/-U start after every non-word character, no `:`/`%` to end the user.
    "user": ("-u " * 7000, "-ua" * 7000 + ":", "(-u" * 7000, "@-u" * 7000, "(--user=" * 3000,
             "(-u'" * 5000),
    "mysql": ("mysql " * 4000 + "-p", "mysql" + " a" * 10000),
    "sshpass": ("sshpass " * 3000,),
    "smbclient": ("-U a" * 5000, "(-U" * 7000),
    "authorization": ("Authorization: " * 1500,),
    "header": ("X-API-Key:" * 2000, "token :" * 3000),
    "query": ("?key" * 5000,),
}


def test_every_shape_has_a_hostile_repetition():
    """Linearity is claimed of every shape, so a shape is not added without its measurement."""
    assert HOSTILE.keys() == SHAPES.keys()


@pytest.mark.parametrize("text", [text for texts in HOSTILE.values() for text in texts],
                         ids=lambda text: text[:8].replace(" ", "_"))
def test_every_shape_is_linear_in_a_hostile_repetition(text):
    import time
    start = time.perf_counter()
    for _ in range(5):
        redact(text)
    assert time.perf_counter() - start < 0.5


def test_a_private_key_block_with_no_end_is_cut_to_the_end_of_the_text():
    """A field capped mid-block still holds key material, and searching for the missing END
    from every BEGIN is what made the shape quadratic."""
    cleaned, count = redact("key: -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\nAAAA more")
    assert (cleaned, count) == (f"key: {MASK}", 1)


def test_a_jwt_is_cut_only_at_the_start_of_a_run():
    """The anchor that keeps the shape linear: after `=`, a space or a quote it is a JWT; inside
    a run of token characters (`-eyJ...`) it is part of that word."""
    jwt = ("eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." +
           "dozjgNryP4J3jVmNHl0w5N")
    for lead in ("id=", "x ", '"'):
        assert redact(lead + jwt) == (lead + MASK, 1)
    assert redact("x-" + jwt)[1] == 0


def test_a_user_is_read_up_to_its_bound_and_no_further():
    """The bound that keeps -u/-U linear: a 256-character user is still one, a longer one not."""
    for flag, sep in (("-u ", ":"), ("--user=", ":"), ("-U ", "%")):
        cleaned, count = redact(f"x {flag}{'u' * 256}{sep}hunter2hunter2 y")
        assert (cleaned, count) == (f"x {MASK} y", 1), flag
        assert redact(f"x {flag}{'u' * 257}{sep}hunter2hunter2 y")[1] == 0, flag
