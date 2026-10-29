"""The agent token file: created private and once, read only when it is safe, rotated in place."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from neonwatch import agent_token
from neonwatch.agent_token import TokenError
from neonwatch.config import Config, Store

ME = os.getuid()


def test_the_token_lives_beside_the_store(tmp_path: Path) -> None:
    config = Config(store=Store(path=str(tmp_path / "state" / "store.sqlite3")))
    assert agent_token.path(config) == tmp_path / "state" / "agent.token"
    assert agent_token.path(Config()) == Path("~/.local/state/neonwatch/agent.token").expanduser()


def test_ensure_creates_a_private_file_once(tmp_path: Path) -> None:
    where = tmp_path / "state" / "agent.token"
    old = os.umask(0)
    try:
        token, created = agent_token.ensure(where, ME)
    finally:
        os.umask(old)
    assert created and len(token) >= 32
    assert stat.S_IMODE(where.stat().st_mode) == 0o600
    assert where.read_text() == token + "\n"
    assert agent_token.ensure(where, ME) == (token, False)
    assert agent_token.read(where, ME) == token


def test_ensure_refuses_an_unsafe_file_rather_than_replacing_it(tmp_path: Path) -> None:
    where = tmp_path / "agent.token"
    where.write_text("x" * 40 + "\n")
    where.chmod(0o644)
    with pytest.raises(TokenError, match="mode 0644"):
        agent_token.ensure(where, ME)
    assert where.read_text() == "x" * 40 + "\n"


def test_ensure_never_writes_through_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    where = tmp_path / "agent.token"
    where.symlink_to(target)  # dangling: O_EXCL must not create the target
    with pytest.raises(TokenError, match="symlink"):
        agent_token.ensure(where, ME)
    assert not target.exists()


def test_ensure_reads_a_file_another_process_made_meanwhile(tmp_path: Path, monkeypatch) -> None:
    where = tmp_path / "agent.token"
    real = agent_token._write

    def racing(path: Path, token: str) -> None:
        real(path, "r" * 40)  # the other process wins
        real(path, token)  # and ours meets O_EXCL

    monkeypatch.setattr(agent_token, "_write", racing)
    assert agent_token.ensure(where, ME) == ("r" * 40, False)


@pytest.mark.parametrize("content, why", [
    ("short\n", "does not hold a token"),
    ("x" * 300, "300 bytes"),
    ("has space " + "x" * 40, "does not hold a token"),
    ("", "does not hold a token"),
])
def test_read_refuses_what_is_not_one_token(tmp_path: Path, content: str, why: str) -> None:
    where = tmp_path / "agent.token"
    where.write_text(content)
    where.chmod(0o600)
    with pytest.raises(TokenError, match=why):
        agent_token.read(where, ME)


def test_read_refuses_a_missing_file_a_directory_and_another_owner(tmp_path: Path) -> None:
    with pytest.raises(TokenError, match="no agent token"):
        agent_token.read(tmp_path / "missing", ME)
    (tmp_path / "dir").mkdir(mode=0o700)
    with pytest.raises(TokenError, match="not a regular file"):
        agent_token.read(tmp_path / "dir", ME)
    where = tmp_path / "agent.token"
    agent_token.ensure(where, ME)
    with pytest.raises(TokenError, match=f"owned by uid {ME}, not {ME + 1}"):
        agent_token.read(where, ME + 1)


def test_a_symlink_to_a_good_token_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real.token"
    agent_token.ensure(real, ME)
    link = tmp_path / "agent.token"
    link.symlink_to(real)
    with pytest.raises(TokenError, match="symlink"):
        agent_token.read(link, ME)


def test_rotate_replaces_the_token_atomically(tmp_path: Path) -> None:
    where = tmp_path / "state" / "agent.token"
    first = agent_token.rotate(where, ME)  # creates when missing
    second = agent_token.rotate(where, ME)
    assert first != second
    assert agent_token.read(where, ME) == second
    assert stat.S_IMODE(where.stat().st_mode) == 0o600
    assert sorted(p.name for p in where.parent.iterdir()) == ["agent.token"]


def test_rotate_replaces_a_symlink_without_following_it(tmp_path: Path) -> None:
    target = tmp_path / "victim"
    target.write_text("keep me")
    where = tmp_path / "agent.token"
    where.symlink_to(target)
    with pytest.raises(TokenError, match="refusing to replace"):
        agent_token.rotate(where, ME)
    assert target.read_text() == "keep me" and where.is_symlink()


def test_rotate_refuses_a_file_another_uid_owns(tmp_path: Path) -> None:
    where = tmp_path / "agent.token"
    agent_token.ensure(where, ME)
    with pytest.raises(TokenError, match="refusing to replace"):
        agent_token.rotate(where, ME + 1)


def test_rotate_leaves_no_staged_file_when_the_rename_fails(tmp_path: Path, monkeypatch) -> None:
    where = tmp_path / "agent.token"
    token = agent_token.ensure(where, ME)[0]

    def broken(*_: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(agent_token.os, "replace", broken)
    with pytest.raises(OSError, match="disk full"):
        agent_token.rotate(where, ME)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["agent.token"]
    assert agent_token.read(where, ME) == token
