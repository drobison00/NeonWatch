#!/usr/bin/env python3
"""Install the root agent as a hardened system service, and the broker and service as user units.

Each step runs as the user it names. Nothing here imports neonwatch, so root runs only this file
and the standard library:

    uv run python tools/services.py bundle                     # as you: build what /opt gets
    sudo /usr/bin/python3 -I tools/services.py install-agent --operator "$USER"
    python3 tools/services.py install-user                     # as you: broker + service units
    sudo /usr/bin/python3 -I tools/services.py uninstall-agent
    python3 tools/services.py uninstall-user

`install-agent` copies the bundle into a directory only root can write before it checks a single
hash, so nothing your account can change is read after it was verified. It builds
/opt/neonwatch.new (a venv on the system python, with the neonwatch and nats-py wheels unpacked
into it), imports the agent's modules from it, refuses unless every file is root's and writable
by nobody else, swaps it into /opt/neonwatch (the previous install kept as /opt/neonwatch.old) and
writes the unit.

What this does not close: the bundle is built by your account, so installing trusts your account
at that moment, and so does running this file under sudo. What it closes is the standing
exposure: from then on the unit runs nothing your account can modify. The build itself runs only
pinned code: nats-py comes from uv.lock by hash, and the build backend that writes our wheel from
build-constraints.txt by hash, so a new release of either cannot reach /opt unannounced.

`--root DIR` installs under DIR as a staging prefix (the unit still names /opt/neonwatch) and
expects files owned by whoever runs it; with `--no-systemctl` that is how the tests run it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

REPO = Path(__file__).resolve().parent.parent
BUNDLE = REPO / "dist" / "agent"
PREFIX = "opt/neonwatch"
UNIT_DIR = "etc/systemd/system"
UNIT = "neonwatch-agent@.service"
USER_UNITS = ("neonwatch-broker.service", "neonwatch-service.service")
PYTHON = "/usr/bin/python3"
NATS = "nats-py"
MANIFEST = "manifest.json"
#: The build backend and its imports, pinned by hash: what writes the wheel root installs.
BUILD_CONSTRAINTS = "build-constraints.txt"
#: What `neonwatch.launch agent` imports once it runs; importing them proves the bundle is whole.
AGENT_MODULES = ("neonwatch.launch", "neonwatch.bus", "neonwatch.collector", "neonwatch.executor",
                 "neonwatch.probes")
OPERATOR = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
PLAIN_PATH = re.compile(r"/[A-Za-z0-9._/-]+")

Run = Callable[..., object]


class Refused(Exception):
    """A precondition does not hold; nothing was installed past the point it was found."""


# The capabilities are the probes' needs, each for a named reason:
#   DAC_READ_SEARCH  read root-only files: the journal, /proc/<pid>/fd for `ss -p`, devices
#   SYS_RAWIO        smartctl's ATA/SCSI passthrough       SYS_ADMIN  smartctl's NVMe admin ioctl
#   NET_ADMIN        `nft list ruleset`                    SYS_PTRACE /proc/<pid>/exe, `ss -p`
#   SETUID SETGID    drop nvidia-smi and apt-get to nobody KILL       end a timed-out nobody group
AGENT_UNIT = """\
[Unit]
Description=neonwatch agent: the read-only root observer, for %i
After=network.target

[Service]
Type=exec
ExecStart=/opt/neonwatch/venv/bin/python -I -B -m neonwatch.launch agent --operator %i \
--require-confined
WorkingDirectory=/
Restart=on-failure
RestartSec=30
UMask=0077

# The filesystem: everything read-only, and the agent refuses to start if it is not.
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes

# Privilege: only what the probes need, and no way to gain more.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_RAWIO CAP_SYS_ADMIN CAP_NET_ADMIN \
CAP_SYS_PTRACE CAP_SETUID CAP_SETGID CAP_KILL
NoNewPrivileges=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @raw-io @reboot \
@resources @swap
# A denied call fails with EPERM, so it shows up as a probe error rather than a crash.
SystemCallErrorNumber=EPERM

# The network: loopback only (the broker), plus netlink for `ss` and `nft`.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
IPAddressAllow=localhost
IPAddressDeny=any

# Resources: an observer stays out of the way of what it observes.
CPUQuota=50%
MemoryMax=512M
TasksMax=64
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=multi-user.target
"""


def user_units(checkout: Path) -> dict[str, str]:
    """The broker and service as `systemctl --user` units running from `checkout`."""
    if not PLAIN_PATH.fullmatch(str(checkout)):
        raise Refused(f"{checkout} has characters a unit file would have to quote; use a "
                      f"checkout path of letters, digits and ._/-")
    neonwatch = f"{checkout}/.venv/bin/neonwatch"
    return {
        "neonwatch-broker.service": f"""\
[Unit]
Description=neonwatch broker: NATS JetStream on loopback

[Service]
Type=exec
# The broker's nats-server path (.tools/nats-server by default) is relative to the checkout.
WorkingDirectory={checkout}
ExecStart={neonwatch} broker
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes

[Install]
WantedBy=default.target
""",
        "neonwatch-service.service": f"""\
[Unit]
Description=neonwatch service: evaluator, judge client and dashboard
Requires=neonwatch-broker.service
After=neonwatch-broker.service

[Service]
Type=exec
WorkingDirectory={checkout}
ExecStart={neonwatch} service
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes

[Install]
WantedBy=default.target
""",
    }


# --- bundle (as the operator) --------------------------------------------------------------------


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def locked_wheel(lock: Path, name: str) -> tuple[str, str]:
    """The one pure-python wheel uv.lock pins for `name`: its URL and sha256."""
    for package in tomllib.loads(lock.read_text())["package"]:
        if package["name"] == name:
            pure = [w for w in package.get("wheels", [])
                    if w["url"].endswith("-py3-none-any.whl")]
            if len(pure) != 1:
                raise Refused(f"{lock} pins {len(pure)} pure-python wheels for {name}, not one")
            return pure[0]["url"], pure[0]["hash"].removeprefix("sha256:")
    raise Refused(f"{name} is not in {lock}")


def fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise Refused(f"refusing to fetch {url}: not https")
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def bundle(out: Path = BUNDLE, *, repo: Path = REPO, run: Run = subprocess.run,
           get: Callable[[str], bytes] = fetch) -> dict:
    """Build the neonwatch wheel and fetch the nats-py wheel uv.lock pins, into `out`."""
    if os.geteuid() == 0:
        raise Refused("bundle as yourself, not as root: it runs uv in your checkout")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    run(["uv", "build", "--wheel", "--require-hashes", "--build-constraints",
         str(repo / BUILD_CONSTRAINTS), "--out-dir", str(out), str(repo)], check=True)
    built = sorted(out.glob("*.whl"))
    if len(built) != 1:
        raise Refused(f"uv build left {len(built)} wheels in {out}, not one")
    url, digest = locked_wheel(repo / "uv.lock", NATS)
    nats = out / url.rsplit("/", 1)[1]
    nats.write_bytes(get(url))
    if (found := sha256(nats)) != digest:
        nats.unlink()
        raise Refused(f"{nats.name} has sha256 {found}, but uv.lock pins {digest}")
    manifest = {"wheels": {wheel.name: sha256(wheel) for wheel in (built[0], nats)}}
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


# --- install-agent (as root) ---------------------------------------------------------------------


def operator_named(name: str, getpwnam: Callable[[str], Any] = pwd.getpwnam) -> str:
    if not OPERATOR.fullmatch(name):
        raise Refused(f"--operator {name!r} is not a plain user name")
    try:
        entry = getpwnam(name)
    except KeyError:
        raise Refused(f"--operator {name!r}: no such user") from None
    if entry.pw_uid == 0:
        raise Refused("--operator is the person the agent observes for, never root")
    return name


def verified_copy(source: Path, into: Path) -> dict[str, str]:
    """Copy the manifest and its wheels into `into`, then check every hash on the copies."""
    shutil.copyfile(source / MANIFEST, into / MANIFEST)
    wheels = json.loads((into / MANIFEST).read_text())["wheels"]
    for name, digest in wheels.items():
        if PurePosixPath(name).name != name or not name.endswith(".whl"):
            raise Refused(f"the manifest names {name!r}, which is not a wheel file name")
        shutil.copyfile(source / name, into / name)
        if (found := sha256(into / name)) != digest:
            raise Refused(f"{name} has sha256 {found}, but the manifest says {digest}")
    return wheels


def unpack(wheel: Path, site: Path) -> None:
    """Unpack a pure wheel into site-packages, refusing anything that would land elsewhere."""
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            if (path.is_absolute() or ".." in path.parts
                    or path.parts[0].endswith(".data")):
                raise Refused(f"{wheel.name} has {member.filename!r}, which would install "
                              f"outside site-packages")
            if member.is_dir():
                continue
            target = site.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as src, open(target, "xb") as dst:
                shutil.copyfileobj(src, dst)


def check_owned(top: Path, uid: int, *, above: Path) -> None:
    """Refuse unless `top`, everything in it and every directory from `above` down to it is
    owned by `uid` and not writable by group or others (a symlink's own mode means nothing)."""
    paths = [top, *(Path(d) / n for d, dirs, files in os.walk(top) for n in dirs + files)]
    parent = top.parent
    while True:
        paths.append(parent)
        if parent in (above, parent.parent):
            break
        parent = parent.parent
    for path in paths:
        st = path.lstat()
        if st.st_uid != uid:
            raise Refused(f"{path} is owned by uid {st.st_uid}, not {uid}")
        if not path.is_symlink() and st.st_mode & 0o022:
            raise Refused(f"{path} is writable by group or others ({st.st_mode & 0o777:o})")


def install_agent(operator: str, *, source: Path = BUNDLE, root: Path = Path("/"),
                  uid: int = 0, run: Run = subprocess.run, systemctl: bool = True,
                  python: str = PYTHON,
                  getpwnam: Callable[[str], Any] = pwd.getpwnam) -> Path:
    operator = operator_named(operator, getpwnam)
    if os.stat(python).st_uid != 0:
        raise Refused(f"{python} is not root's; the agent's interpreter must be")
    umask = os.umask(0o022)
    try:
        return _install_agent(operator, source, root, uid, run, systemctl, python)
    finally:
        os.umask(umask)


def _install_agent(operator: str, source: Path, root: Path, uid: int, run: Run,
                   systemctl: bool, python: str) -> Path:
    opt = root / PREFIX
    opt.parent.mkdir(parents=True, exist_ok=True)
    new, old = opt.with_name("neonwatch.new"), opt.with_name("neonwatch.old")
    staging = Path(tempfile.mkdtemp(prefix=".neonwatch-bundle-", dir=opt.parent))
    try:
        wheels = verified_copy(source, staging)
        if new.exists():
            shutil.rmtree(new)
        new.mkdir()
        run([python, "-I", "-m", "venv", "--without-pip", str(new / "venv")], check=True)
        (site,) = (new / "venv" / "lib").glob("python3.*/site-packages")
        for name in wheels:
            unpack(staging / name, site)
        shutil.copyfile(staging / MANIFEST, new / MANIFEST)
        check_owned(new, uid, above=root)
        run([str(new / "venv" / "bin" / "python"), "-I", "-B", "-c",
             "import " + ", ".join(AGENT_MODULES)], check=True)
    finally:
        shutil.rmtree(staging)
    if old.exists():
        shutil.rmtree(old)
    if opt.exists():
        opt.rename(old)
    new.rename(opt)
    unit = root / UNIT_DIR / UNIT
    unit.parent.mkdir(parents=True, exist_ok=True)
    _write(unit, AGENT_UNIT)
    instance = f"neonwatch-agent@{operator}.service"
    if systemctl:
        run(["systemctl", "daemon-reload"], check=True)
        run(["systemctl", "enable", instance], check=True)
        run(["systemctl", "try-restart", instance], check=True)
    print(f"installed /{PREFIX} and /{UNIT_DIR}/{UNIT}"
          f"{f', and enabled {instance}' if systemctl else ''}.\n"
          f"Stop a hand-started agent first (Ctrl-C in its terminal), then:\n"
          f"  sudo systemctl start {instance}\n"
          f"  journalctl -u {instance} -f")
    return opt


def uninstall_agent(*, root: Path = Path("/"), run: Run = subprocess.run,
                    systemctl: bool = True) -> list[str]:
    instances = sorted({link.name for link in (root / UNIT_DIR).glob("*.wants/neonwatch-agent@*")})
    if systemctl:
        for instance in instances:
            run(["systemctl", "disable", "--now", instance], check=True)
    (root / UNIT_DIR / UNIT).unlink(missing_ok=True)
    if systemctl:
        run(["systemctl", "daemon-reload"], check=True)
    for tree in ("neonwatch", "neonwatch.old", "neonwatch.new"):
        shutil.rmtree((root / PREFIX).with_name(tree), ignore_errors=True)
    print(f"removed the agent unit and /{PREFIX}" + (f"; disabled {', '.join(instances)}"
                                                     if instances else ""))
    return instances


# --- user units (as the operator) ----------------------------------------------------------------


def install_user(checkout: Path = REPO, *, home: Path | None = None, run: Run = subprocess.run,
                 systemctl: bool = True) -> list[Path]:
    if os.geteuid() == 0:
        raise Refused("install the user units as yourself, not as root")
    for needed in (".venv/bin/neonwatch", ".tools/nats-server"):
        if not (checkout / needed).exists():
            raise Refused(f"{checkout / needed} is missing; run 'uv sync' and "
                          f"scripts/fetch-nats-server in {checkout} first")
    where = (home or Path.home()) / ".config" / "systemd" / "user"
    where.mkdir(parents=True, exist_ok=True)
    written = []
    for name, text in user_units(checkout).items():
        _write(where / name, text)
        written.append(where / name)
    if systemctl:
        run(["systemctl", "--user", "daemon-reload"], check=True)
        run(["systemctl", "--user", "enable", *USER_UNITS], check=True)
        run(["systemctl", "--user", "try-restart", *USER_UNITS], check=True)
    print(f"installed {'and enabled ' if systemctl else ''}{' and '.join(USER_UNITS)} "
          f"from {checkout}.\n"
          f"Stop a hand-started broker and service first, then:\n"
          f"  systemctl --user start neonwatch-service     # starts the broker too\n"
          f"To keep them running when you are logged out, and start them at boot:\n"
          f"  sudo loginctl enable-linger {pwd.getpwuid(os.getuid()).pw_name}")
    return written


def uninstall_user(*, home: Path | None = None, run: Run = subprocess.run,
                   systemctl: bool = True) -> None:
    if systemctl:
        run(["systemctl", "--user", "disable", "--now", *USER_UNITS], check=False)
    where = (home or Path.home()) / ".config" / "systemd" / "user"
    for name in USER_UNITS:
        (where / name).unlink(missing_ok=True)
    if systemctl:
        run(["systemctl", "--user", "daemon-reload"], check=True)
    print(f"removed {' and '.join(USER_UNITS)}")


def _write(path: Path, text: str) -> None:
    """Write a 0644 file by rename, so a reader never sees half of it."""
    partial = path.with_name(f".{path.name}.partial")
    partial.write_text(text)
    partial.chmod(0o644)
    partial.replace(path)


# --- the command line ----------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="services.py", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("bundle", help="as you: build the wheels /opt gets, into dist/agent")
    agent = commands.add_parser("install-agent", help="as root: install /opt and the unit")
    agent.add_argument("--operator", required=True, metavar="USER",
                       help="the user the agent observes for")
    commands.add_parser("uninstall-agent", help="as root: remove the unit and /opt/neonwatch")
    commands.add_parser("install-user", help="as you: the broker and service user units")
    commands.add_parser("uninstall-user", help="as you: remove the user units")
    for command in commands.choices.values():
        command.add_argument("--no-systemctl", action="store_true",
                             help="write the files only; do not call systemctl")
    for name in ("install-agent", "uninstall-agent"):
        commands.choices[name].add_argument("--root", metavar="DIR", type=Path,
                                            help="install under DIR, owned by you (for tests)")
    args = parser.parse_args(argv)
    systemctl = not args.no_systemctl
    try:
        if args.command == "bundle":
            print(json.dumps(bundle(BUNDLE), indent=2))
        elif args.command in ("install-agent", "uninstall-agent"):
            if args.root is None and os.geteuid() != 0:
                raise Refused(f"{args.command} writes /opt and /etc: run it with "
                              f"sudo {PYTHON} -I tools/services.py {args.command} ...")
            root = args.root or Path("/")
            if args.command == "install-agent":
                install_agent(args.operator, source=BUNDLE, root=root, uid=os.geteuid(),
                              systemctl=systemctl)
            else:
                uninstall_agent(root=root, systemctl=systemctl)
        elif args.command == "install-user":
            install_user(REPO, systemctl=systemctl)
        else:
            uninstall_user(systemctl=systemctl)
    except (Refused, subprocess.CalledProcessError, OSError) as failed:
        print(f"services.py {args.command}: {failed}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
