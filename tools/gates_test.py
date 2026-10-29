"""Every gate, seen red on a planted violation and quiet on the clean control."""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

from tools import gates


def tree(root: Path, files: dict[str, str], components: list[dict], edges=()) -> Path:
    """A fixture repository: files, plus a plan.json naming the components and edges."""
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (root / "neonwatch" / "__init__.py").touch()
    (root / "plan.json").write_text(json.dumps({
        "components": components,
        "dependency_edges": [{"component": a, "depends_on": b} for a, b in edges]}))
    return root


def component(name: str, *files: str) -> dict:
    return {"name": name, "files": list(files)}


# --- components -------------------------------------------------------------------------------


def test_a_module_without_a_sibling_test_is_refused(tmp_path):
    root = tree(tmp_path, {"neonwatch/lonely.py": ""}, [component("lonely", "neonwatch/lonely.py")])
    assert gates.check_components(root) == ["components: neonwatch/lonely.py has no sibling test"]


def test_a_test_without_its_module_is_refused(tmp_path):
    root = tree(tmp_path, {"neonwatch/ghost_test.py": ""}, [])
    assert gates.check_components(root) == [
        "components: neonwatch/ghost_test.py tests a module that does not exist"]


def test_a_module_with_its_test_passes(tmp_path):
    root = tree(tmp_path, {"neonwatch/a.py": "", "neonwatch/a_test.py": ""},
                [component("a", "neonwatch/a.py")])
    assert gates.check_components(root) == []


# --- levels and insulation ----------------------------------------------------------------------


LAYERED = {
    "neonwatch/low.py": "",
    "neonwatch/low_test.py": "",
    "neonwatch/high.py": "from neonwatch import low\n",
    "neonwatch/high_test.py": "import sqlite3\n",  # a test may use any library
}
COMPONENTS = [component("low", "neonwatch/low.py"), component("high", "neonwatch/high.py")]


def test_a_declared_edge_passes_and_an_undeclared_one_is_refused(tmp_path):
    root = tree(tmp_path, LAYERED, COMPONENTS, edges=[("high", "low")])
    assert gates.check_levels_and_insulation(root) == []

    upward = dict(LAYERED, **{"neonwatch/low.py": "from neonwatch import high\n"})
    root = tree(tmp_path / "up", upward, COMPONENTS, edges=[("high", "low")])
    assert gates.check_levels_and_insulation(root) == [
        "levels: neonwatch/low.py:1 imports high but plan.json declares no edge low -> high"]


def test_a_module_outside_the_plan_and_an_import_of_nothing_are_refused(tmp_path):
    root = tree(tmp_path, {"neonwatch/stray.py": "import neonwatch.nowhere\n",
                           "neonwatch/stray_test.py": ""}, [])
    assert gates.check_levels_and_insulation(root) == [
        "levels: neonwatch/stray.py belongs to no component in plan.json",
        "levels: neonwatch/stray_test.py belongs to no component in plan.json"]

    root = tree(tmp_path / "b", {"neonwatch/a.py": "import neonwatch.nowhere\n"},
                [component("a", "neonwatch/a.py")])
    assert gates.check_levels_and_insulation(root) == [
        "levels: neonwatch/a.py:1 imports neonwatch.nowhere, which no component owns"]


def test_a_package_component_owns_its_directory(tmp_path):
    files = {"neonwatch/pkg/__init__.py": "",
             "neonwatch/pkg/part.py": "from neonwatch.pkg import x\n",
             "neonwatch/pkg/x.py": "", "neonwatch/pkg/part_test.py": "",
             "neonwatch/pkg/x_test.py": ""}
    root = tree(tmp_path, files, [component("pkg", "neonwatch/pkg/__init__.py")])
    assert gates.check_levels_and_insulation(root) == []


def test_only_the_network_half_of_the_stdlib_is_insulated(tmp_path):
    source = ("from urllib.parse import urlsplit\nfrom http import HTTPStatus\n"
              "import urllib.request\nfrom http import client\nimport http.server\n")
    root = tree(tmp_path, {"neonwatch/config.py": source},
                [component("config", "neonwatch/config.py")])
    assert gates.check_levels_and_insulation(root) == [
        "insulation: neonwatch/config.py:3 imports urllib.request, owned by analyst, judge",
        "insulation: neonwatch/config.py:4 imports http.client, owned by analyst, executor, judge, "
        "mcp",
        "insulation: neonwatch/config.py:5 imports http.server, owned by no component"]


def test_an_insulated_library_outside_its_owner_is_refused(tmp_path):
    root = tree(tmp_path, {"neonwatch/web.py": "import sqlite3\nfrom nats import aio\n",
                           "neonwatch/store.py": "import sqlite3\n"},
                [component("web", "neonwatch/web.py"), component("store", "neonwatch/store.py")])
    assert gates.check_levels_and_insulation(root) == [
        "insulation: neonwatch/web.py:1 imports sqlite3, owned by store",
        "insulation: neonwatch/web.py:2 imports nats, owned by bus"]



SPAWNING = {
    "neonwatch/web.py": "import asyncio\nasync def f():\n"
                       "    await asyncio.create_subprocess_exec('/bin/x')\n",
    "neonwatch/store.py": "from asyncio import create_subprocess_shell as run\nrun('x')\n",
    "neonwatch/rules.py": "import asyncio.subprocess as sp\nimport asyncio as aio\n"
                         "x = sp.PIPE\ny = aio.subprocess.DEVNULL\n",
    "neonwatch/jobs.py": "def f(loop):\n    return loop.subprocess_exec(None, 'x')\n",
    "neonwatch/notifier.py": "import asyncio\nasyncio.create_subprocess_exec('/usr/bin/gdbus')\n",
    "neonwatch/logs.py": "import asyncio\nasyncio.create_subprocess_exec('/usr/bin/journalctl')\n",
    "neonwatch/logs_test.py": "",
    "neonwatch/web_test.py": "import asyncio\nasyncio.create_subprocess_exec('/bin/x')\n",
    "neonwatch/config.py": "import asyncio\nasyncio.sleep(1)\n",
}


def test_a_process_started_through_asyncio_is_held_to_subprocess_owners(tmp_path):
    names = ("web", "store", "rules", "jobs", "notifier", "logs", "config")
    root = tree(tmp_path, SPAWNING, [component(n, f"neonwatch/{n}.py") for n in names])
    owners = "broker, executor, logs, notifier"
    found = [
        ("jobs.py:2", ".subprocess_exec()"),
        ("rules.py:1", "asyncio.subprocess"),
        ("rules.py:3", "asyncio.subprocess.PIPE"),
        ("rules.py:4", "asyncio.subprocess.DEVNULL"),
        ("store.py:1", "asyncio.create_subprocess_shell"),
        ("store.py:2", "asyncio.create_subprocess_shell"),
        ("web.py:3", "asyncio.create_subprocess_exec"),
    ]
    assert gates.check_levels_and_insulation(root) == [
        f"insulation: neonwatch/{where} starts a process ({name}), which only subprocess's "
        f"owners may: {owners}" for where, name in found]


def test_a_relative_import_is_resolved_and_held_to_the_plan(tmp_path):
    files = {"neonwatch/collector.py": "from . import store\n", "neonwatch/store.py": "",
             "neonwatch/pkg/__init__.py": "from .part import x\nfrom .. import store\n",
             "neonwatch/pkg/part.py": ""}
    root = tree(tmp_path, files, [component("collector", "neonwatch/collector.py"),
                                  component("store", "neonwatch/store.py"),
                                  component("pkg", "neonwatch/pkg/__init__.py")])
    assert gates.check_levels_and_insulation(root) == [
        "levels: neonwatch/collector.py:1 imports store but plan.json declares no edge "
        "collector -> store",
        "levels: neonwatch/pkg/__init__.py:2 imports store but plan.json declares no edge "
        "pkg -> store"]


def test_a_package_init_is_scanned_for_levels_and_insulation(tmp_path):
    files = {"neonwatch/pkg/__init__.py": "import sqlite3\n", "neonwatch/pkg/part.py": ""}
    root = tree(tmp_path, files, [component("pkg", "neonwatch/pkg/__init__.py")])
    assert gates.check_levels_and_insulation(root) == [
        "insulation: neonwatch/pkg/__init__.py:1 imports sqlite3, owned by store"]


# --- read-only ---------------------------------------------------------------------------------

#: Where each privileged component's file lives in a fixture tree.
FILES = {"collector": "neonwatch/collector.py", "executor": "neonwatch/executor.py",
         "bus": "neonwatch/bus.py", "launcher": "neonwatch/launch.py",
         "probes": "neonwatch/probes/__init__.py", "config": "neonwatch/config.py",
         "broker": "neonwatch/broker.py", "service": "neonwatch/service.py",
         "store": "neonwatch/store.py"}


def read_only(root: Path, sources: dict[str, str]) -> list[str]:
    """check_read_only over a tree holding `sources` (component -> code), every component known."""
    files = {FILES[name]: textwrap.dedent(code) for name, code in sources.items()}
    for rel in FILES.values():
        files.setdefault(rel, "")
    return gates.check_read_only(tree(root, files, [component(n, f) for n, f in FILES.items()]))


#: Each bypass demonstrated against an earlier denylist gate, as it was planted: (component,
#: code, what the finding must say).
BYPASSES = {
    "from os import remove": (
        "collector", "from os import remove\ndef _x(p):\n    remove(p)\n",
        "uses os.remove, which is not on the os allowlist"),
    "import os as o; o.unlink": (
        "collector", "import os as o\ndef _x(p):\n    o.unlink(p)\n", "uses os.unlink"),
    "getattr(os, 'remove')": (
        "collector", "import os\ndef _x(p):\n    getattr(os, 'remove')(p)\n",
        "calls getattr on the module os"),
    "Path(p).open('w')": (
        "collector", "from pathlib import Path\ndef _x(p):\n    Path(p).open('w').write('x')\n",
        "opens a file in mode 'w'"),
    "os.fdopen(os.open(p, 577), 'w') - flags": (
        "collector", "import os\ndef _x(p):\n    os.fdopen(os.open(p, 577), 'w')\n",
        "os.open flags are not a literal OR of"),
    "os.fdopen(os.open(p, 577), 'w') - mode": (
        "collector", "import os\ndef _x(p):\n    os.fdopen(os.open(p, 577), 'w')\n",
        "opens a file in mode 'w'"),
    "asyncio.create_subprocess_exec": (
        "collector",
        "import asyncio\nasync def _x(p):\n"
        "    await asyncio.create_subprocess_exec('/usr/bin/rm', '-f', p)\n",
        "creates a process: asyncio.create_subprocess_exec"),
    "subprocess.run inside executor": (
        "executor", "import subprocess\ndef _x(p):\n    subprocess.run(['/usr/bin/rm', '-f', p])\n",
        "creates a process: subprocess.run"),
    "raw socket sending 'PO'+'ST' - the method": (
        "executor",
        "def _x(s):\n"
        "    s.sendall(('PO' + 'ST /containers/x/stop HTTP/1.1\\r\\n\\r\\n').encode())\n",
        "names HTTP method POST"),
    "raw socket sending 'PO'+'ST' - the send": (
        "executor",
        "def _x(s):\n"
        "    s.sendall(('PO' + 'ST /containers/x/stop HTTP/1.1\\r\\n\\r\\n').encode())\n",
        "calls .sendall(), which writes to a socket"),
    "from . import store": (
        "collector", "from . import store as _store\n", "uses a relative import"),
    "importlib.import_module('sqlite3')": (
        "collector", "import importlib\n_db = importlib.import_module('sqlite3')\n",
        "imports dynamically: importlib"),
    "__import__('sqlite3')": (
        "collector", "_db = __import__('sqlite3')\n", "uses __import__"),
    "os.remove in probes/__init__.py": (
        "probes", "import os\ndef _x(p):\n    os.remove(p)\n", "uses os.remove"),
    # Both passed "gates: all hold" before the chain and by-name rules.
    "os.path.os.system": (
        "collector", "import os\ndef _x():\n    os.path.os.system('true')\n",
        "creates a process: os.system (reached as os.path.os.system)"),
    "getattr(pathlib.Path(p), 'write' + '_text')": (
        "collector",
        "import pathlib\ndef _x(p):\n    getattr(pathlib.Path(p), 'write' + '_text')('x')\n",
        "calls getattr for .write_text, which is judged only where called"),
    "a nested function named _kill_own_group": (
        "executor",
        "import os\ndef _other():\n    def _kill_own_group(proc):\n        os.killpg(1, 9)\n"
        "    return _kill_own_group\n",
        "calls os.killpg outside executor._kill_own_group"),
}


@pytest.mark.parametrize("name", BYPASSES)
def test_every_demonstrated_bypass_is_refused(tmp_path, name):
    owner, code, expected = BYPASSES[name]
    found = read_only(tmp_path, {owner: code})
    assert any(expected in line for line in found), found


#: Further ways round an allowlist, each refused on its own.
EVASIONS = {
    "exec": ("collector", "exec('import os')\n", "uses exec"),
    "eval": ("collector", "eval('1')\n", "uses eval"),
    "compile": ("collector", "compile('1', 'x', 'eval')\n", "uses compile"),
    "globals()": ("collector", "globals()['x'] = 1\n", "uses globals"),
    "a module's __dict__": ("collector", "import os\nos.__dict__\n", "uses __dict__"),
    "from os import *": ("collector", "from os import *\n", "star import"),
    "os bound to another name": ("collector", "import os\nm = os\n", "refers to the module os"),
    "open aliased": ("collector", "o = open\no('/etc/x', 'w')\n", "refers to open"),
    "os.open aliased": ("collector", "import os\nf = os.open\n", "refers to os.open"),
    "setattr on a module": (
        "collector", "from neonwatch import executor\nsetattr(executor, '_admit', id)\n",
        "calls setattr on the module executor"),
    "delattr on a module": (
        "collector", "import re\ndelattr(re, 'compile')\n", "calls delattr on the module re"),
    "assigning into a module": (
        "collector", "from neonwatch import executor\nexecutor._admit = id\n",
        "assigns to executor._admit"),
    "a write-mode open": ("collector", "open('/etc/x', mode='a+')\n", "opens a file in mode 'a+'"),
    "a non-literal mode": ("collector", "def _x(m):\n    open('/etc/x', m)\n",
                           "opens a file with a non-literal mode"),
    "an unpacked open": ("collector", "def _x(a):\n    open(*a)\n", "unpacked arguments"),
    "Path.open(p, 'w')": ("collector", "from pathlib import Path\nPath.open(Path('/x'), 'w')\n",
                          "opens a file in mode 'w'"),
    "os.open with a writing flag": (
        "collector", "import os\nos.open('/x', os.O_RDONLY | os.O_WRONLY)\n",
        "os.open flags are not a literal OR of"),
    "os.open with named flags": (
        "collector", "import os\nFLAGS = os.O_RDONLY\nos.open('/x', FLAGS)\n",
        "os.open flags are not a literal OR of"),
    "os.open without flags": ("collector", "import os\nos.open('/x')\n", "without flags"),
    "an unpacked os.open": ("collector", "import os\ndef _x(a):\n    os.open(*a)\n",
                            "passes unpacked arguments to os.open"),
    "a writing method taken as a value": (
        "collector", "from pathlib import Path\nw = Path('/x').write_text\n",
        "refers to .write_text without calling it"),
    "Popen outside the approved site": (
        "executor", "import subprocess\ndef elsewhere(spec):\n    subprocess.Popen(spec.argv)\n",
        "creates a process outside executor._command"),
    "Popen at the site on another argv": (
        "executor",
        "import subprocess\ndef _command(spec):\n    subprocess.Popen(['/usr/bin/rm', '/x'])\n",
        "creates a process outside executor._command"),
    "Popen at the site with executable=": (
        "executor", "import subprocess\ndef _command(spec):\n"
        "    subprocess.Popen(spec.argv, executable='/usr/bin/rm')\n",
        "creates a process outside executor._command"),
    "Popen twice at the site": (
        "executor", "import subprocess\ndef _command(spec):\n"
        "    subprocess.Popen(spec.argv)\n    subprocess.Popen(spec.argv)\n",
        "neonwatch/executor.py:4 creates a process outside executor._command"),
    "Popen in a function nested in the site": (
        "executor", "import subprocess\ndef _command(spec):\n"
        "    def inner():\n        subprocess.Popen(spec.argv)\n    return inner\n",
        "creates a process outside executor._command"),
    "Popen aliased": ("executor", "import subprocess\nP = subprocess.Popen\n",
                      "creates a process outside executor._command"),
    "Popen from collector": (
        "collector", "import subprocess\ndef _command(spec):\n    subprocess.Popen(spec.argv)\n",
        "creates a process outside executor._command"),
    "a call inside an annotation": (
        "executor", "import os\ndef _x(p: os.remove('/x')):\n    pass\n",
        "calls inside an annotation"),
    "killpg on another pid in the right function": (
        "executor", "import os\ndef _kill_own_group(proc):\n    os.killpg(1, 9)\n",
        "calls os.killpg outside executor._kill_own_group"),
    "killpg on another object's pid": (
        "executor", "import os\ndef _kill_own_group(proc, other):\n    os.killpg(other.pid, 9)\n",
        "calls os.killpg outside executor._kill_own_group"),
    "killpg from the collector": (
        "collector", "import os\ndef _kill_own_group(proc):\n    os.killpg(proc.pid, 9)\n",
        "calls os.killpg outside executor._kill_own_group"),
    "a posix_spawn": ("executor", "import os\nos.posix_spawn('/bin/sh', [], {})\n",
                      "creates a process: os.posix_spawn"),
    "a loop subprocess": ("collector", "def _x(loop):\n    loop.subprocess_exec(None, 'x')\n",
                          "creates a process: .subprocess_exec()"),
    "a socket outside executor": (
        "collector", "import socket\nsocket.socket()\n", "creates a socket: socket.socket"),
    "an asyncio connection": (
        "collector", "import asyncio\nasyncio.open_connection('h', 1)\n",
        "creates a socket: asyncio.open_connection"),
    "a loop connection": ("bus", "def _x(loop):\n    loop.create_connection(None)\n",
                          "creates a socket: .create_connection()"),
    "an uppercase method literal": ("collector", "m = 'DELETE'\n", "names HTTP method DELETE"),
    "an f-string method": ("collector", "m = f'PU' f'T'\n", "names HTTP method PUT"),
    "a bytes request line": ("executor", "m = b'PATCH /x HTTP/1.1'\n", "names HTTP method PATCH"),
    "a non-GET request": ("executor", "def _x(c):\n    c.request('POST', '/x')\n",
                          "sends an HTTP method that is not a literal 'GET'"),
    "putrequest passing the method on": (
        "executor", "def _x(c, method, url):\n    c.putrequest(method, url)\n",
        "sends an HTTP method that is not a literal 'GET'"),
    "shell=True": ("collector", "def _x(run):\n    run('x', shell=True)\n", "passes shell=True"),
    "a writing method": ("collector", "from pathlib import Path\nPath('/x').write_text('x')\n",
                         "calls .write_text(), which writes"),
    "Path.replace": ("collector", "from pathlib import Path\nPath('/a').replace(Path('/b'))\n",
                     "calls .replace(), which writes"),
    "a log file": ("collector", "import logging\nlogging.basicConfig(filename='/etc/x')\n",
                   "logs to a file"),
    "an unlisted library": ("config", "import shutil\n", "imports shutil, which is not on "
                            "config's import allowlist"),
    "an unlisted library, from-imported": (
        "config", "from tempfile import mkstemp\n", "imports tempfile, which is not on"),
    "os in the bus": ("bus", "import os\ndef _x(p):\n    os.unlink(p)\n", "uses os.unlink"),
    "a non-privileged component": (
        "collector", "from neonwatch import store\n", "imports store, which does not run as root"),
}


#: Other routes to the same two holes: a module reached through another module's attributes,
#: and an attribute fetched by a name the gate cannot read.
REACHED = {
    "pathlib.os.system": (
        "collector", "import pathlib\npathlib.os.system('true')\n",
        "creates a process: os.system (reached as pathlib.os.system)"),
    "from-imported glob, then glob.os.remove": (
        "collector", "from glob import os as g\ng.remove('/x')\n",
        "uses os.remove, which is not on the os allowlist"),
    "logging.sys.modules": (
        "collector", "import logging\nlogging.sys.modules['os'].system('true')\n",
        "uses sys.modules, which is not on the sys allowlist (reached as logging.sys.modules)"),
    "random._os.system": (
        "collector", "import random\nrandom._os.system('true')\n",
        "uses _os of random, a private name"),
    "enum.bltns.exec": (
        "probes", "import enum\nenum.bltns.exec('x')\n",
        "uses builtins.exec, which is not on the builtins allowlist (reached as enum.bltns.exec)"),
    "logging.io.FileIO": (
        "collector", "import logging\nlogging.io.FileIO('/x', 'w')\n",
        "uses io.FileIO, which is not on the io allowlist (reached as logging.io.FileIO)"),
    "a module held as a value": (
        "collector", "import glob\nshell = glob.os\n", "reaches the module os as glob.os"),
    "the process site reached through executor": (
        "collector", "from neonwatch import executor\nexecutor.subprocess.Popen(['/x'])\n",
        "creates a process outside executor._command"),
    "getattr with a variable name": (
        "collector", "def _x(o, n):\n    return getattr(o, n)\n",
        "calls getattr with a name it does not spell out"),
    "setattr with a computed name": (
        "collector", "def _x(o, n):\n    setattr(o, 'x' + n, 1)\n",
        "calls setattr with a name it does not spell out"),
    "getattr with no name": (
        "collector", "def _x(o, a):\n    return getattr(o, *a)\n",
        "calls getattr without spelling out the name"),
    "getattr for a dunder": (
        "collector", "def _x(o):\n    return getattr(o, '__globals__')\n",
        "calls getattr for __globals__, which reaches past the allowlist"),
    "getattr on a module reached by a chain": (
        "collector", "import os\ngetattr(os.path, 'join')\n",
        "calls getattr on the module os.path"),
    "a field read of a different object": (
        "collector",
        "import dataclasses\ndef _x(a, b):\n"
        "    return [getattr(b, f.name) for f in dataclasses.fields(a)]\n",
        "calls getattr with a name it does not spell out"),
    "a field read in a for statement, where the object can be rebound": (
        "collector",
        "import dataclasses\ndef _x(a):\n    for f in dataclasses.fields(a):\n"
        "        getattr(a, f.name)\n",
        "calls getattr with a name it does not spell out"),
    "a field read with a walrus in the comprehension": (
        "collector",
        "import dataclasses\ndef _x(a, p):\n"
        "    return [getattr(a, f.name) for f in dataclasses.fields(a) if (a := p)]\n",
        "calls getattr with a name it does not spell out"),
}


@pytest.mark.parametrize("name", REACHED)
def test_a_module_reached_by_another_name_or_an_attribute_by_a_computed_one_is_refused(
        tmp_path, name):
    owner, code, expected = REACHED[name]
    found = read_only(tmp_path, {owner: code})
    assert any(expected in line for line in found), found


def test_chains_through_allowlisted_attributes_and_field_reads_stay_clean(tmp_path):
    source = ("import dataclasses\nimport os\nimport time\n"
              "def _x(record):\n"
              "    os.path.join('/a', 'b'), time.time(), os.O_RDONLY\n"
              "    getattr(record, 'upper', None)\n"
              "    return {f.name: getattr(record, f.name) for f in dataclasses.fields(record)}\n")
    assert read_only(tmp_path / "c", {"collector": source}) == []
    assert read_only(tmp_path / "e", {"executor": "import socket\nsocket.socket\n"}) == []


@pytest.mark.parametrize("name", EVASIONS)
def test_every_other_evasion_is_refused(tmp_path, name):
    owner, code, expected = EVASIONS[name]
    found = read_only(tmp_path, {owner: code})
    assert any(expected in line for line in found), found


#: The shape of the real executor: the one process site, the one group kill, literal read-only
#: opens and a GET-only HTTP connection. It must stay clean, or the gate refuses the boundary.
CLEAN_EXECUTOR = '''
from __future__ import annotations
import http.client
import os
import resource
import signal
import socket
import subprocess

_Reaped = tuple[int, resource.struct_rusage]


def _command(spec, timeout_s: float) -> _Reaped:
    proc = subprocess.Popen(spec.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            env={}, cwd="/", close_fds=True, start_new_session=True)
    return proc


def _collect(proc: subprocess.Popen) -> tuple[int, resource.struct_rusage | None]:
    proc.kill()
    return os.wait4(proc.pid, os.WNOHANG)


def _kill_own_group(proc: subprocess.Popen) -> bool:
    if os.getpgid(proc.pid) != proc.pid:
        return False
    os.killpg(proc.pid, signal.SIGKILL)
    return True


def _read(path: str) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(os.open(path, os.O_RDONLY), "rb") as file:
        file.read()
    with open(path, encoding="utf-8") as a, open(path, "rb") as b, open(path, mode="r") as c:
        a.read(), b.read(), c.read()
    os.close(fd)
    return "a-b".replace("-", "_").encode()


class _Docker(http.client.HTTPConnection):
    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def putrequest(self, method: str, url: str) -> None:
        if method != "GET":
            raise ValueError(f"the executor sends GET only, not {type(method).__name__}")
        super().putrequest("GET", url)


def _docker(connection: _Docker, path: str) -> None:
    connection.request("GET", path)
'''

CLEAN_COLLECTOR = '''
import dataclasses
import os
from pathlib import Path

from neonwatch import executor, probes

open("/proc/loadavg")
open("/proc/loadavg", "rb")
Path("/proc/meminfo").read_text()
Path("/proc/meminfo").open()
line = "x"
line.replace("x", "y")
dataclasses.replace(line)
os.open("/proc/stat", os.O_RDONLY)
method = "GET"
getattr(line, "upper")
statvfs = os.statvfs
runner = executor.execute(probes.CATALOG[0], 1, 1)
'''

CLEAN_LAUNCH = '''
import sys
from neonwatch.config import load


def main(argv):
    sys.dont_write_bytecode = True
    if argv[:1] == ["service"]:
        from neonwatch import service  # lazily, and never on the agent path
        return service.main([])
    return _run_agent(load(None))


def _run_agent(config):
    from neonwatch import bus, collector, executor, probes
    return bus, collector, executor, probes
'''


def test_the_real_shapes_are_clean(tmp_path):
    assert read_only(tmp_path, {"executor": CLEAN_EXECUTOR, "collector": CLEAN_COLLECTOR,
                                "launcher": CLEAN_LAUNCH}) == []


def test_unprivileged_components_are_not_scanned(tmp_path):
    assert read_only(tmp_path, {"store": "import os, shutil\nos.remove('/x')\n"}) == []


def test_the_launcher_imports_non_privileged_code_only_lazily_and_never_as_the_agent(tmp_path):
    source = ("from neonwatch import broker\n"
              "def _agent():\n"
              "    from neonwatch import broker\n"
              "def _run_agent():\n"
              "    def observe():\n"
              "        from neonwatch import service\n")
    assert read_only(tmp_path, {"launcher": source}) == [
        "read-only: neonwatch/launch.py:1 imports broker, which does not run as root, at module "
        "level",
        "read-only: neonwatch/launch.py:3 imports broker, which does not run as root, on the "
        "agent path (_agent)",
        "read-only: neonwatch/launch.py:6 imports service, which does not run as root, on the "
        "agent path (_run_agent)"]


def test_the_package_root_runs_as_root_and_may_import_nothing(tmp_path):
    root = tree(tmp_path, {"neonwatch/__init__.py": "import os\n"}, [])
    assert gates.check_read_only(root) == [
        "read-only: neonwatch/__init__.py:1 imports os, which is not on neonwatch's import "
        "allowlist"]


def test_methods_are_uppercase_names_so_a_lowercase_data_key_passes(tmp_path):
    assert read_only(tmp_path / "key", {"probes": "key = {'options': True}\n"}) == []
    assert read_only(tmp_path / "word", {"probes": "m = 'OPTIONS'\n"}) == [
        "read-only: neonwatch/probes/__init__.py:1 names HTTP method OPTIONS"]
    assert read_only(tmp_path / "folded", {"probes": "m = 'PO' + 'ST'\n"}) == [
        "read-only: neonwatch/probes/__init__.py:1 names HTTP method POST"]


def test_one_finding_per_line_and_reason(tmp_path):
    found = read_only(tmp_path, {"executor": "m = 'POST' + ' /x'\n"})
    assert found == ["read-only: neonwatch/executor.py:1 names HTTP method POST"]


# --- catalog -----------------------------------------------------------------------------------


def test_every_reviewed_argv_passes():
    assert gates.APPROVED_ARGV
    for argv in gates.APPROVED_ARGV:
        assert gates.argv_is_read_only(argv) == "", argv


def test_the_smart_template_passes_only_with_its_reviewed_devices():
    ((argv, devices),) = gates.APPROVED_TEMPLATES.items()
    assert argv[-1] == "/dev/{device}"
    assert gates.argv_is_read_only(argv, devices) == ""
    assert "not a reviewed template" in gates.argv_is_read_only(argv, r".*")
    assert "not a reviewed argv" in gates.argv_is_read_only(argv)
    moved = ("/usr/sbin/smartctl", "-j", "/dev/{device}", "-a")
    assert "not a reviewed template" in gates.argv_is_read_only(moved, devices)


@pytest.mark.parametrize("argv, why", [
    ((), "empty argv"),
    (("/tmp/evil/ps", "-e"), "not an absolute path in /usr/bin, /usr/sbin, /bin, /sbin"),
    (("/home/alice/bin/ss",), "not an absolute path in"),
    (("ps", "-e"), "not an absolute path in"),
    (("/usr/bin/../../tmp/ps",), "not an absolute path in"),
    (("/usr/bin/ss", "-tK"), "not a reviewed argv"),
    (("/usr/bin/ss", "-D", "/etc/passwd"), "not a reviewed argv"),
    (("/usr/sbin/ip", "-j", "-s", "link", "set", "enp5s0", "down"), "not a reviewed argv"),
    (("/usr/sbin/ip", "-j", "-s", "link", "delete", "docker0"), "not a reviewed argv"),
    (("/usr/bin/nvidia-smi", "-q", "-f", "/etc/shadow"), "not a reviewed argv"),
    (("/usr/bin/nvidia-smi", "--query-gpu", "x", "-mig", "1"), "not a reviewed argv"),
    (("/usr/bin/journalctl", "--cursor-file=/etc/ld.so.preload"), "not a reviewed argv"),
    (("/usr/sbin/smartctl", "-j", "-a", "-tlong", "/dev/sda"), "not a reviewed argv"),
    (("/usr/sbin/smartctl", "-j", "-a", "-soff", "/dev/sda"), "not a reviewed argv"),
    (("/usr/bin/sensors", "-j", "-s"), "not a reviewed argv"),
    (("/usr/sbin/iptables-save", "-f", "/etc/passwd"), "not a reviewed argv"),
    (("/usr/sbin/nft", "flush", "ruleset"), "not a reviewed argv"),
    (("/usr/bin/sensors", "-j", "--extra"), "not a reviewed argv"),
])
def test_writing_or_unreviewed_invocations_are_refused(argv, why):
    assert why in gates.argv_is_read_only(argv)


def test_the_binary_directory_is_checked_even_for_a_reviewed_argv(monkeypatch):
    monkeypatch.setattr(gates, "APPROVED_ARGV", gates.APPROVED_ARGV | {("/tmp/evil/ps",)})
    assert "not an absolute path in" in gates.argv_is_read_only(("/tmp/evil/ps",))


def test_the_catalog_gate_waits_for_a_catalog_then_holds_it(tmp_path, monkeypatch):
    assert gates.check_catalog(tmp_path) == []

    probes = tmp_path / "neonwatch" / "probes"
    probes.mkdir(parents=True)
    (tmp_path / "neonwatch" / "__init__.py").touch()
    (probes / "catalog.py").touch()
    (probes / "__init__.py").write_text(
        "from types import SimpleNamespace as S\n"
        "CATALOG = (S(id='fw', argv=('/usr/sbin/nft', '-j', 'list', 'ruleset'), devices=''),\n"
        "           S(id='smart', argv=('/usr/sbin/smartctl', '-j', '-a', '/dev/{device}'),\n"
        "             devices=r'nvme\\d+n\\d+|sd[a-z]+'),\n"
        "           S(id='bad', argv=('/usr/sbin/nft', 'flush', 'ruleset'), devices=''),\n"
        "           S(id='file', argv=(), devices=''))\n")
    for name in [m for m in sys.modules if m == "neonwatch" or m.startswith("neonwatch.")]:
        monkeypatch.delitem(sys.modules, name)
    found = gates.check_catalog(tmp_path)
    assert len(found) == 1 and found[0].startswith("catalog: bad:")


def test_every_argv_that_must_drop_root_is_a_reviewed_argv():
    assert gates.UNPRIVILEGED_ARGV and gates.UNPRIVILEGED_ARGV <= gates.APPROVED_ARGV


@pytest.mark.parametrize("argv", sorted(gates.UNPRIVILEGED_ARGV), ids=lambda a: a[0])
def test_the_catalog_gate_refuses_an_argv_that_must_drop_root_run_as_root(argv, tmp_path,
                                                                         monkeypatch):
    probes = tmp_path / "neonwatch" / "probes"
    probes.mkdir(parents=True)
    (tmp_path / "neonwatch" / "__init__.py").touch()
    (probes / "catalog.py").touch()
    (probes / "__init__.py").write_text(
        "from types import SimpleNamespace as S\n"
        f"CATALOG = (S(id='root', argv={argv!r}, devices='', unprivileged=False),\n"
        f"           S(id='nobody', argv={argv!r}, devices='', unprivileged=True))\n")
    for name in [m for m in sys.modules if m == "neonwatch" or m.startswith("neonwatch.")]:
        monkeypatch.delitem(sys.modules, name)
    assert gates.check_catalog(tmp_path) == [
        "catalog: root: must run unprivileged (UNPRIVILEGED_ARGV in tools/gates.py), not as root"]


def test_a_catalog_that_will_not_import_is_a_violation_not_a_crash(tmp_path, monkeypatch):
    probes = tmp_path / "neonwatch" / "probes"
    probes.mkdir(parents=True)
    (tmp_path / "neonwatch" / "__init__.py").touch()
    (probes / "catalog.py").touch()
    (probes / "__init__.py").write_text("raise ValueError('a command names its binary by path')\n")
    for name in [m for m in sys.modules if m == "neonwatch" or m.startswith("neonwatch.")]:
        monkeypatch.delitem(sys.modules, name)
    assert gates.check_catalog(tmp_path) == [
        "catalog: the probe catalog cannot be imported: ValueError: a command names its "
        "binary by path"]


def test_main_reports_and_sets_the_exit_code(tmp_path, capsys):
    root = tree(tmp_path, {"neonwatch/lonely.py": ""}, [component("lonely", "neonwatch/lonely.py")])
    assert gates.main(root) == 1
    assert "gates: 1 violation(s)" in capsys.readouterr().out

    clean = tree(tmp_path / "c", {"neonwatch/a.py": "", "neonwatch/a_test.py": ""},
                 [component("a", "neonwatch/a.py")])
    assert gates.main(clean) == 0
    assert "gates: all hold" in capsys.readouterr().out
