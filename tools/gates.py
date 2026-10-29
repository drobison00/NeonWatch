#!/usr/bin/env python3
"""The repository's mechanical gates. Each rule in docs/design.md that can be a check is one here.

Run: `uv run python tools/gates.py` — exits non-zero with every violation listed.

1. components  — every module has a sibling `<name>_test.py`, and every test has its module.
2. levels      — a neonwatch import (relative ones resolved) follows a dependency edge declared in
                 plan.json, or stays inside its own component. Adding an edge is an edit to the
                 plan, not to code.
3. insulation  — each volatile library is importable only by the component that owns it, and a
                 process started without importing `subprocess` (asyncio's subprocess API) is
                 held to `subprocess`'s owners all the same.
4. read-only   — an ALLOWLIST over the code that runs as root: each privileged component imports
                 only the modules listed for it, uses only the listed attributes of the modules
                 that can write, spawn, signal or connect, opens files read-only by literal, and
                 creates a process or signals a group at exactly one reviewed call site each.
                 What the gate cannot resolve statically (dynamic imports, getattr on a module
                 or by a computed name, exec, a module reached through another module's
                 attributes) is refused rather than guessed at.
5. catalog     — every command in the catalog is, verbatim, one of the reviewed argvs below, and
                 one reviewed as needing no privilege is marked to run without it.

The allowlists were written from the code as it stood on 2026-09-30. Adding a module, an
attribute or an argv is a reviewed edit to this file; the gate never infers that something new is
safe.
"""

from __future__ import annotations

import ast
import json
import posixpath
import re
import sys
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "neonwatch"

#: library (top-level import name) -> components allowed to import it.
INSULATED: dict[str, frozenset[str]] = {
    "nats": frozenset({"bus"}),
    "sqlite3": frozenset({"store"}),
    "aiohttp": frozenset({"web"}),
    # `logs` runs one fixed journalctl argv as the unprivileged service (reviewed 2026-10-27).
    "subprocess": frozenset({"executor", "broker", "notifier", "logs"}),
    "socket": frozenset({"executor"}),
    # The network halves only: `urllib.parse` and `http.HTTPStatus` touch nothing and are free.
    # `mcp` reaches the dashboard's agent API on loopback (reviewed 2026-10-27).
    "http.client": frozenset({"executor", "judge", "analyst", "mcp"}),
    "http.server": frozenset(),
    "urllib.request": frozenset({"judge", "analyst"}),
}


#: Ways to start a process without importing `subprocess`, held to `subprocess`'s owners: dotted
#: prefixes of a name an import or attribute chain reaches, and method names called on anything.
SPAWNERS = ("asyncio.create_subprocess_", "asyncio.subprocess")
SPAWN_METHODS = frozenset({"subprocess_exec", "subprocess_shell"})


def spawns(tree: ast.AST) -> Iterable[tuple[str, int]]:
    """(what starts a process, line) for each use of asyncio's subprocess API, once per line."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "asyncio":
                    aliases[alias.asname or "asyncio"] = alias.name if alias.asname else "asyncio"
        elif isinstance(node, ast.ImportFrom) and node.module == "asyncio" and not node.level:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"asyncio.{alias.name}"
    seen: set[int] = set()
    for node in ast.walk(tree):
        found = ""
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [
                f"{node.module}.{alias.name}" for alias in node.names if not node.level]
            found = next((name for name in names if name.startswith(SPAWNERS)), "")
        elif isinstance(node, ast.Attribute) and node.attr in SPAWN_METHODS:
            found = f".{node.attr}()"
        elif isinstance(node, ast.Name | ast.Attribute):
            name = dotted(node)
            head = name.split(".")[0]
            if head in aliases:
                full = aliases[head] + name[len(head):]
                if full.startswith(SPAWNERS):
                    found = full
        if found and node.lineno not in seen:
            seen.add(node.lineno)
            yield found, node.lineno


def insulated(name: str) -> str | None:
    """The insulated library an import name falls under, matched by dotted prefix."""
    for library in INSULATED:
        if name == library or name.startswith(library + "."):
            return library
    return None


# --- what runs as root -------------------------------------------------------------------------

#: The components whose code runs as root. `bus` is how the agent publishes; `launcher` is the
#: agent's entry point; `neonwatch` is the package root, `neonwatch/__init__.py`, which every import
#: of the package executes first.
PRIVILEGED = frozenset({"collector", "executor", "probes", "redact", "schema", "config", "bus",
                        "launcher", PACKAGE})

#: The launcher's functions that run as the agent. Outside them the launcher may import a
#: non-privileged component lazily (the service); inside them, and at module level, it may not.
AGENT_PATH = frozenset({"_agent", "_run_agent"})

_FUTURE = "__future__"
#: component -> every module outside neonwatch it may import, exactly as the import names it.
#: neonwatch imports are held by `levels`, and here by "privileged code imports only privileged".
ALLOWED_IMPORTS: dict[str, frozenset[str]] = {
    "collector": frozenset({_FUTURE, "asyncio", "collections", "collections.abc", "contextlib",
                            "dataclasses", "functools", "hashlib", "logging", "math", "os",
                            "pathlib", "random", "re", "time", "typing"}),
    "executor": frozenset({_FUTURE, "collections.abc", "dataclasses", "errno", "fnmatch", "glob",
                           "http.client", "math", "os", "re", "resource", "selectors", "signal",
                           "socket", "stat", "subprocess", "threading", "time"}),
    "probes": frozenset({_FUTURE, "base64", "binascii", "collections", "collections.abc",
                         "dataclasses", "enum", "hashlib", "ipaddress", "json", "posixpath", "re",
                         "typing"}),
    "redact": frozenset({_FUTURE, "collections.abc", "re", "typing"}),
    "schema": frozenset({_FUTURE, "collections.abc", "dataclasses", "enum", "json", "types",
                         "typing"}),
    "config": frozenset({_FUTURE, "dataclasses", "ipaddress", "os", "pathlib", "re", "stat",
                         "tomllib", "typing", "urllib.parse"}),
    # bus reads its creds file safely as root; `stat` names the file type (reviewed 2026-09-30).
    "bus": frozenset({_FUTURE, "asyncio", "collections", "collections.abc", "contextlib", "json",
                      "logging", "nats", "nats.errors", "nats.js.api", "nats.js.errors", "os",
                      "pathlib", "re", "stat"}),
    "launcher": frozenset({_FUTURE, "argparse", "asyncio", "collections.abc", "dataclasses",
                           "enum", "logging", "os", "pathlib", "pwd", "signal", "sys", "time",
                           "typing"}),
    PACKAGE: frozenset(),
}

#: Modules with a surface that writes, spawns, signals, connects or changes the host: privileged
#: code may use only these attributes of them, and may not hold the module itself. Every other
#: module on an import allowlist above is pure computation or a read.
RESTRICTED: dict[str, frozenset[str]] = {
    "os": frozenset({"O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK", "O_RDONLY",
                     "ST_RDONLY", "WNOHANG", "W_OK", "access", "close", "environ", "fdopen",
                     "fstat", "getpgid", "getuid", "listdir", "lstat", "open", "path", "read",
                     "readlink", "set_blocking", "stat", "statvfs", "wait4",
                     "waitstatus_to_exitcode"}),
    "sys": frozenset({"argv", "dont_write_bytecode", "exit", "flags", "stderr"}),
    "time": frozenset({"monotonic", "process_time", "sleep", "thread_time_ns", "time"}),
    "signal": frozenset({"SIGINT", "SIGKILL", "SIGTERM"}),
    "socket": frozenset({"AF_UNIX", "SOCK_STREAM", "socket"}),
    "subprocess": frozenset({"DEVNULL", "PIPE"}),
    "asyncio": frozenset({"Event", "Lock", "Semaphore", "create_task", "ensure_future", "gather",
                          "get_running_loop", "run", "shield", "to_thread", "wait_for"}),
    "logging": frozenset({"INFO", "basicConfig", "getLogger"}),
    "resource": frozenset({"struct_rusage"}),
    "argparse": frozenset({"ArgumentParser"}),
    "http.client": frozenset({"HTTPConnection", "HTTPException"}),
    # Imported by no privileged code, but reachable as an attribute of modules that are:
    # `logging.io`, `socket.io`, `enum.bltns` (2026-10-27). Nothing of either is needed.
    "io": frozenset(),
    "builtins": frozenset(),
}
#: Public names under which an allowlisted module re-exports a RESTRICTED one, other than the
#: module's own name: `enum.bltns` is builtins (found by walking the allowlisted modules).
MODULE_ALIASES = {"bltns": "builtins"}

#: The only call sites allowed to create a process or signal a process group, and how each is
#: pinned: call -> (component, TOP-LEVEL function, attribute of that function's first parameter
#: that must be the call's first argument, what the call does). Exactly one such call per site.
#: `executor._kill_own_group` may `os.killpg` the group of a probe it spawned itself
#: (start_new_session, so the group id is the child's pid), and only after checking that; a
#: timed-out probe's grandchildren would otherwise run on as unsupervised root processes.
SITES: dict[str, tuple[str, str, str, str]] = {
    "subprocess.Popen": ("executor", "_command", "argv", "creates a process"),
    "os.killpg": ("executor", "_kill_own_group", "pid", "calls os.killpg"),
}
#: Keywords that would let the approved call run something other than its first argument.
SITE_REFUSED_KEYWORDS = frozenset({"shell", "executable", "preexec_fn"})

#: Names that create a process, refused wherever they appear (prefix match on the dotted name).
PROCESS = ("subprocess.", "asyncio.create_subprocess_", "asyncio.subprocess", "os.exec",
           "os.spawn", "os.posix_spawn", "os.fork", "os.system", "os.popen", "pty.",
           "multiprocessing")
#: Names that create a socket; only the executor may.
SOCKET_CREATORS = frozenset({"socket.socket", "socket.create_connection", "socket.socketpair",
                             "socket.fromfd", "socket.create_server", "asyncio.open_connection",
                             "asyncio.open_unix_connection", "asyncio.start_server",
                             "asyncio.start_unix_server"})

#: Built-ins that reach code or modules the gate cannot see.
REFUSED_BUILTINS = frozenset({"exec", "eval", "compile", "__import__", "globals", "locals",
                              "vars", "__builtins__"})
#: The only dunder attributes privileged code may touch.
DUNDERS = frozenset({"__name__", "__init__"})
#: The only attributes of an imported module privileged code may assign.
ASSIGNABLE = frozenset({"sys.dont_write_bytecode"})

#: File opens: callable -> index of its positional mode argument. Any other `.open(...)` is taken
#: to be `Path.open`, whose mode is its FIRST positional argument.
OPENERS = {"open": 1, "io.open": 1, "builtins.open": 1, "os.fdopen": 1, "pathlib.Path.open": 1}
READ_MODES = frozenset({"r", "rb", "rt"})
READ_FLAGS = ("O_RDONLY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "O_DIRECTORY")

#: Methods refused by name, since the receiver's type is not known statically.
WRITE_METHODS = frozenset({
    "write_text", "write_bytes", "unlink", "mkdir", "touch", "rename", "replace", "rmdir",
    "symlink_to", "hardlink_to", "link_to", "chmod", "lchmod",
})
SEND_METHODS = frozenset({"send", "sendall", "sendto", "sendmsg", "sendfile", "makefile"})
PROCESS_METHODS = frozenset({"subprocess_exec", "subprocess_shell"})
SOCKET_METHODS = frozenset({"create_connection", "create_unix_connection",
                            "create_datagram_endpoint", "create_server", "create_unix_server",
                            "sock_connect"})
HTTP_METHODS = frozenset({"request", "putrequest"})
#: Every method judged where it is called, so it may not be taken as a value anywhere else.
CHECKED_METHODS = (WRITE_METHODS | SEND_METHODS | PROCESS_METHODS | SOCKET_METHODS
                   | HTTP_METHODS | {"open"})
#: Module functions whose names collide with a writing method and write nothing.
PURE_FUNCTIONS = frozenset({"dataclasses.replace", "copy.replace"})

NON_GET = ("POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE")
_REQUEST_LINE = re.compile(rf"({'|'.join(NON_GET)})\s")


# --- the tree ----------------------------------------------------------------------------------


def modules(root: Path) -> list[Path]:
    return sorted(p for p in (root / PACKAGE).rglob("*.py")
                  if not p.name.endswith("_test.py") and p.name != "__init__.py")


def inits(root: Path) -> list[Path]:
    return sorted((root / PACKAGE).rglob("__init__.py"))


def tests(root: Path) -> list[Path]:
    return sorted((root / PACKAGE).rglob("*_test.py"))


def check_components(root: Path) -> list[str]:
    found = []
    for module in modules(root):
        if not module.with_name(module.stem + "_test.py").exists():
            found.append(f"components: {module.relative_to(root)} has no sibling test")
    for test in tests(root):
        stem = test.name[: -len("_test.py")]
        sibling = test.with_name(stem + ".py")
        package = test.parent / stem / "__init__.py"
        if not sibling.exists() and not package.exists() and stem != "__init__":
            found.append(f"components: {test.relative_to(root)} tests a module that does not exist")
    return found


def load_plan(root: Path) -> tuple[dict[str, str], set[tuple[str, str]]]:
    """file path -> component, and the declared edges."""
    plan = json.loads((root / "plan.json").read_text())
    owner = {}
    for component in plan["components"]:
        for file in component["files"]:
            owner[file] = component["name"]
    edges = {(e["component"], e["depends_on"]) for e in plan["dependency_edges"]}
    return owner, edges


def component_of(path: str, owner: dict[str, str]) -> str | None:
    if path in owner:
        return owner[path]
    if path == f"{PACKAGE}/__init__.py":
        return PACKAGE
    # A package component owns its directory: neonwatch/probes/*.py belong to probes.
    for file, name in owner.items():
        if file.endswith("/__init__.py") and path.startswith(file[: -len("__init__.py")]):
            return name
    return None


def module_file(dotted: str, root: Path) -> str | None:
    parts = dotted.split(".")
    for end in range(len(parts), 0, -1):
        base = root.joinpath(*parts[:end])
        for candidate in (base.with_suffix(".py"), base / "__init__.py"):
            if candidate.exists():
                return str(candidate.relative_to(root))
    return None


def target_of(name: str, root: Path, owner: dict[str, str]) -> str | None:
    """The component a neonwatch import lands in. The package root owns no importable name, so
    `neonwatch.nowhere` falling back to `neonwatch/__init__.py` lands nowhere."""
    target_file = module_file(name, root)
    if target_file is None or target_file == f"{PACKAGE}/__init__.py":
        return None
    return component_of(target_file, owner)


def package_of(rel: str) -> str:
    """The dotted package a file's relative imports start from."""
    return ".".join(Path(rel).with_suffix("").parts[:-1])


def imports(tree: ast.AST, package: str = "") -> Iterable[tuple[str, int]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                # `from . import x` in neonwatch/a.py is neonwatch.x; each extra dot climbs one.
                parts = package.split(".")
                parts = parts[: len(parts) - node.level + 1]
                base = ".".join(parts + ([node.module] if node.module else []))
            # `from neonwatch import low` imports neonwatch.low when that is a module; the longest
            # existing prefix decides, so a plain name falls back to the module itself.
            for alias in node.names:
                yield f"{base}.{alias.name}", node.lineno


def check_levels_and_insulation(root: Path) -> list[str]:
    owner, edges = load_plan(root)
    found = []
    for path in modules(root) + inits(root) + tests(root):
        rel = str(path.relative_to(root))
        is_test = path.name.endswith("_test.py")
        me = component_of(rel if not is_test else rel.replace("_test.py", ".py"), owner)
        if me is None:
            found.append(f"levels: {rel} belongs to no component in plan.json")
            continue
        tree = ast.parse(path.read_text(), filename=rel)
        for name, line in imports(tree, package_of(rel)):
            top = name.split(".")[0]
            if top == PACKAGE:
                target = target_of(name, root, owner)
                if target is None:
                    found.append(f"levels: {rel}:{line} imports {name}, which no component owns")
                elif target != me and (me, target) not in edges:
                    found.append(f"levels: {rel}:{line} imports {target} but plan.json declares "
                                 f"no edge {me} -> {target}")
            elif ((library := insulated(name)) and me not in INSULATED[library]
                    and not is_test):
                owners = ", ".join(sorted(INSULATED[library])) or "no component"
                found.append(f"insulation: {rel}:{line} imports {library}, owned by {owners}")
        if not is_test and me not in INSULATED["subprocess"]:
            owners = ", ".join(sorted(INSULATED["subprocess"]))
            for name, line in sorted(spawns(tree), key=lambda item: item[1]):
                found.append(f"insulation: {rel}:{line} starts a process ({name}), which only "
                             f"subprocess's owners may: {owners}")
    return found


# --- read-only ---------------------------------------------------------------------------------


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    return ""


def _chain_head(node: ast.AST) -> ast.Name | None:
    while isinstance(node, ast.Attribute):
        node = node.value
    return node if isinstance(node, ast.Name) else None


def _literal(node: ast.AST) -> str | None:
    """A str or bytes literal's text, folding `+` of literals and placeholder-free f-strings."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
        value = node.value
        return value.decode("latin-1") if isinstance(value, bytes) else value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal(node.left), _literal(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = [_literal(value) for value in node.values]
        return None if None in parts else "".join(parts)  # type: ignore[arg-type]
    return None


def _http_method(text: str) -> str:
    """The non-GET HTTP method a literal names, as a whole word or a request line, or `""`.

    Methods are case-sensitive (RFC 9110), so only the uppercase names count: a data key such as
    `"options"` is not one. The request path is held separately: `.request`/`.putrequest` must
    pass a literal "GET".
    """
    if text.strip() in NON_GET:
        return text.strip()
    request = _REQUEST_LINE.match(text)
    return request.group(1) if request else ""


def _unpacked(call: ast.Call) -> bool:
    return (any(isinstance(arg, ast.Starred) for arg in call.args)
            or any(keyword.arg is None for keyword in call.keywords))


def _argument(call: ast.Call, index: int, keyword: str) -> ast.AST | None:
    for given in call.keywords:
        if given.arg == keyword:
            return given.value
    return call.args[index] if len(call.args) > index else None


def _own_calls(function: ast.AST) -> list[ast.Call]:
    """The calls in a function's own body, not in a function, lambda or class nested in it."""
    calls, todo = [], list(ast.iter_child_nodes(function))
    while todo:
        node = todo.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
            continue
        if isinstance(node, ast.Call):
            calls.append(node)
        todo.extend(ast.iter_child_nodes(node))
    return sorted(calls, key=lambda call: (call.lineno, call.col_offset))


def _annotations(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.arg | ast.AnnAssign) and node.annotation:
        return [node.annotation]
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.returns:
        return [node.returns]
    return []


class _Privileged:
    """One privileged module, scanned against the allowlists."""

    def __init__(self, tree: ast.Module, component: str, root: Path, owner: dict[str, str]):
        self.tree, self.me, self.root, self.owner = tree, component, root, owner
        self.found: list[tuple[int, str]] = []
        self.parent: dict[int, ast.AST] = {
            id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        #: local name -> the dotted name an import bound it to, wherever in the module it is.
        self.aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.aliases[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        #: Annotations are names, not uses; a call inside one is refused outright.
        self.annotation: set[int] = set()
        for node in ast.walk(tree):
            for note in _annotations(node):
                if any(isinstance(inner, ast.Call) for inner in ast.walk(note)):
                    self.refuse(note, "calls inside an annotation")
                self.annotation.update(id(inner) for inner in ast.walk(note))
        self.approved = self._approved_sites()

    def refuse(self, node: ast.AST, why: str) -> None:
        self.found.append((getattr(node, "lineno", 0), why))

    def resolve(self, node: ast.AST) -> tuple[str, bool]:
        """(the dotted name `node` means, whether its head was bound by an import)."""
        head = _chain_head(node)
        if head is None:
            return "", False
        name = dotted(node)
        if head.id in self.aliases:
            return self.aliases[head.id] + name[len(head.id):], True
        return name, False

    def _approved_sites(self) -> set[int]:
        """Ids of the `func` nodes of the (at most one per site) approved calls in this module."""
        approved: set[int] = set()
        for function in self.tree.body:
            if not isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            params = function.args.posonlyargs + function.args.args
            for call_name, (component, name, attribute, _) in SITES.items():
                if component != self.me or function.name != name or not params:
                    continue
                for call in _own_calls(function):
                    first = call.args[0] if call.args else None
                    if (self.resolve(call.func) == (call_name, True) and not _unpacked(call)
                            and isinstance(first, ast.Attribute) and first.attr == attribute
                            and isinstance(first.value, ast.Name)
                            and first.value.id == params[0].arg
                            and not any(k.arg in SITE_REFUSED_KEYWORDS for k in call.keywords)):
                        approved.add(id(call.func))
                        break
        return approved

    def scan(self) -> list[tuple[int, str]]:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                self._import(node)
            elif isinstance(node, ast.Call):
                self._call(node)
            if isinstance(node, ast.Name | ast.Attribute) and id(node) not in self.annotation:
                self._reference(node)
            if isinstance(node, ast.Constant | ast.BinOp | ast.JoinedStr):
                text = _literal(node)
                if text is not None and (method := _http_method(text)):
                    self.refuse(node, f"names HTTP method {method}")
        return self.found

    # imports

    def _import(self, node: ast.Import | ast.ImportFrom) -> None:
        if isinstance(node, ast.ImportFrom) and node.level:
            self.refuse(node, "uses a relative import")
            return
        if isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                self.refuse(node, "uses a star import")
            names = [node.module or ""]
            if names[0].split(".")[0] == PACKAGE:
                names = [f"{node.module}.{alias.name}" for alias in node.names]
        else:
            names = [alias.name for alias in node.names]
        for name in names:
            if name.split(".")[0] == PACKAGE:
                self._import_neonwatch(node, name)
            elif name.split(".")[0] == "importlib":
                self.refuse(node, "imports dynamically: importlib")
            elif name not in ALLOWED_IMPORTS[self.me]:
                self.refuse(node, f"imports {name}, which is not on {self.me}'s import allowlist")

    def _import_neonwatch(self, node: ast.AST, name: str) -> None:
        target = target_of(name, self.root, self.owner)
        if target is None or target in PRIVILEGED:
            return  # an unowned target is the levels gate's finding
        why = f"imports {target}, which does not run as root"
        if self.me != "launcher":
            self.refuse(node, why)
            return
        function = self._top_level_function(node)
        if function is None:
            self.refuse(node, f"{why}, at module level")
        elif function in AGENT_PATH:
            self.refuse(node, f"{why}, on the agent path ({function})")

    def _top_level_function(self, node: ast.AST) -> str | None:
        name = None
        while id(node) in self.parent:
            node = self.parent[id(node)]
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                name = node.name
        return name

    # names and attributes

    def _is_called(self, node: ast.AST) -> bool:
        parent = self.parent.get(id(node))
        return isinstance(parent, ast.Call) and parent.func is node

    def _reference(self, node: ast.Name | ast.Attribute) -> None:
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("__") and node.attr.endswith("__") and node.attr not in DUNDERS:
                self.refuse(node, f"uses {node.attr}, which reaches past the allowlist")
            if node.attr in CHECKED_METHODS and not self._is_called(node):
                self.refuse(node, f"refers to {dotted(node)} without calling it")
            if isinstance(node.ctx, ast.Store | ast.Del):
                name, imported = self.resolve(node)
                if imported and name not in ASSIGNABLE:
                    self.refuse(node, f"assigns to {dotted(node)}, an attribute of an imported "
                                      f"module")
        elif node.id not in self.aliases:
            if node.id in REFUSED_BUILTINS:
                self.refuse(node, f"uses {node.id}")
            elif node.id == "open" and not self._is_called(node):
                self.refuse(node, "refers to open without calling it")
        parent = self.parent.get(id(node))
        if isinstance(parent, ast.Attribute) and parent.value is node:
            return  # only the whole chain `a.b.c` is judged, not its prefixes
        name, imported = self.resolve(node)
        if imported:
            self._imported_name(node, name)
            self._reached_through(node, name)

    def _reached_through(self, node: ast.AST, name: str) -> None:
        """Judge what an imported chain reaches past its head, whatever the head was.

        Modules hold other modules as attributes (`os.path.os`, `pathlib.os`, `random._os`), so
        `os.path.os.system` is `os.system` reached by another name. Every tail of the chain is
        judged as if it had been imported, a module itself reached that way is refused unless it
        is an allowlisted attribute of the module before it (`time.time`, `socket.socket`), and a
        private name is refused outright: that is where re-exports hide (`threading._os`).
        """
        parts = name.split(".")
        for start in range(1, len(parts)):
            part = parts[start]
            if part.startswith("_") and not (part.startswith("__") and part.endswith("__")):
                self.refuse(node, f"uses {part} of {'.'.join(parts[:start])}, a private name")
                return
            tail = ".".join([MODULE_ALIASES.get(part, part), *parts[start + 1:]])
            if start < len(parts) - 1:
                before = len(self.found)
                self._imported_name(node, tail)
                if len(self.found) > before:
                    self.found[before:] = [(line, f"{why} (reached as {name})")
                                           for line, why in self.found[before:]]
                    return
            elif tail in RESTRICTED and part not in RESTRICTED.get(".".join(parts[:start]), ()):
                self.refuse(node, f"reaches the module {tail} as {name}")

    def _imported_name(self, node: ast.AST, name: str) -> None:
        if name in SITES:
            component, function, attribute, verb = SITES[name]
            if id(node) not in self.approved:
                self.refuse(node, f"{verb} outside {component}.{function}, its one approved "
                                  f"site, on its first parameter's .{attribute}")
            return
        module = next((m for m in sorted(RESTRICTED, key=len, reverse=True)
                       if name == m or name.startswith(m + ".")), None)
        attribute = name[len(module) + 1:].split(".")[0] if module else ""
        if module and attribute in RESTRICTED[module]:
            if name in SOCKET_CREATORS and self.me != "executor":
                self.refuse(node, f"creates a socket: {name}")
        elif name.startswith(PROCESS):
            self.refuse(node, f"creates a process: {name}")
        elif name in SOCKET_CREATORS and self.me != "executor":
            self.refuse(node, f"creates a socket: {name}")
        elif module and not attribute:
            self.refuse(node, f"refers to the module {module} itself")
        elif module:
            self.refuse(node, f"uses {name}, which is not on the {module} allowlist")

    # calls

    def _call(self, call: ast.Call) -> None:
        name, imported = self.resolve(call.func)
        attr = call.func.attr if isinstance(call.func, ast.Attribute) else ""
        if not imported and name in {"getattr", "setattr", "delattr"}:
            self._by_name(call, name)
        builtin_open = name == "open" and not imported
        if name == "os.open" and imported:
            self._os_open(call)
        elif (imported and name in OPENERS) or builtin_open:
            self._open_mode(call, OPENERS[name])
        elif attr == "open":
            self._open_mode(call, 0)
        if attr in WRITE_METHODS and name not in PURE_FUNCTIONS and not _two_arg(call, attr):
            self.refuse(call, f"calls .{attr}(), which writes")
        if attr in SEND_METHODS:
            self.refuse(call, f"calls .{attr}(), which writes to a socket")
        if attr in PROCESS_METHODS:
            self.refuse(call, f"creates a process: .{attr}()")
        if attr in SOCKET_METHODS and self.me != "executor":
            self.refuse(call, f"creates a socket: .{attr}()")
        if attr in HTTP_METHODS:
            method = _argument(call, 0, "method")
            if not (isinstance(method, ast.Constant) and method.value == "GET"):
                self.refuse(call, "sends an HTTP method that is not a literal 'GET'")
        if name == "logging.basicConfig" and any(k.arg == "filename" for k in call.keywords):
            self.refuse(call, "logs to a file")
        for keyword in call.keywords:
            if (keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True):
                self.refuse(call, "passes shell=True")

    def _by_name(self, call: ast.Call, name: str) -> None:
        """getattr and friends: the name must be spelled out, and must be one a plain reference
        could make. A computed name (`"write" + suffix`) is what the name-based checks cannot
        see, so it is refused, except a dataclass field read (`_field_read`)."""
        if call.args and self.resolve(call.args[0])[1]:
            self.refuse(call, f"calls {name} on the module {dotted(call.args[0])}")
        if _unpacked(call) or len(call.args) < 2:
            self.refuse(call, f"calls {name} without spelling out the name")
            return
        attribute = _literal(call.args[1])
        if attribute is None:
            if not (name == "getattr" and self._field_read(call)):
                self.refuse(call, f"calls {name} with a name it does not spell out")
        elif attribute in CHECKED_METHODS:
            self.refuse(call, f"calls {name} for .{attribute}, which is judged only where called")
        elif (attribute.startswith("__") and attribute.endswith("__")
              and attribute not in DUNDERS):
            self.refuse(call, f"calls {name} for {attribute}, which reaches past the allowlist")

    def _field_read(self, call: ast.Call) -> bool:
        """`getattr(x, f.name)` inside a comprehension `for f in dataclasses.fields(x)`.

        That reads only `x`'s own fields, so the name needs no spelling out. A comprehension
        and no walrus, so neither name can be rebound between the loop and the read.
        """
        target, field = call.args[0], call.args[1]
        if (len(call.args) != 2 or call.keywords or not isinstance(target, ast.Name)
                or not isinstance(field, ast.Attribute) or field.attr != "name"
                or not isinstance(field.value, ast.Name)):
            return False
        node: ast.AST = call
        while id(node) in self.parent:
            node = self.parent[id(node)]
            if not isinstance(node, ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp):
                continue
            if any(isinstance(inner, ast.NamedExpr) for inner in ast.walk(node)):
                return False
            for loop in node.generators:
                source = loop.iter
                if (isinstance(loop.target, ast.Name) and loop.target.id == field.value.id
                        and isinstance(source, ast.Call) and not source.keywords
                        and self.resolve(source.func) == ("dataclasses.fields", True)
                        and len(source.args) == 1 and isinstance(source.args[0], ast.Name)
                        and source.args[0].id == target.id):
                    return True
        return False

    def _open_mode(self, call: ast.Call, index: int) -> None:
        if _unpacked(call):
            self.refuse(call, "passes unpacked arguments to open")
            return
        mode = _argument(call, index, "mode")
        if mode is None:
            return
        if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)):
            self.refuse(call, "opens a file with a non-literal mode")
        elif mode.value not in READ_MODES:
            self.refuse(call, f"opens a file in mode {mode.value!r}")

    def _os_open(self, call: ast.Call) -> None:
        if _unpacked(call):
            self.refuse(call, "passes unpacked arguments to os.open")
            return
        flags = _argument(call, 1, "flags")
        if flags is None:
            self.refuse(call, "calls os.open without flags")
        elif not self._read_flags(flags):
            self.refuse(call, "os.open flags are not a literal OR of "
                              + " | ".join(f"os.{flag}" for flag in READ_FLAGS))

    def _read_flags(self, node: ast.AST) -> bool:
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return self._read_flags(node.left) and self._read_flags(node.right)
        name, imported = self.resolve(node)
        return imported and name in {f"os.{flag}" for flag in READ_FLAGS}


def _two_arg(call: ast.Call, attr: str) -> bool:
    """`str.replace(old, new)` takes two arguments; `Path.rename/replace(target)` one."""
    return attr in {"replace", "rename"} and len(call.args) >= 2


def check_read_only(root: Path) -> list[str]:
    owner, _ = load_plan(root)
    found = []
    for path in sorted(modules(root) + inits(root)):
        rel = str(path.relative_to(root))
        me = component_of(rel, owner)
        if me not in PRIVILEGED:
            continue
        scan = _Privileged(ast.parse(path.read_text(), filename=rel), me, root, owner).scan()
        seen: set[tuple[int, str]] = set()
        for line, why in sorted(scan, key=lambda item: item[0]):
            if (line, why) not in seen:
                seen.add((line, why))
                found.append(f"read-only: {rel}:{line} {why}")
    return found


# --- catalog -----------------------------------------------------------------------------------

#: Every command the catalog may run, verbatim, copied from neonwatch/probes/catalog.py on
#: 2026-09-30 (systemctl list-timers --all and show added 2026-10-12, apt-get -s 2026-10-28).
#: Adding or changing one is a reviewed edit HERE: read the binary's man page for
#: every word, because a flag that looks like a read can write a file (`nvidia-smi -f`,
#: `journalctl --cursor-file`, `ss -D`) or change state (`sensors -s`, `smartctl -s`).
APPROVED_ARGV: frozenset[tuple[str, ...]] = frozenset({
    ("/usr/bin/sensors", "-j"),
    ("/usr/bin/nvidia-smi", "--query-gpu",
     "index,name,temperature.gpu,power.draw,power.limit,memory.used,memory.total,"
     "utilization.gpu,clocks_event_reasons.active,pcie.link.width.current,pcie.link.width.max",
     "--format=csv,noheader,nounits"),
    ("/usr/bin/df", "-l", "-B1", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs", "-x",
     "devtmpfs", "--output=source,fstype,size,used,avail,itotal,iused,target"),
    # Reviewed 2026-10-27: `pidns` is a column like the rest; ps reads /proc/<pid>/ns/pid with
    # readlink, which changes nothing.
    ("/usr/bin/ps", "-e", "-o",
     "pid=,ppid=,user:32=,stat=,pcpu=,rss=,etimes=,nlwp=,times=,pidns=,comm:15=,args="),
    ("/usr/bin/systemctl", "list-units", "--failed", "-o", "json", "--no-pager"),
    ("/usr/bin/journalctl", "-q", "-p", "warning", "-o", "json",
     "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_TRANSPORT", "--no-pager",
     "-n", "500", "--since", "-6min"),
    ("/usr/bin/journalctl", "-q", "-p", "err", "-o", "json",
     "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_TRANSPORT", "--no-pager",
     "-n", "200", "--since", "-6min"),
    ("/usr/bin/ss", "-ltnupH"),
    ("/usr/sbin/nft", "-j", "list", "ruleset"),
    ("/usr/bin/systemctl", "list-unit-files", "-o", "json", "--no-pager"),
    # --all: inactive timers too. Reviewed 2026-10-12: list-timers only reads.
    ("/usr/bin/systemctl", "list-timers", "--all", "-o", "json", "--no-pager"),
    # Reviewed 2026-10-12. `show` reads properties over D-Bus; -p names them, --timestamp
    # formats them, --all includes loaded units that are inactive (a timer's service between
    # runs). The unit arguments are PATTERNS on purpose: a pattern matches loaded units only,
    # while a unit named explicitly is loaded by PID 1 to answer, which is a (transient) change
    # the agent may not cause; measured, the loaded-unit count is the same before and after.
    # No shell: systemctl expands the patterns itself.
    ("/usr/bin/systemctl", "show", "--all", "-p",
     "Id,Description,User,ExecStart,ActiveState,SubState,Result,NRestarts,ExecMainStatus,"
     "ExecMainStartTimestamp,ExecMainExitTimestamp,UnitFileState,FragmentPath,Triggers,"
     "TriggeredBy,TimersCalendar,TimersMonotonic,Unit",
     "--timestamp=unix", "--no-pager", "*.service", "*.timer"),
    # Reviewed 2026-10-28. -s (--simulate) "perform a simulation of events that would occur
    # ... but do not actually change the system"; locking is disabled, and a non-root user may
    # run it. dist-upgrade is only what is simulated. Run unprivileged, below.
    ("/usr/bin/apt-get", "-s", "dist-upgrade"),
})
#: Reviewed argvs that must run `unprivileged`: as root each changes the host even though it
#: only reads. nvidia-smi unlinks and recreates /dev/char/195:* on every run (2026-10-27); its
#: device nodes are 0666, so as nobody it reads the same and changes nothing.
UNPRIVILEGED_ARGV: frozenset[tuple[str, ...]] = frozenset({
    ("/usr/bin/nvidia-smi", "--query-gpu",
     "index,name,temperature.gpu,power.draw,power.limit,memory.used,memory.total,"
     "utilization.gpu,clocks_event_reasons.active,pcie.link.width.current,pcie.link.width.max",
     "--format=csv,noheader,nounits"),
    # As root apt may rebuild /var/cache/apt/*.bin when the lists are newer; as nobody it
    # cannot, and simulates from memory.
    ("/usr/bin/apt-get", "-s", "dist-upgrade"),
})
#: Templates: the argv with `{device}` in its reviewed position -> the devices regex that may
#: fill it. Both are reviewed; a template is admitted only as the pair.
APPROVED_TEMPLATES: dict[tuple[str, ...], str] = {
    ("/usr/sbin/smartctl", "-j", "-a", "/dev/{device}"): r"nvme\d+n\d+|sd[a-z]+",
}
#: Root-owned binary directories. A binary anywhere else could be replaced by its owner.
BINARY_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")


def argv_is_read_only(argv: tuple[str, ...], devices: str = "") -> str:
    """Why this argv is not a reviewed catalog invocation, or `""`."""
    if not argv:
        return "empty argv"
    binary = argv[0]
    if posixpath.dirname(binary) not in BINARY_DIRS or posixpath.normpath(binary) != binary:
        return f"{binary} is not an absolute path in {', '.join(BINARY_DIRS)}"
    if devices:
        if APPROVED_TEMPLATES.get(argv) != devices:
            return (f"{' '.join(argv)} with devices {devices!r} is not a reviewed template "
                    f"(APPROVED_TEMPLATES in tools/gates.py)")
        return ""
    if argv not in APPROVED_ARGV:
        return f"{' '.join(argv)} is not a reviewed argv (APPROVED_ARGV in tools/gates.py)"
    return ""


def check_catalog(root: Path) -> list[str]:
    if not (root / PACKAGE / "probes" / "catalog.py").exists():
        return []
    sys.path.insert(0, str(root))
    try:
        from neonwatch.probes import CATALOG  # imported only once the catalog exists
    except Exception as broken:
        # Reported, not raised: a crash would hide every other gate's findings in the same run.
        return [f"catalog: the probe catalog cannot be imported: {type(broken).__name__}: {broken}"]
    finally:
        sys.path.pop(0)
    found = []
    for spec in CATALOG:
        if spec.argv and (why := argv_is_read_only(tuple(spec.argv), spec.devices)):
            found.append(f"catalog: {spec.id}: {why}")
        elif tuple(spec.argv) in UNPRIVILEGED_ARGV and spec.unprivileged is not True:
            found.append(f"catalog: {spec.id}: must run unprivileged (UNPRIVILEGED_ARGV in "
                         f"tools/gates.py), not as root")
    return found


def run(root: Path = ROOT) -> list[str]:
    return (check_components(root) + check_levels_and_insulation(root)
            + check_read_only(root) + check_catalog(root))


def main(root: Path | None = None) -> int:
    found = run(root or ROOT)
    for line in found:
        print(line)
    print(f"gates: {len(found)} violation(s)" if found else "gates: all hold")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
