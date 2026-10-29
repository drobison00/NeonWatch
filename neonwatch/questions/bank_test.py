"""The bank is data, so these tests are its review: every question askable, every answer read.

Two halves. The first holds every question in every bank to the shape the judge accepts and the
rules the dashboard relies on. The second pins `interpret` at the exact boundaries where an
answer changes what a person is told to do.
"""

from __future__ import annotations

import math
import re
import shlex

import pytest

from neonwatch.questions.answers import (
    AnswerError,
    AnswerKind,
    ChoiceAnswer,
    NoulAnswer,
    ScoreAnswer,
)
from neonwatch.questions.bank import (
    COMPOSITES,
    DOMAINS,
    ENTITIES,
    QUIET,
    ContextKind,
    Meaning,
    Option,
    Outcome,
    Question,
    QuestionError,
    Reading,
    bank_for,
    interpret,
    needs_present,
    needs_values,
    refuse_mutating,
)
from neonwatch.schema import Severity

INFO, WATCH, WARN, CRITICAL = Severity.INFO, Severity.WATCH, Severity.WARN, Severity.CRITICAL

#: Mirrors `config.JudgeServer.max_questions_per_request`'s default. A test here may not import
#: config (plan.json gives `questions` no edge to it), so the number is restated and named.
MAX_QUESTIONS_PER_REQUEST = 24
#: Question text per request, in characters. The model's context is 16K tokens and the judge
#: gives state up to 24,000 characters of it; this keeps a whole bank to roughly a quarter.
QUESTION_TEXT_BUDGET = 16_000
#: A dynamic choice's options come from the context: up to six members, each summarised.
MEMBER_ALLOWANCE = 6 * 300

ALL = [(kind, q) for kind in ContextKind for q in bank_for(kind)]
ids = [f"{kind.value}.{q.id}" for kind, q in ALL]


def steps(question: Question) -> list[str]:
    return [o.next_step for o in question.meaning.outcomes]


MEMBERS = tuple(Option(f"m{i}", f"member {i}: a finding with its evidence") for i in range(1, 5))


def askable(question: Question) -> Question:
    """The question as the judge would send it: a dynamic choice filled with sample members."""
    return question.fill(MEMBERS) if question.dynamic_options else question


# --- an independent refusal list: written here, not imported, so the bank's own check is checked


INDEPENDENT_REFUSALS = [
    r"\brm\b", r"\brmdir\b", r"\bmv\b", r"\bdd\b", r"\bshred\b", r"\btruncate\b",
    r"\bkill(all)?\b", r"\bpkill\b", r"\brestart\b", r"\bstop\b", r"\bstart\b", r"\breload\b",
    r"\benable\b", r"\bdisable\b", r"\bmask\b", r"\bunmask\b", r"\bchmod\b", r"\bchown\b",
    r"\bchgrp\b", r"\bchattr\b", r"\binstall\b", r"\bremove\b", r"\bpurge\b", r"\bupgrade\b",
    r"\bupdate\b", r"\bautoremove\b", r"\bprune\b", r"\bmount\b", r"\bumount\b", r"\bmkfs",
    r"\bmodprobe\b", r"\brmmod\b", r"\binsmod\b", r"\breboot\b", r"\bshutdown\b",
    r"\bpoweroff\b", r"\btee\b", r"\bxargs\b", r"\bsed\b", r"\bdelete\b", r"-delete\b",
    r"-exec\b", r"\bdocker\s+(rm|rmi|stop|kill|restart|start|run|exec|compose\s+(up|down))\b",
    r"\bsmartctl\b.*\s(-t|-s|-X|--test|--smart)\b", r"\bdmesg\b.*\s-(c|C)\b",
    r"\bnvidia-smi\b.*\s(-r|-pm|-pl|--gpu-reset)\b", r">", r"\$\(", r"`", r";", r"&&", r"\|\|",
]


def mutating(step: str) -> list[str]:
    return [pattern for pattern in INDEPENDENT_REFUSALS if re.search(pattern, step, re.I)]


# --- the shape of every bank ----------------------------------------------------------------


def test_the_context_kinds_are_the_domains_and_the_entities():
    assert {k.value for k in DOMAINS} == {
        "hardware", "cpu", "memory", "storage", "gpu", "network", "firewall", "processes",
        "services", "containers", "logs", "security", "kernel"}
    assert {k.value for k in ENTITIES} == {
        "process", "unit", "container", "listener", "disk", "gpu_device", "log_burst", "job"}
    assert {k.value for k in COMPOSITES} == {"correlation"}
    assert set(DOMAINS) | set(ENTITIES) | set(COMPOSITES) == set(ContextKind)
    assert len(DOMAINS) + len(ENTITIES) + len(COMPOSITES) == len(ContextKind)


@pytest.mark.parametrize("kind", list(ContextKind), ids=lambda k: k.value)
def test_every_bank_is_a_real_bank(kind):
    bank = bank_for(kind)
    assert isinstance(bank, tuple) and all(isinstance(q, Question) for q in bank)
    # The floor is 7, not 8: network lost the questions nothing in its state could answer
    # (DNS, link speed, connections, 2026-10-28), and a bank is not padded to a count.
    assert 7 <= len(bank) <= 20, f"{kind.value}: {len(bank)} questions"
    assert len({q.id for q in bank}) == len(bank), f"{kind.value}: duplicate ids"
    # Mixed deliberately: yes/no for "is it happening", choice for "which", score for "how much".
    assert {q.kind for q in bank} == set(AnswerKind), f"{kind.value} lacks a question type"


@pytest.mark.parametrize("kind", list(ContextKind), ids=lambda k: k.value)
def test_every_bank_says_what_to_do_about_it(kind):
    bank = {q.id: q for q in bank_for(kind)}
    assert "action" in bank and bank["action"].kind is AnswerKind.CHOICE
    assert "urgency" in bank and bank["urgency"].kind is AnswerKind.SCORE


def test_bank_for_refuses_anything_but_a_context_kind():
    with pytest.raises(QuestionError):
        bank_for("cpu")  # type: ignore[arg-type]


def test_bank_for_is_stable_between_calls():
    assert bank_for(ContextKind.CPU) is bank_for(ContextKind.CPU)


@pytest.mark.parametrize("kind, question", ALL, ids=ids)
def test_every_question_is_askable(kind, question):
    if question.dynamic_options:
        assert question.options == (), "the bank holds a dynamic choice unfilled"
        question = askable(question)
    assert re.fullmatch(r"[a-z][a-z0-9_]{1,47}", question.id)
    assert len(question.instructions.strip()) >= 60, "instructions must say what to look at"
    if question.kind is AnswerKind.NOUL:
        assert question.options == () and question.levels == ()
    elif question.kind is AnswerKind.CHOICE:
        assert 1 <= len(question.options) <= 255 and question.levels == ()
        option_ids = [o.id for o in question.options]
        assert len(set(option_ids)) == len(option_ids)
        assert all(re.fullmatch(r"[a-z][a-z0-9_]{0,31}", i) for i in option_ids)
        assert all(len(o.description) >= 10 for o in question.options), "options carry criteria"
    else:
        assert 2 <= len(question.levels) <= 10 and question.options == ()
        assert all(level.strip() for level in question.levels)


@pytest.mark.parametrize("kind, question", ALL, ids=ids)
def test_every_next_step_is_read_only(kind, question):
    for step in steps(question):
        assert not mutating(step), f"{step!r} matches {mutating(step)}"
        assert refuse_mutating(step) == ""


@pytest.mark.parametrize("kind, question", ALL, ids=ids)
def test_only_entity_contexts_name_the_entity(kind, question):
    for step in steps(question):
        placeholders = re.findall(r"\{[^}]*\}", step)
        assert set(placeholders) <= {"{entity}"}
        if kind not in ENTITIES:
            assert "{entity}" not in step, "only an entity context has an entity to fill"


@pytest.mark.parametrize("kind, question", ALL, ids=ids)
def test_every_choice_is_mapped_and_every_serious_outcome_is_actionable(kind, question):
    meaning = question.meaning
    if question.dynamic_options:
        assert meaning.each is not None and meaning.choices == () == meaning.thresholds
    elif question.kind is AnswerKind.CHOICE:
        assert [c for c, _ in meaning.choices] == [o.id for o in question.options]
        assert meaning.thresholds == ()
    else:
        assert meaning.choices == () and meaning.thresholds
    for outcome in meaning.outcomes:
        if outcome.severity.rank >= WATCH.rank:
            assert outcome.cause
        if outcome.severity.rank >= WARN.rank:
            assert outcome.next_step, "a WARN tells the reader where to look"


@pytest.mark.parametrize("kind, question", ALL, ids=ids)
def test_stability_is_checked_exactly_where_an_answer_decides_warn_or_above(kind, question):
    decides = any(o.severity.rank >= WARN.rank for o in question.meaning.outcomes)
    if kind in COMPOSITES:
        # A correlation's answers decide grouping and ordering, not only severity: which member
        # leads and whether several issues show as one are re-asked too.
        assert question.stability_check or not decides
    else:
        assert question.stability_check is decides


def test_a_correlation_re_asks_its_grouping_and_its_cause():
    bank = {q.id: q for q in bank_for(ContextKind.CORRELATION)}
    assert {"same_problem", "likely_cause", "relationship", "causal_confidence",
            "one_incident"} <= set(bank)
    assert bank["same_problem"].stability_check and bank["same_problem"].kind is AnswerKind.NOUL
    assert bank["likely_cause"].dynamic_options and bank["likely_cause"].stability_check
    assert bank["one_incident"].kind is AnswerKind.NOUL
    assert bank["causal_confidence"].kind is AnswerKind.SCORE
    assert [o.id for o in bank["relationship"].options] == [
        "same_root_cause", "cause_and_effect", "coincidental", "same_entity_different"]
    assert [q.id for q in bank.values() if q.dynamic_options] == ["likely_cause"]


@pytest.mark.parametrize("kind", [ContextKind.LOGS, ContextKind.LOG_BURST], ids=lambda k: k.value)
def test_log_text_can_never_raise_a_critical_on_its_own(kind):
    # Anyone can write to the journal. A judgement drawn from log text alone may raise a WARN;
    # CRITICAL, which notifies the desktop, needs a deterministic rule behind it.
    for question in bank_for(kind):
        assert all(o.severity is not CRITICAL for o in question.meaning.outcomes), question.id
        assert "untrusted" in question.instructions


def test_command_text_can_never_raise_a_critical_on_its_own():
    # Any user can write a crontab, so a job's command is as untrusted as a log line: a judgement
    # drawn from it may raise a WARN, never the CRITICAL that notifies the desktop.
    security = {q.id: q for q in bank_for(ContextKind.SECURITY)}
    for question in (*bank_for(ContextKind.JOB), security["cron_payload"]):
        assert all(o.severity is not CRITICAL for o in question.meaning.outcomes), question.id
        assert "untrusted" in question.instructions, question.id
    assert WARN in {o.severity for o in security["cron_payload"].meaning.outcomes}


def test_no_container_question_reads_an_exit_code_as_an_oom_kill():
    # 137 is SIGKILL from anyone, and the containers probe carries no OOMKilled flag: imagegen
    # exited 137 with OOMKilled=false and was answered `oom_killed` yes (2026-10-27).
    for kind, id in ((ContextKind.CONTAINERS, "oom_killed"), (ContextKind.CONTAINER, "oom")):
        text = next(q for q in bank_for(kind) if q.id == id).instructions
        assert "137" in text and "SIGKILL" in text and "never carries Docker's OOMKilled" in text
    cause = {o.id: o.description for o in next(
        q for q in bank_for(ContextKind.CONTAINER) if q.id == "exit_cause").options}
    assert "not proof" in cause["oom"] and "137" in cause["signal"]


def test_the_suspicious_module_question_asks_only_what_proc_modules_shows():
    # The kernel state is /proc/modules: no file, package or signer. Asked whether a module
    # "carries no package or signer", the judge guessed from the O/E taint of DKMS nvidia and of zfs
    # and answered yes (WARN, 2026-10-27).
    text = next(q for q in bank_for(ContextKind.KERNEL)
                if q.id == "module_suspicious").instructions
    assert "do not judge those" in text and "carry no package" not in text
    assert "random-looking name" in text and "added" in text
    assert "(E) taint alone is common for DKMS" in text


def test_a_gpu_link_is_judged_by_a_drop_not_by_its_width_below_the_maximum():
    # A slot wired x4 for an x16 card is the board; only a drop is news.
    link = next(q for q in bank_for(ContextKind.GPU_DEVICE) if q.id == "link_degraded")
    assert "pcie_width_dropped" in link.instructions and "maximum" not in link.instructions
    for kind in (ContextKind.GPU, ContextKind.GPU_DEVICE):
        action = next(q for q in bank_for(kind) if q.id == "action").instructions
        assert "narrow PCIe link that has not changed" in action, kind.value


def test_heat_is_judged_against_each_limit_not_as_a_bare_number():
    # Tctl 77 C against a 95 C limit read as overheating; the evaluator now gives
    # each temperature limit_c and headroom_c, and the questions read those.
    bank = {q.id: q for q in bank_for(ContextKind.HARDWARE)}
    assert "headroom_c of 5 or less" in bank["overheating"].instructions
    assert "smallest headroom_c" in bank["thermal_headroom"].instructions
    thermal = {o.id: o.description for o in bank["fault_class"].options}["thermal"]
    assert "limit_c" in thermal


def test_an_unread_job_is_judged_by_where_its_link_points():
    # /etc/cron.daily/google-chrome links into /opt/google/chrome (package-owned) and was
    # called disguised with no command and no target to read (2026-10-27).
    bank = {q.id: q for q in bank_for(ContextKind.JOB)}
    assert all("its target is where the link points" in q.instructions for q in bank.values()
               if q.instructions.startswith("The state is one scheduled job"))
    disguised = bank["disguised"].instructions
    assert "judge where its target lies" in disguised and "no target says nothing" in disguised


def test_unexpected_root_weighs_host_processes_not_container_ones():
    # Root minio, uvicorn and kind's kube-controller-manager are container workloads; with no
    # attribution they read as unexpected root (p=0.82, WARN, 2026-10-27).
    text = next(q for q in bank_for(ContextKind.PROCESSES)
                if q.id == "unexpected_root").instructions
    assert "pid_ns 'host'" in text and "pid_ns 'separate'" in text and "do not count it" in text


def test_a_job_is_asked_the_questions_decided_with_the_operator():
    bank = {q.id: q for q in bank_for(ContextKind.JOB)}
    assert set(bank) == {"fetches_remote", "obfuscated", "root_writable_path", "disguised",
                         "user_persistence", "raw_ip", "action", "urgency"}
    reach = {id: max(o.severity.rank for o in q.meaning.outcomes) for id, q in bank.items()}
    assert {id for id, rank in reach.items() if rank >= WARN.rank} == set(bank) - {
        "user_persistence"}
    assert reach["user_persistence"] == WATCH.rank   # common on a workstation, alone harmless


@pytest.mark.parametrize("job", ["cron:3fa2b1c4d5e6", "cron:/etc/cron.daily/logrotate",
                                 "timer:apt-daily.timer"])
def test_every_job_step_works_with_the_entity_the_judge_fills(job):
    # The judge fills {entity} with the job id (`job:<id>` less its kind): a hash, a script path
    # or a timer name, never a file to cat, so the steps say where to read rather than run it.
    for question in bank_for(ContextKind.JOB):
        for step in steps(question):
            rendered = step.replace("{entity}", shlex.quote(job))
            assert refuse_mutating(rendered) == "" and not mutating(rendered), rendered
            # The judge keeps a step only if it still parses into the template's words.
            assert shlex.split(rendered) == [w.replace("\0", job) for w in shlex.split(
                step.replace("{entity}", "\0"))], rendered


def test_every_bank_fits_in_one_request_and_the_counts_are_reported(capsys):
    counts = {}
    for kind in ContextKind:
        bank = bank_for(kind)
        text = sum(len(q.id) + len(q.instructions) + sum(len(o.id) + len(o.description)
                                                          for o in q.options)
                   + sum(len(level) for level in q.levels)
                   + (MEMBER_ALLOWANCE if q.dynamic_options else 0) for q in bank)
        counts[kind.value] = (len(bank), text)
        assert len(bank) <= MAX_QUESTIONS_PER_REQUEST, kind.value
        assert text <= QUESTION_TEXT_BUDGET, f"{kind.value}: {text} chars of question text"
    with capsys.disabled():
        total = sum(n for n, _ in counts.values())
        print(f"\nquestions per kind (count, chars): {counts}; total {total}")


# --- constructing a question refuses what the judge or the dashboard could not use ---------------


def outcome(severity=WATCH, cause="c", step="free -h"):
    return Outcome(severity, cause, step)


def noul(**overrides):
    fields = dict(id="q", kind=AnswerKind.NOUL, instructions="Is it happening? Look at x.",
                  options=(), levels=(), meaning=Meaning(thresholds=((0.5, outcome()),)),
                  stability_check=False)
    return Question(**{**fields, **overrides})


def choice(options=(("a", INFO), ("b", WARN)), **overrides):
    opts = tuple(Option(i, f"option {i} criteria") for i, _ in options)
    meaning = Meaning(choices=tuple((i, outcome(s)) for i, s in options))
    fields = dict(id="q", kind=AnswerKind.CHOICE, instructions="Which one? Look at x.",
                  options=opts, levels=(), meaning=meaning, stability_check=True)
    return Question(**{**fields, **overrides})


def score(levels=("low", "mid", "high"), thresholds=((1.0, WATCH), (2.0, WARN)), **overrides):
    meaning = Meaning(thresholds=tuple((t, outcome(s)) for t, s in thresholds))
    fields = dict(id="q", kind=AnswerKind.SCORE, instructions="How much? Look at x.",
                  options=(), levels=levels, meaning=meaning, stability_check=True)
    return Question(**{**fields, **overrides})


def test_the_builders_above_make_valid_questions():
    assert noul().kind is AnswerKind.NOUL
    assert choice().stability_check
    assert score().levels == ("low", "mid", "high")


@pytest.mark.parametrize("build", [
    lambda: noul(id="Bad Id"),
    lambda: noul(id=""),
    lambda: noul(instructions="   "),
    lambda: noul(kind="noul"),
    lambda: noul(options=(Option("a", "an option"),)),
    lambda: noul(levels=("a", "b")),
    lambda: noul(meaning=Meaning(thresholds=())),
    lambda: noul(meaning=Meaning(thresholds=((1.5, outcome()),))),
    lambda: noul(meaning=Meaning(thresholds=((0.0, outcome()),))),
    lambda: noul(meaning=Meaning(choices=(("a", outcome()),))),
    lambda: noul(meaning=Meaning(thresholds=((0.5, outcome(WARN)),))),  # WARN but unchecked
    lambda: noul(stability_check=1),
    lambda: choice(options=()),
    lambda: choice(options=tuple((f"o{i}", INFO) for i in range(256))),
    lambda: choice(options=(("a", INFO), ("a", INFO))),
    lambda: choice(options=(("A b", INFO),)),
    lambda: choice(levels=("x", "y")),
    lambda: choice(meaning=Meaning(choices=(("a", outcome()),))),        # b is unmapped
    lambda: choice(meaning=Meaning(choices=(("a", outcome()), ("b", outcome()),
                                            ("c", outcome())))),        # c is not an option
    lambda: choice(meaning=Meaning(choices=(("b", outcome()), ("a", outcome())))),  # order
    lambda: choice(meaning=Meaning(thresholds=((0.5, outcome()),))),
    lambda: score(levels=("only",)),
    lambda: score(levels=tuple(str(i) for i in range(11))),
    lambda: score(levels=("low", " ")),
    lambda: score(options=(Option("a", "an option"),)),
    lambda: score(thresholds=((2.5, WATCH),)),                           # past the top level
    lambda: score(thresholds=((2.0, WARN), (1.0, WATCH))),               # not ascending
    lambda: score(thresholds=((1.0, WARN), (2.0, WATCH))),               # severity falls
    lambda: score(thresholds=((1.0, WATCH), (1.0, WARN))),               # repeated threshold
    lambda: score(meaning=Meaning(choices=(("a", outcome()),))),
    lambda: noul(needs="memory"),                                        # a tuple, not a str
    lambda: noul(needs=("",)),
    lambda: noul(needs=("memory/",)),
    lambda: noul(needs=("/memory",)),
    lambda: noul(needs=("Memory",)),
    lambda: noul(needs=("smart*x",)),                                    # * ends a key
    lambda: noul(needs=(3,)),
])
def test_a_malformed_question_is_refused(build):
    with pytest.raises(QuestionError):
        build()


@pytest.mark.parametrize("build", [
    lambda: Outcome("warn", "c", ""),
    lambda: Outcome(WATCH, "", ""),                  # a WATCH says what it is about
    lambda: Outcome(WARN, "c", ""),                  # a WARN says where to look
    lambda: Outcome(WATCH, "c", "sudo systemctl restart docker"),
    lambda: Outcome(WATCH, "c", "journalctl -u {unit} -n 50"),    # only {entity} is filled
    lambda: Outcome(WATCH, 3, ""),                   # a cause is text
    lambda: Outcome(INFO, "", None),
    lambda: Option("", "no id"),
    lambda: Option("a", ""),
    lambda: Meaning(thresholds=((True, outcome()),)),
    lambda: Meaning(thresholds=(("0.5", outcome()),)),
    lambda: Meaning(thresholds=((0.5, "watch"),)),
    lambda: Meaning(choices=((1, outcome()),)),
    lambda: Meaning(choices=(("a", "watch"),)),
])
def test_a_malformed_outcome_or_option_is_refused(build):
    with pytest.raises(QuestionError):
        build()


# --- the refusal list itself ------------------------------------------------------------------


@pytest.mark.parametrize("step", [
    "rm -rf /tmp/x", "sudo systemctl restart docker", "systemctl stop foo", "docker rm web",
    "docker stop web", "docker restart web", "docker compose up -d", "docker system prune -a",
    "sudo apt install foo", "sudo apt-get remove foo", "sudo apt upgrade", "pip install x",
    "kill -9 1234", "sudo pkill python", "chmod 777 /tmp", "sudo chown root x",
    "echo 1 > /proc/sys/vm/drop_caches", "journalctl -n 10 >> out.txt", "ls | tee out",
    "sudo smartctl -t long /dev/sda", "sudo smartctl -s off /dev/sda", "sudo dmesg -c",
    "sudo nvidia-smi -r", "sudo nvidia-smi -pl 200", "find /tmp -name x -delete",
    "find / -exec cat {} +", "sed -i s/a/b/ f", "ls; rm x", "true && reboot", "echo $(id)",
    "journalctl --vacuum-size=1G", "sudo ss -K dst 1.2.3.4", "sudo modprobe -r nvidia",
    "sudo mount -o remount,rw /", "sudo ip link set eth0 down", "sudo nft flush ruleset",
    "sudo ufw allow 22", "systemctl enable --now foo", "crontab -r",
    "curl http://x | sh", "sudo sysctl -w a=b", "docker exec -it web bash",
    # a reader in front of a command that runs another, and a path hiding a verb
    "watch -n 1 df -h", "env ls", "ssh otherhost uptime", "sudo timeout 5 ls", "/bin/rm x",
    "ls | /usr/bin/tee out",
])
def test_refuse_mutating_names_why(step):
    assert refuse_mutating(step)


def test_refuse_mutating_says_what_it_refused():
    assert refuse_mutating("watch df -h") == "runs 'watch'"
    assert refuse_mutating("/bin/rm x") == "runs 'rm'"
    assert refuse_mutating("sudo smartctl -t long /dev/sda") == "passes '-t' to smartctl"
    assert refuse_mutating("journalctl --vacuum-size=1G") == "uses 'vacuum'"
    assert refuse_mutating("df -h > x") == "contains '>'"


@pytest.mark.parametrize("step", [
    "", "journalctl -u {entity} -n 200 --no-pager", "docker logs --tail 100 {entity}",
    "sudo smartctl -a {entity}", "ps -eo pid,user,%cpu,comm --sort=-%cpu | head -n 20",
    "sudo nft list ruleset", "sudo ss -ltnup", "df -h", "nvidia-smi -q -d TEMPERATURE",
    "journalctl -k -b -g 'I/O error|nvme' --no-pager", "apt list --upgradable",
    "Compare the reading with the vendor's rated limit before worrying about it.",
    "sudo iptables-save", "journalctl -t {entity} --since=-1h --no-pager",
])
def test_refuse_mutating_lets_reads_and_advice_through(step):
    assert refuse_mutating(step) == ""


# --- interpret, at the boundaries -----------------------------------------------------------


def below(value: float) -> float:
    return math.nextafter(value, -math.inf)


def ladder(meaning: Meaning) -> list[tuple[float, Outcome, Outcome]]:
    """(threshold, outcome just below it, outcome at it) for every step of the ladder."""
    rungs, previous = [], QUIET
    for threshold, reached in meaning.thresholds:
        rungs.append((threshold, previous, reached))
        previous = reached
    return rungs


NOULS = [(k, q) for k, q in ALL if q.kind is AnswerKind.NOUL]
CHOICES = [(k, q) for k, q in ALL if q.kind is AnswerKind.CHOICE]
SCORES = [(k, q) for k, q in ALL if q.kind is AnswerKind.SCORE]


@pytest.mark.parametrize("kind, question", NOULS, ids=[f"{k.value}.{q.id}" for k, q in NOULS])
def test_a_noul_changes_severity_exactly_at_its_thresholds(kind, question):
    for threshold, under, at in ladder(question.meaning):
        low = interpret(question, NoulAnswer(below(threshold)))
        high = interpret(question, NoulAnswer(threshold))
        assert (low.severity, low.cause, low.next_step) == (
            under.severity, under.cause, under.next_step)
        assert (high.severity, high.cause, high.next_step) == (
            at.severity, at.cause, at.next_step)
    assert interpret(question, NoulAnswer(0.0)).severity is INFO
    top = question.meaning.thresholds[-1][1]
    assert interpret(question, NoulAnswer(1.0)).severity is top.severity


@pytest.mark.parametrize("kind, question", CHOICES, ids=[f"{k.value}.{q.id}" for k, q in CHOICES])
def test_every_choice_id_reads_as_its_mapped_outcome(kind, question):
    question = askable(question)
    ids_ = [o.id for o in question.options]
    mapped = question.meaning.choices or tuple((i, question.meaning.each) for i in ids_)
    for chosen, expected in mapped:
        dist = {i: (0.9 if i == chosen else 0.1 / max(1, len(ids_) - 1)) for i in ids_}
        reading = interpret(question, ChoiceAnswer(chosen, dist, 0.8))
        assert (reading.severity, reading.cause, reading.next_step) == (
            expected.severity, expected.cause, expected.next_step)
        assert reading.value == chosen and reading.confidence == 0.8
        assert reading.question == question.id


@pytest.mark.parametrize("kind, question", SCORES, ids=[f"{k.value}.{q.id}" for k, q in SCORES])
def test_a_score_changes_severity_exactly_at_its_thresholds(kind, question):
    n = len(question.levels)
    dist = {str(i): 1 / n for i in range(n)}
    for threshold, under, at in ladder(question.meaning):
        assert interpret(question, ScoreAnswer(below(threshold), n, dist, 0.5)).severity \
            is under.severity
        high = interpret(question, ScoreAnswer(threshold, n, dist, 0.5))
        assert (high.severity, high.cause, high.next_step) == (at.severity, at.cause,
                                                               at.next_step)
        assert high.value == threshold and high.confidence == 0.5
    assert interpret(question, ScoreAnswer(0.0, n, dist, 0.5)).severity is INFO


def test_a_noul_reading_is_confident_the_further_it_is_from_even():
    question = noul()
    assert interpret(question, NoulAnswer(0.5)).confidence == 0.0
    assert interpret(question, NoulAnswer(1.0)).confidence == 1.0
    assert interpret(question, NoulAnswer(0.0)).confidence == 1.0
    assert interpret(question, NoulAnswer(0.75)).confidence == pytest.approx(0.5)
    reading = interpret(question, NoulAnswer(0.75))
    assert isinstance(reading, Reading) and reading.value == 0.75
    assert interpret(question, NoulAnswer(0.2)) == Reading("q", INFO, "", "", pytest.approx(0.6),
                                                           0.2)


def test_the_standard_action_class_maps_to_the_four_severities():
    action = {q.id: q for q in bank_for(ContextKind.CPU)}["action"]
    got = {o.id: interpret(action, ChoiceAnswer(o.id, {i.id: 0.25 for i in action.options},
                                                0.9)).severity for o in action.options}
    assert got == {"ignore": INFO, "watch": WATCH, "investigate": WARN, "act_now": CRITICAL}


@pytest.mark.parametrize("question, answer", [
    (noul(), ChoiceAnswer("a", {"a": 1.0}, 0.5)),                       # wrong type
    (noul(), ScoreAnswer(1.0, 3, {"0": 1.0}, 0.5)),
    (choice(), NoulAnswer(0.5)),
    (choice(), ChoiceAnswer("z", {"z": 1.0}, 0.5)),                     # not an option
    (choice(), ChoiceAnswer("a", {"a": 1.0}, 0.5)),                     # distribution misses b
    (choice(), ChoiceAnswer("a", {"a": 0.5, "b": 0.3, "z": 0.2}, 0.5)),  # and names z
    (score(), NoulAnswer(0.5)),
    (score(), ScoreAnswer(1.0, 4, {"0": 1.0}, 0.5)),                    # another scale
    (noul(), {"type": "noul", "noul": 0.5}),                             # raw, not an answer
])
def test_interpret_refuses_an_answer_to_a_different_question(question, answer):
    with pytest.raises(AnswerError):
        interpret(question, answer)


# --- dynamic options: a choice filled from the context -------------------------------------------


def dynamic(**overrides):
    fields = dict(id="cause", kind=AnswerKind.CHOICE, instructions="Which member? Look at x.",
                  options=(), levels=(), meaning=Meaning(each=Outcome(INFO, "likely-cause", "")),
                  stability_check=True, dynamic_options=True)
    return Question(**{**fields, **overrides})


def test_a_dynamic_choice_is_filled_then_read():
    filled = dynamic().fill(MEMBERS)
    assert [o.id for o in filled.options] == ["m1", "m2", "m3", "m4"] and filled.dynamic_options
    reading = interpret(filled, ChoiceAnswer("m3", {o.id: 0.25 for o in MEMBERS}, 0.7))
    assert (reading.value, reading.severity, reading.cause) == ("m3", INFO, "likely-cause")


def test_an_unfilled_dynamic_choice_cannot_be_read():
    with pytest.raises(AnswerError):
        interpret(dynamic(), ChoiceAnswer("m1", {"m1": 1.0}, 0.5))


def test_a_filled_choice_still_refuses_an_answer_outside_its_members():
    filled = dynamic().fill(MEMBERS)
    with pytest.raises(AnswerError):
        interpret(filled, ChoiceAnswer("m9", {"m9": 1.0}, 0.5))


@pytest.mark.parametrize("build", [
    lambda: noul().fill(MEMBERS),                                   # not dynamic
    lambda: dynamic().fill(()),                                     # nothing to fill with
    lambda: dynamic().fill(["m1"]),                                 # not options
    lambda: dynamic().fill((Option("m1", "a member"), Option("m1", "a member"))),
    lambda: dynamic().fill(tuple(Option(f"m{i}", "a member") for i in range(256))),
    lambda: dynamic(kind=AnswerKind.NOUL, meaning=Meaning(each=QUIET)),
    lambda: dynamic(meaning=Meaning(choices=(("m1", QUIET),))),     # a fixed map, not each
    lambda: dynamic(levels=("a", "b")),
    lambda: dynamic(dynamic_options=1),
    lambda: choice(meaning=Meaning(each=QUIET)),                     # each on a fixed choice
    lambda: noul(meaning=Meaning(each=QUIET)),
    lambda: Meaning(each="info"),
    lambda: Meaning(thresholds=((0.5, outcome()),), each=QUIET),
])
def test_a_malformed_dynamic_question_is_refused(build):
    with pytest.raises(QuestionError):
        build()


def test_every_listener_step_works_with_the_entity_the_judge_fills():
    # The judge fills {entity} with what follows the entity's first ':'. A listener entity is
    # `listener:<proto>/<port>`, so its steps receive `tcp/6379`, not an address.
    listener_steps = {step for question in bank_for(ContextKind.LISTENER)
                      for step in steps(question) if step}
    # The one step that names no entity is the shared "watch" advice, which asks for no command.
    assert {s for s in listener_steps if "{entity}" not in s} == {
        "Nothing to look at yet. The monitor keeps asking and will raise it if it grows."}
    rendered = [step.replace("{entity}", "tcp/6379") for step in listener_steps
                if "{entity}" in step]
    assert rendered
    for step in rendered:
        assert refuse_mutating(step) == "" and not mutating(step), step
        assert "6379" in step, f"{step!r} does not name the port"
        assert "grep -F -- 'tcp/6379'" not in step, "ss prints ports, never proto/port"


def test_security_does_not_ask_about_path_permissions_it_has_no_probe_for():
    # No probe reads the PATH directories' modes, so the answer could only be a guess: it read
    # the agent's own writable mounts as a writable PATH and kept a false WARN open.
    assert "writable_path" not in {q.id for q in bank_for(ContextKind.SECURITY)}



# --- evidence -------------------------------------------------------------------------------------


STATE = {"memory": {"slab_kb": 10, "gone": None}, "psi.cpu": {"some_avg60": 1.0},
         "containers": {"containers": [{"name": "a"}, {"name": "b", "published": []}]},
         "smart.nvme0n1": {"passed": True}, "kernel.modules": {"count": 3}}


@pytest.mark.parametrize("needs, present", [
    ((), True),
    (("memory",), True),
    (("memory/slab_kb",), True),
    (("psi.cpu", "memory/slab_kb"), True),             # dotted keys are probe ids, not paths
    (("memory/gone",), False),                         # null is no evidence
    (("memory/slab_kb/deeper",), False),
    (("memory/absent",), False),
    (("psi.cpu", "absent"), False),                    # every need, not any
    (("containers/containers/published",), True),      # any element of a list will do
    (("containers/containers/image",), False),
    (("smart.*",), True),
    (("smart.*/passed",), True),
    (("disk.*",), False),
    (("kernel.modules/added",), False),                # a diff, only once there is a baseline
])
def test_needs_present_finds_each_path_in_the_state(needs, present):
    assert needs_present(noul(needs=needs), STATE) is present


def test_needs_present_reads_only_mappings_and_lists():
    assert not needs_present(noul(needs=("a/b",)), {"a": "a string has no keys"})
    assert not needs_present(noul(needs=("a",)), ["a"])


def test_needs_values_keeps_what_each_path_found_and_only_that():
    q = noul(needs=("memory/slab_kb", "containers/containers/published", "smart.*/passed",
                    "memory/gone", "absent"))
    assert needs_values(q, STATE) == {
        "memory/slab_kb": 10,
        "containers/containers/published": [[]],        # only the element that carries it
        "smart.*/passed": {"smart.nvme0n1": True},      # only the keys that match
    }
    assert needs_values(noul(), STATE) == {}
