# Probes: the catalog and what each parser emits

Source of truth: `neonwatch/probes/catalog.py` (the specs) and `neonwatch/probes/parsers.py` (the
fields). This page is the contract that `rules`, `evaluator`, `questions` and `ui` code against.
If a parser changes a field, this page changes in the same commit.

## How to read a probe

- **Tier** sets the cadence (`config.Cadence`: fast 60 s, medium 300 s, slow 3600 s, daily 86400 s).
- **Kind**: what the executor does. `command` runs a fixed argv, with an absolute binary path, no
  shell and no environment. `file` reads one path. `glob` reads every file matching one pattern.
  `listdir` lists one directory. `docker` sends `GET <path>` to the Docker Engine API socket.
- **Cost** is a budget class for deferral (`cheap`, `moderate`, `heavy`), not a measurement.
- `parse(probe_id, raw) -> dict` returns the fields below. It raises `ParseError` (a
  `ValueError`) on input it cannot read. It never returns a partial dict. Unknown ids raise
  `ParseError` as well.
- Every output survives `json.dumps(..., allow_nan=False)` unchanged. Counters are cumulative, as
  the kernel reports them, so a rate is a difference between two observations.
- `null` means the source did not report the value. It never means zero.

### One bad record never blanks a probe

Every list-shaped parser reads its output one record at a time: a line, an array element, a
sensor reading, a memory controller, an ATA attribute row. A record it cannot read is skipped and
counted in `skipped` (int). The rest of the output is still returned, because
one crafted record from any local user must not turn a whole observation into an error.

The probe still raises `ParseError` in two cases. The first is when the output as a whole has the
wrong shape: it is not JSON, it is not an array, or the header is missing. The second is when
there were records but not one of them could be read. The journal probes are exempt from the
second case, because a sender can fill a whole window with hostile entries. They return
`count: 0` and `skipped: N` instead.

The parsers with a `skipped` field are `sensors`, `gpu`, `disk.fill`, `net.dev`, `processes`,
`units.failed`, `journal.warnings`, `journal.errors`, `listeners`, `containers`, `edac`,
`smart.<dev>` (ATA attribute rows), `kernel.modules`, `units.files`, `units.timers`,
`units.detail`, `cron.system`, `cron.d`, `cron.user` and `cron.anacron`. The four crontab parsers
never refuse for bad lines: a crontab of nothing but unreadable lines is `count: 0`.

Three parsers stay strict:

- `firewall`: a hash of a partly read ruleset would report a change, or no change, that did not
  happen, and only root writes the ruleset.
- The `listdir`/`glob` framing: it is the executor's own encoding, not host data.
- `reboot.required`: two fixed file names.

Names chosen by a sender are cut to 128 characters. These are the journal `unit`, `identifier`
and `transport`, the ps `user`, and the ss `process`. Command lines and messages are redacted over the whole field, up to 4096
characters (journald's field threshold), and then cut to 300 for display. A secret that starts
in the kept part and ends far past it, such as a private key block, is therefore matched whole
before the cut.

### Raw framing for `glob` and `listdir`

The executor builds these with `probes.frame_files` and `probes.frame_listing`, so both sides
share one implementation:

- **glob** → a JSON object mapping each matched absolute path to its contents, decoded as UTF-8
  with replacement: `{"/path": "text", ...}`. If nothing matches, the result is `{}`, and that is
  a valid answer.
- **listdir** → a JSON array of entry names (`["a", "b"]`), sorted. The parser refuses names that
  are empty, contain `/`, or repeat.

For `command` probes the raw input is stdout. For `file`, it is the file's bytes. For `docker`,
it is the HTTP response body.

### Device templates

`smart` is a template: its argv carries `{device}`, and its `devices` regex is
`nvme\d+n\d+|sd[a-z]+`, matched in full. `expand(spec, names)` returns one concrete spec per name,
with id `smart.<name>` (for example `smart.nvme0n1`, `smart.sda`) and `devices=""`. It raises
`ValueError` if any name fails the regex, and it also raises on a spec that is not a template.
Names come from `block.devices` (`/sys/block`). The collector filters them with the regex before
calling `expand`. `parse("smart.<name>", raw)` goes to the SMART parser only when `<name>`
matches the regex.

## Catalog

43 specs: 12 fast, 8 medium, 12 slow (one of them the `smart` template, 3 concrete disks on this
host), 11 daily.

| id | tier | kind | cost | domain | source |
| --- | --- | --- | --- | --- | --- |
| `load` | fast | file | cheap | cpu | `/proc/loadavg` |
| `uptime` | fast | file | cheap | kernel | `/proc/uptime` |
| `psi.cpu` | fast | file | cheap | cpu | `/proc/pressure/cpu` |
| `psi.memory` | fast | file | cheap | memory | `/proc/pressure/memory` |
| `psi.io` | fast | file | cheap | storage | `/proc/pressure/io` |
| `memory` | fast | file | cheap | memory | `/proc/meminfo` |
| `vmstat` | fast | file | cheap | memory | `/proc/vmstat` |
| `cpu.stat` | fast | file | cheap | cpu | `/proc/stat` |
| `sensors` | fast | command | cheap | hardware | `/usr/bin/sensors -j` |
| `gpu` | fast | command | moderate | gpu | `/usr/bin/nvidia-smi --query-gpu index,name,temperature.gpu,power.draw,power.limit,memory.used,memory.total,utilization.gpu,clocks_event_reasons.active,pcie.link.width.current,pcie.link.width.max --format=csv,noheader,nounits` |
| `disk.fill` | fast | command | cheap | storage | `/usr/bin/df -l -B1 -x squashfs -x overlay -x efivarfs -x devtmpfs --output=source,fstype,size,used,avail,itotal,iused,target` |
| `net.dev` | fast | file | cheap | network | `/proc/net/dev` |
| `processes` | medium | command | moderate | processes | `/usr/bin/ps -e -o pid=,ppid=,user:32=,stat=,pcpu=,rss=,etimes=,nlwp=,times=,pidns=,comm:15=,args=` |
| `units.failed` | medium | command | cheap | services | `/usr/bin/systemctl list-units --failed -o json --no-pager` |
| `journal.warnings` | medium | command | heavy | logs | `/usr/bin/journalctl -q -p warning -o json --output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_TRANSPORT --no-pager -n 500 --since -6min` |
| `journal.errors` | medium | command | heavy | logs | `/usr/bin/journalctl -q -p err -o json --output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_TRANSPORT --no-pager -n 200 --since -6min` |
| `listeners` | medium | command | moderate | network | `/usr/bin/ss -ltnupH` |
| `kernel.tainted` | medium | file | cheap | kernel | `/proc/sys/kernel/tainted` |
| `containers` | medium | docker | moderate | containers | `GET /containers/json?all=1` |
| `edac` | medium | glob | cheap | hardware | `/sys/devices/system/edac/mc/mc*/[cu]e_count` |
| `block.devices` | slow | listdir | cheap | storage | `/sys/block` |
| `smart` → `smart.<dev>` | slow | command | heavy | storage | `/usr/sbin/smartctl -j -a /dev/{device}` |
| `firewall` | slow | command | moderate | firewall | `/usr/sbin/nft -j list ruleset` |
| `kernel.modules` | slow | file | cheap | kernel | `/proc/modules` |
| `reboot.required` | slow | glob | cheap | kernel | `/var/run/reboot-required*` |
| `cron.system` | slow | file | cheap | security | `/etc/crontab` |
| `cron.anacron` | slow | glob | cheap | security | `/etc/anacrontab*` |
| `cron.d` | slow | glob | cheap | security | `/etc/cron.d/*` |
| `cron.d.names` | slow | listdir | cheap | security | `/etc/cron.d` |
| `cron.user` | slow | glob | cheap | security | `/var/spool/cron/crontabs/*` |
| `fs.protected_hardlinks` | slow | file | cheap | security | `/proc/sys/fs/protected_hardlinks` |
| `units.timers` | slow | command | cheap | services | `/usr/bin/systemctl list-timers --all -o json --no-pager` |
| `units.detail` | slow | command | moderate | services | `/usr/bin/systemctl show --all -p Id,Description,User,ExecStart,ActiveState,SubState,Result,NRestarts,ExecMainStatus,ExecMainStartTimestamp,ExecMainExitTimestamp,UnitFileState,FragmentPath,Triggers,TriggeredBy,TimersCalendar,TimersMonotonic,Unit --timestamp=unix --no-pager *.service *.timer` |
| `ssh.keys.home` | daily | glob | cheap | security | `/home/*/.ssh/authorized_keys*` |
| `ssh.keys.root` | daily | glob | cheap | security | `/root/.ssh/authorized_keys*` |
| `cron.hourly` `cron.daily` `cron.weekly` `cron.monthly` | daily | glob | cheap | security | `/etc/cron.<period>/*` |
| `cron.hourly.names` … `cron.monthly.names` | daily | listdir | cheap | security | `/etc/cron.<period>` |
| `units.files` | daily | command | moderate | services | `/usr/bin/systemctl list-unit-files -o json --no-pager` |

Why some sources look the way they do:

- `disk.fill` uses `-l` (local filesystems only) because a `stat` on a dead NFS mount blocks in
  D state, and no executor timeout can interrupt that. Remote mounts are therefore not measured.
- `journal.warnings` covers a 6-minute window on a 5-minute cadence, so consecutive runs overlap
  by one minute. Downstream should expect repeated entries across runs. `journal.errors` works
  the same way.
- `journal.errors` is the same read at `-p err` (priority 0–3), with its own cap of 200. One
  unit flooding warnings can fill all 500 of `journal.warnings` (a chatty VPN agent can do
  exactly that), and it would otherwise hide every real error in the window.
- `reboot.required` and `ssh.keys.root` are globs so that a missing file is an ordinary answer
  rather than a read error.
- Each cron directory is both read (`glob`) and listed (`listdir`). The glob skips dot names and
  refuses symlinks (`O_NOFOLLOW`: a user's link must not make root read its target), but cron may
  still run either, so the listing is what shows they are there. The listing also reads each
  link's target with `readlink` (the link's own text; it is never followed). `jobs.scheduled`
  turns a name listed and not read into a job with `unread: true` and, for a link, its `target`
  made absolute against the directory.
- `units.detail` passes unit *patterns*, not names. A pattern matches loaded units only, so PID 1
  loads nothing to answer. `--all` is needed because without it a pattern matches active units
  only, which leaves out most services that a timer starts (they run and exit). Measured on this
  host: 214 units, about 100 KB.

## Fields per probe

Types are JSON types: `int`, `float`, `str`, `bool`, `list`, `object`. A `|null` suffix means the
field can be `null`.

### `load`

| field | type | meaning |
| --- | --- | --- |
| `load1` / `load5` / `load15` | float | load averages over 1, 5 and 15 minutes |
| `runnable` | int | runnable scheduling entities right now |
| `threads` | int | scheduling entities (threads) that exist |
| `last_pid` | int | most recently assigned pid |

### `uptime`

| field | type | meaning |
| --- | --- | --- |
| `uptime_s` | float | seconds since boot; a decrease between observations means a reboot |
| `idle_s` | float | summed idle seconds across all CPUs |

### `psi.cpu`, `psi.memory`, `psi.io`

| field | type | meaning |
| --- | --- | --- |
| `some_avg10` / `some_avg60` / `some_avg300` | float | % of time at least one task stalled on the resource, over 10/60/300 s |
| `some_total_us` | int | cumulative stall time, µs |
| `full_avg10` / `full_avg60` / `full_avg300` | float\|null | % of time all non-idle tasks stalled together; `null` when the kernel prints no `full` line |
| `full_total_us` | int\|null | cumulative full-stall time, µs |

### `memory`

Every `_kb` field is an int in KiB, taken from the matching `/proc/meminfo` key.

| field | type | meaning |
| --- | --- | --- |
| `mem_total_kb` | int | MemTotal |
| `mem_free_kb` | int | MemFree |
| `mem_available_kb` | int | MemAvailable, the kernel's estimate of what can be allocated without swapping |
| `buffers_kb` / `cached_kb` | int | Buffers / Cached |
| `swap_total_kb` / `swap_free_kb` / `swap_cached_kb` | int | SwapTotal / SwapFree / SwapCached |
| `dirty_kb` / `writeback_kb` | int | Dirty / Writeback |
| `anon_pages_kb` / `shmem_kb` / `slab_kb` | int | AnonPages / Shmem / Slab |
| `commit_limit_kb` / `committed_as_kb` | int | CommitLimit / Committed_AS |
| `hardware_corrupted_kb` | int\|null | HardwareCorrupted (memory poisoned by the hardware); `null` if the kernel lacks the key |
| `mem_available_pct` | float | 100 × MemAvailable / MemTotal, 2 dp |
| `swap_used_pct` | float | 100 × (SwapTotal − SwapFree) / SwapTotal, 2 dp; `0.0` when there is no swap |

### `vmstat`

All fields are cumulative counters (int) since boot.

| field | type | meaning |
| --- | --- | --- |
| `oom_kill` | int | processes killed by the OOM killer |
| `pgfault` / `pgmajfault` | int | page faults / major (disk-backed) page faults |
| `pswpin` / `pswpout` | int | pages swapped in / out |

### `cpu.stat`

| field | type | meaning |
| --- | --- | --- |
| `user` `nice` `system` `idle` `iowait` `irq` `softirq` `steal` | int | cumulative CPU time across all CPUs, in USER_HZ ticks (normally 1/100 s) |
| `cpus` | int | number of `cpuN` lines (online CPUs) |
| `ctxt` | int | cumulative context switches |
| `btime` | int | boot time, epoch seconds |
| `processes` | int | cumulative forks |
| `procs_running` / `procs_blocked` | int | tasks runnable / blocked on IO right now |

### `sensors`

| field | type | meaning |
| --- | --- | --- |
| `readings` | list | one object per sensor feature that has an `_input` value, in the order lm-sensors reports them |
| `readings[].chip` | str | chip id, e.g. `k10temp-pci-00c3`, `nvme-pci-0600` |
| `readings[].adapter` | str | lm-sensors `Adapter`, `""` if none |
| `readings[].label` | str | feature label, e.g. `Tctl`, `Composite`, `fan2` |
| `readings[].sensor` | str | hwmon sensor name, e.g. `temp1`, `fan2`, `in0` |
| `readings[].kind` | str | the sensor name without its digits: `temp`, `fan`, `in`, `power`, `curr`… |
| `readings[].input` | float | current value (°C for temp, RPM for fan, V for in, W for power) |
| `readings[].min` / `.max` / `.crit` | float\|null | limits the chip reports, as reported. Some are sentinel values such as `-273.15` or `65261.85` |
| `readings[].alarm` | float\|null | the chip's alarm flag (`0.0` or `1.0`) |
| `count` | int | length of `readings` |
| `skipped` | int | readings (or chips) that could not be read |

### `gpu`

| field | type | meaning |
| --- | --- | --- |
| `gpus` | list | one object per GPU |
| `gpus[].index` | int | nvidia-smi index |
| `gpus[].name` | str | product name |
| `gpus[].temperature_c` | int\|null | core temperature, °C |
| `gpus[].power_w` / `.power_limit_w` | float\|null | current draw / enforced limit, W |
| `gpus[].memory_used_mib` / `.memory_total_mib` | int\|null | framebuffer memory, MiB |
| `gpus[].utilization_pct` | int\|null | GPU utilisation, % |
| `gpus[].throttle_reasons` | int\|null | `clocks_event_reasons.active` bitmask |
| `gpus[].throttle` | list[str] | names of the set bits: `gpu_idle`, `applications_clocks_setting`, `sw_power_cap`, `hw_slowdown`, `sync_boost`, `sw_thermal_slowdown`, `hw_thermal_slowdown`, `hw_power_brake_slowdown`, `display_clock_setting` |
| `gpus[].pcie_width` / `.pcie_width_max` | int\|null | current / maximum PCIe link width (lanes) |
| `count` | int | number of GPUs |
| `skipped` | int | nvidia-smi lines that could not be read |

A field that nvidia-smi reports as `[N/A]` or `[Not Supported]` is `null`.

### `disk.fill`

| field | type | meaning |
| --- | --- | --- |
| `filesystems` | list | one object per mounted local filesystem, in df order |
| `filesystems[].source` | str | device or source, e.g. `/dev/nvme0n1p6`, `tmpfs` |
| `filesystems[].fstype` | str | filesystem type |
| `filesystems[].mount` | str | mount point (may contain spaces) |
| `filesystems[].size_bytes` / `.used_bytes` / `.avail_bytes` | int | bytes |
| `filesystems[].used_pct` | float\|null | 100 × used / (used + avail), 2 dp, as df computes Use%. `null` for an empty filesystem |
| `filesystems[].inodes` / `.inodes_used` | int | inode totals (0 on filesystems without inodes, such as vfat) |
| `filesystems[].inodes_used_pct` | float\|null | 100 × inodes_used / inodes, 2 dp; `null` when `inodes` is 0 |
| `count` | int | number of filesystems |
| `skipped` | int | df lines that could not be read |

### `net.dev`

| field | type | meaning |
| --- | --- | --- |
| `interfaces` | list | one object per interface, in kernel order. Comparing names across observations shows interface churn, such as veth creation |
| `interfaces[].name` | str | interface name |
| `interfaces[].rx_bytes` `rx_packets` `rx_errs` `rx_drop` `rx_fifo` `rx_frame` `rx_compressed` `rx_multicast` | int | cumulative receive counters |
| `interfaces[].tx_bytes` `tx_packets` `tx_errs` `tx_drop` `tx_fifo` `tx_colls` `tx_carrier` `tx_compressed` | int | cumulative transmit counters |
| `count` | int | number of interfaces |
| `skipped` | int | interface lines that could not be read |

### `processes`

A process entry (`proc`) has these fields:

| field | type | meaning |
| --- | --- | --- |
| `pid` / `ppid` | int | process / parent id |
| `user` | str | effective user name, or uid when the name does not resolve; ≤128 chars |
| `state` | str | ps `stat`, e.g. `Ss`, `Rsl`, `D`, `Z` |
| `cpu_pct` | float | ps `pcpu`: CPU time ÷ elapsed time over the process's **lifetime**, not current load. It can exceed 100 for multithreaded processes |
| `rss_kb` | int | resident set, KiB |
| `elapsed_s` | int | seconds since the process started |
| `threads` | int | thread count |
| `cpu_s` | int | cumulative CPU seconds; the difference between two observations is the real recent usage |
| `comm` | str | command name, at most 15 characters (kernel threads are truncated) |
| `pid_ns` | str\|null | `host` when it runs in PID 1's PID namespace, `separate` in another one (a container or a sandbox), null where ps could not read either |
| `args` | str | command line, redacted, then cut to 300 characters. The environment is never read |

| field | type | meaning |
| --- | --- | --- |
| `count` | int | processes |
| `threads` | int | sum of `threads` |
| `rss_kb_total` | int | sum of RSS, KiB (shared pages are counted once per process) |
| `cpu_pct_total` | float | sum of `cpu_pct`, 1 dp |
| `zombies` | int | processes whose state starts with `Z` |
| `uninterruptible` | int | processes whose state starts with `D` |
| `top_cpu` | list[proc] | top 20 by `cpu_pct`, ties broken by pid |
| `top_rss` | list[proc] | top 20 by `rss_kb`, ties broken by pid |
| `from_tmp` | list[proc] | up to 20 processes whose `args` starts with `/tmp/`, `/var/tmp/` or `/dev/shm/`, other than a test run's (below); each raises `process.runs_from_tmp` |
| `tmp_test_runs` | list[run] | up to 20 pytest runs whose programs run from `/tmp/pytest-of-<user>/`: the first ancestor outside a temporary directory (at most 8 up) runs pytest. Each is `pid`, `user`, `pid_ns` and `args` of the runner, `processes` (how many), `programs` (up to 3) and `pids` (up to 20); each raises one INFO `process.tests_from_tmp` |
| `redacted` | int | secret-shaped strings cut from command lines |
| `skipped` | int | ps lines that could not be read |

### `units.failed`

| field | type | meaning |
| --- | --- | --- |
| `units` | list | one object per failed unit |
| `units[].unit` `.load` `.active` `.sub` `.description` | str | as systemctl reports them |
| `count` | int | number of failed units |
| `skipped` | int | array elements that could not be read |

### `journal.warnings`, `journal.errors`

Both use the same parser and emit the same fields. The only difference is the cap: 500 for
`journal.warnings` and 200 for `journal.errors`. When `capped` is true and one `by_unit` key
holds most of `count`, one unit is flooding the log.

Fields come from `journalctl -o json`, which encodes a field over its size threshold as
`null`, a repeated field as an array, and non-UTF-8 as an array of byte values. Every text field
below is coerced as follows:

- `null` becomes `""`.
- A byte array is decoded as UTF-8 with replacement.
- An array of values is decoded value by value and joined with `|`.
- Anything else is dropped to `""`.

An entry is skipped only when it is not a JSON object, or when its `__REALTIME_TIMESTAMP` or
`PRIORITY` is not a single integer.

| field | type | meaning |
| --- | --- | --- |
| `entries` | list | the newest 200 entries read, oldest first |
| `entries[].at` | float | `__REALTIME_TIMESTAMP`, epoch seconds |
| `entries[].unit` | str | `_SYSTEMD_UNIT`, `""` if absent (kernel messages have none); ≤128 chars |
| `entries[].identifier` | str | `SYSLOG_IDENTIFIER`, e.g. `kernel`; `""` if absent; ≤128 chars |
| `entries[].transport` | str | `_TRANSPORT`: `kernel`, `syslog`, `journal`, `stdout`…; ≤128 chars |
| `entries[].priority` | int | 0 emerg … 4 warning (0–3 only for `journal.errors`) |
| `entries[].message` | str | `MESSAGE`, redacted, then cut to 300 characters. Binary messages are decoded with replacement; a message over journald's size threshold is `""` |
| `count` | int | entries read successfully |
| `kept` | int | length of `entries` |
| `capped` | bool | `count + skipped` reached the probe's `-n` cap (500 or 200), so older entries in the window were not read |
| `by_unit` | object | str → int over **all** entries read. The key is `unit`, or `identifier` when `unit` is empty, or `"unknown"` |
| `by_priority` | object | `"0"`…`"4"` → int over all entries read (`"0"`…`"3"` for `journal.errors`) |
| `redacted` | int | secret-shaped strings cut from messages |
| `skipped` | int | entries that could not be read (see above) |
| `truncated` | bool | the output ended mid-line (cut at the executor's byte cap). The partial last line was dropped. journalctl prints oldest first, so the entries lost are the **newest** |

#### Not a probe: the Logs view's read

The dashboard's Logs view reads the journal too, but not through the agent or this catalog:
`neonwatch/logs.py`, in the unprivileged service, runs `journalctl -n 200 -o json
--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,__REALTIME_TIMESTAMP --no-pager
-q` only when the operator clicks "Load", as the service's user (group `adm`). Fields are coerced
as above; messages are redacted, then cut to 2000 characters; a line with no readable time or
priority is kept and shown as unknown. Each line gets a `key` (16 hex characters) over its masked
source and template, which keys the explanation cache. See "Logs view" in `docs/design.md`.

### `listeners`

| field | type | meaning |
| --- | --- | --- |
| `listeners` | list | one object per listening TCP or bound UDP socket, in ss order |
| `listeners[].proto` | str | `tcp` or `udp` |
| `listeners[].state` | str | `LISTEN` or `UNCONN` |
| `listeners[].address` | str | local address without brackets or scope: `0.0.0.0`, `::`, `*`, `127.0.0.1`, `::ffff:127.0.0.1` |
| `listeners[].interface` | str | scope or bound interface after `%`, e.g. `lo`; `""` if none |
| `listeners[].port` | int | local port |
| `listeners[].process` / `.pid` | str / int\|null | first owning process (≤128 chars), or `""` / `null` when ss cannot see it |
| `listeners[].wildcard` | bool | bound to all addresses (`0.0.0.0`, `::`, `*`, `::ffff:0.0.0.0`) |
| `listeners[].loopback` | bool | bound to a loopback address (v4, v6, or v4-mapped) |
| `count` / `wildcard_count` | int | sockets / sockets with `wildcard` true |
| `skipped` | int | ss lines that could not be read |

### `kernel.tainted`

| field | type | meaning |
| --- | --- | --- |
| `value` | int | the taint bitmask |
| `bits` | list[int] | the set bit numbers, ascending |
| `flags` | str | one letter per set bit, in bit order: `P F S R M B U D A W C I O E L K X T N` for bits 0–18, `?` above that. `M` machine check, `D` oops, `L` soft lockup, `W` warning, `O`/`E` out-of-tree/unsigned module |

### `containers`

| field | type | meaning |
| --- | --- | --- |
| `containers` | list | every container, including stopped ones |
| `containers[].id` | str | the first 12 hex characters of the id |
| `containers[].name` | str | name without its leading `/` |
| `containers[].image` | str | image reference |
| `containers[].state` | str | `running`, `restarting`, `exited`, `paused`, `created`, `dead` |
| `containers[].status` | str | Docker's human status, e.g. `Restarting (1) 57 seconds ago` |
| `containers[].health` | str | `healthy`, `unhealthy`, `starting`, or `""` when the container has no healthcheck |
| `containers[].exit_code` | int\|null | the code in `Exited (N)` or `Restarting (N)`; `null` otherwise |
| `containers[].created` | int | creation time, epoch seconds |
| `containers[].compose_project` | str | `com.docker.compose.project` label, or `""` |
| `count` | int | number of containers |
| `by_state` | object | state → count |
| `skipped` | int | array elements that could not be read |

The container's command line is not carried, because it can hold secrets. Restart counts are not
in this listing, and reading them would need a per-container path. A crash loop shows up as
`state == "restarting"` with an `exit_code`, or, when a container dies within a second and is
sampled between restarts, as the same `id` `running` with a `status` of `Up` under a minute in
two observations in a row.

### `edac`

| field | type | meaning |
| --- | --- | --- |
| `controllers` | list | one object per EDAC memory controller, sorted by name |
| `controllers[].mc` | str | controller directory, e.g. `mc0` |
| `controllers[].ce_count` / `.ue_count` | int | corrected / uncorrected error counts since boot |
| `ce_total` / `ue_total` | int | sums across controllers |
| `skipped` | int | controllers with a file that could not be read |

No controllers means no EDAC driver is loaded. That is not the same as zero errors.

### `block.devices`, `cron.d.names`, `cron.hourly.names`, `cron.daily.names`, `cron.weekly.names`, `cron.monthly.names`

| field | type | meaning |
| --- | --- | --- |
| `entries` | list[str] | directory entry names, sorted, hidden names included (block devices, cron files and scripts) |
| `count` | int | number of entries |
| `links` | object | entry name → target, for each entry that is a symbolic link: the link's own text from `readlink` (not followed, not resolved), redacted and cut to 300 characters |

### `smart.<device>`

| field | type | meaning |
| --- | --- | --- |
| `device` | str | device path, e.g. `/dev/nvme0n1` |
| `type` / `protocol` | str | smartctl device type (`nvme`, `sat`, `scsi`) / protocol (`NVMe`, `ATA`, `SCSI`) |
| `model` / `serial` / `firmware` | str | as reported, `""` if absent |
| `exit_status` | int | smartctl's exit bitmask. Bit 2 = a SMART command failed, 3 = disk failing, 4 = prefail attribute at threshold, 5 = usage attribute past threshold, 6 = error log has errors, 7 = self-test log has errors |
| `passed` | bool\|null | overall health self-assessment |
| `temperature_c` | int\|null | current temperature |
| `power_on_hours` / `power_cycles` | int\|null | lifetime counters |
| `critical_warning` | int\|null | NVMe critical warning bitmask (0 is healthy); `null` on non-NVMe |
| `available_spare_pct` / `available_spare_threshold_pct` | int\|null | NVMe spare capacity and its threshold |
| `percentage_used` | int\|null | NVMe endurance used, % (can exceed 100) |
| `media_errors` / `error_log_entries` / `unsafe_shutdowns` | int\|null | NVMe counters |
| `reallocated_sectors` | int\|null | ATA attribute 5 raw value; `null` on NVMe |
| `reported_uncorrect` | int\|null | ATA 187 raw |
| `pending_sectors` | int\|null | ATA 197 raw |
| `offline_uncorrectable` | int\|null | ATA 198 raw |
| `udma_crc_errors` | int\|null | ATA 199 raw (usually cabling) |
| `failing_attributes` | list[str] | ATA attribute names whose `when_failed` is `now` or `past` |
| `skipped` | int | ATA attribute rows that could not be read; the named fields above are `null` if their row was skipped |

If exit bit 0 or 1 is set (bad command line, or the device could not be opened), the output is a
`ParseError`, not a record of nulls.

### `firewall`

| field | type | meaning |
| --- | --- | --- |
| `hash` | str | sha256 hex of the ruleset with `metainfo` and every `handle` removed, as canonical JSON. It changes when the rules change, and it does not change when the same ruleset is reloaded |
| `version` | str | nftables version from `metainfo` |
| `tables` / `chains` / `rules` | int | counts |
| `sets` | int | named sets plus maps |
| `table_names` | list[str] | `"<family> <name>"`, in ruleset order |
| `base_chains` | list | the chains attached to a netfilter hook |
| `base_chains[].family` `.table` `.name` `.hook` `.type` `.policy` | str | as nft reports them; `type` and `policy` are `""` if absent |
| `base_chains[].priority` | int | hook priority |
| `base_chains[].rules` | int | rules directly in that chain |

### `kernel.modules`

| field | type | meaning |
| --- | --- | --- |
| `modules` | list[str] | loaded module names, sorted |
| `count` | int | number of modules |
| `tainting` | object | name → taint letters the module carries, e.g. `{"nvidia": "OE"}` |
| `not_live` | list[str] | modules whose state is not `Live` (loading or unloading) |
| `skipped` | int | lines that could not be read |

### `fs.protected_hardlinks`

| field | type | meaning |
| --- | --- | --- |
| `value` | int | the sysctl as the kernel reports it |
| `protected` | bool | `value == 1`: a user cannot hardlink a file they do not own |

The cron reads refuse a symlink and anything but a regular file, but a hardlink is a regular
file. That a user cannot hardlink `/etc/shadow` into a directory root reads rests on this
sysctl, so it is read rather than assumed.

### `reboot.required`

| field | type | meaning |
| --- | --- | --- |
| `required` | bool | `/var/run/reboot-required` exists |
| `packages` | list[str] | unique package names from `reboot-required.pkgs`, sorted |

### `ssh.keys.home`, `ssh.keys.root`

| field | type | meaning |
| --- | --- | --- |
| `files` | list | one object per matched file (`authorized_keys`, `authorized_keys2`…) |
| `files[].path` | str | absolute path |
| `files[].keys` | int | valid keys in the file |
| `files[].invalid_lines` | int | non-blank, non-comment lines that are not a readable key (sshd ignores them) |
| `files[].sha256` | str | sha256 hex of the file's text |
| `keys` | list | one object per valid key |
| `keys[].path` | str | the file it is in |
| `keys[].type` | str | e.g. `ssh-ed25519`, `ecdsa-sha2-nistp256`, `sk-ssh-ed25519@openssh.com` |
| `keys[].fingerprint` | str | `SHA256:<base64>`, identical to `ssh-keygen -l` |
| `keys[].comment` | str | trailing comment, `""` if none |
| `keys[].options` | bool | the line carries options before the key type, e.g. `command="…"` or `from=` |
| `count` | int | length of `keys` |

The key material itself is not carried. The fingerprint identifies the key.

### `units.files`

| field | type | meaning |
| --- | --- | --- |
| `units` | object | unit file name → state (`enabled`, `disabled`, `static`, `masked`, `generated`, `transient`, `alias`, `indirect`, `enabled-runtime`…) |
| `count` | int | number of unit files |
| `skipped` | int | array elements that could not be read |
| `by_state` | object | state → count |

### `units.timers`

| field | type | meaning |
| --- | --- | --- |
| `timers` | list | one object per loaded timer, inactive ones included (`--all`) |
| `timers[].unit` / `.activates` | str | the timer / the unit it starts |
| `timers[].next` / `.last` | float\|null | next and last trigger, epoch seconds; `null` for never or not scheduled |
| `count` | int | number of timers |
| `skipped` | int | array elements that could not be read |

### `cron.system`, `cron.d`, `cron.user`

`/etc/crontab` and `/etc/cron.d/*` have a user field; a spool crontab does not, and its owner is
its file name. Comments and blank lines are dropped. There is no line continuation, because cron
has none: a trailing backslash is part of the command.

What is kept is capped, so no user's own valid crontab can make the observation too large to
publish and blank every other user's. At most 100 entries per file, 500 per
observation and 32 env names per file are kept, and the kept entries and env values together
stay within half the event cap in JSON bytes. Counts alone would allow 500 commands of 1024
characters that each escape to 12 bytes. Root's spool file is read first, then files by path, so
no user can spend the caps before root's crontab is read. Whatever is not kept is counted.

| field | type | meaning |
| --- | --- | --- |
| `files` | list | one object per file read, sorted by path |
| `files[].path` | str | the file |
| `files[].env` | object | its `NAME=value` lines (`MAILTO`, `PATH`, `SHELL`…), values redacted and cut to 300 |
| `files[].env_dropped` | int | env lines not kept (over 32 names, or over the byte budget) |
| `files[].entries` | int | entries kept from this file |
| `files[].total` | int | entries this file held (lines read as jobs) |
| `files[].dropped` | int | `total - entries`: read but not kept |
| `files[].skipped` | int | job lines that could not be read |
| `entries` | list | one object per job line, in file order |
| `entries[].file` | str | the file it is in |
| `entries[].user` | str | the user field, or the spool file's name; cut to 128 |
| `entries[].schedule` | str | the five time fields joined by one space, or the `@word` |
| `entries[].command` | str | the command as written, redacted, cut to 1024 |
| `entries[].stdin` | bool | the command has an unescaped `%`: cron sends the rest as standard input |
| `count` | int | length of `entries` |
| `skipped` | int | job lines that could not be read: too few fields, a field cron would not read, an unknown `@word` |
| `dropped` | int | entries read but not kept, over all files |
| `redacted` | int | token shapes cut from commands and env values |

### `cron.anacron`

The same shape and caps as the crontabs, with these entries:

| field | type | meaning |
| --- | --- | --- |
| `entries[].file` | str | the anacrontab |
| `entries[].period` | str | days, or `@daily`/`@weekly`/`@monthly`/`@yearly`/`@annually`, as written |
| `entries[].delay` | int | minutes |
| `entries[].job_id` | str | anacron's job identifier, cut to 128 |
| `entries[].command` | str | redacted, cut to 1024 |

### `cron.hourly`, `cron.daily`, `cron.weekly`, `cron.monthly`

| field | type | meaning |
| --- | --- | --- |
| `scripts` | list | one object per script read, sorted by path |
| `scripts[].path` | str | the script |
| `scripts[].size` | int | bytes as read (UTF-8) |
| `scripts[].head` | str | the start of its text, redacted, at most 4096 characters |
| `scripts[].truncated` | bool | the script is longer than `head` |
| `count` | int | length of `scripts` |
| `redacted` | int | token shapes cut |

A script over the executor's per-file cap (`max_bytes // 4`, 256 KiB) is cut before it is
parsed. That cut shows in the observation's `truncated` flag and warnings, not here.

### `units.detail`

`systemctl show` prints one blank-line-separated block of `Key=value` lines per unit, in no fixed
order. `ExecStart`, `TimersCalendar` and `TimersMonotonic` repeat, one line per value. A block
with no `Id`, or a value in an unexpected form, is skipped and counted.

| field | type | meaning |
| --- | --- | --- |
| `units` | list | one object per service and timer, sorted by `id` |
| `units[].id` | str | the unit name |
| `units[].description` | str | cut to 300 |
| `units[].user` | str | `User=`; `""` when unset (a system service then runs as root) |
| `units[].exec` | list[str] | each `ExecStart` command line (`argv[]`), redacted, cut to 1024 |
| `units[].active` / `.sub` / `.result` | str | `ActiveState`, `SubState`, `Result` |
| `units[].restarts` | int\|null | `NRestarts`: automatic restarts; `null` for a timer |
| `units[].main_status` | int\|null | `ExecMainStatus`: the main process's last exit status |
| `units[].started` / `.exited` | float\|null | main process start and exit, epoch seconds; `null` for never |
| `units[].enabled` | str | `UnitFileState` |
| `units[].file` | str | `FragmentPath`, the unit file |
| `units[].triggers` / `.triggered_by` | list[str] | units this one starts / units that start it |
| `units[].calendar` | list[str] | a timer's `OnCalendar` specs |
| `units[].monotonic` | list[str] | a timer's intervals, as the unit file spells them: `OnBootSec=15min`, `OnUnitActiveSec=1d` |
| `units[].unit` | str | the unit a timer activates; `""` for a service |
| `count` | int | length of `units` |
| `skipped` | int | blocks that could not be read |
| `redacted` | int | token shapes cut from commands |

A timer's last and next trigger are not here: `units.timers` has them.
