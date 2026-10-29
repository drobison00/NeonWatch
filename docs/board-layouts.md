# Board layouts

The dashboard's **Board** view draws a top-down schematic of your motherboard and colours each
CPU, NVMe drive and GPU by its temperature against its own limit. The drawing comes from a TOML
layout file, chosen in the config:

```toml
[web]
board = "atx"                                   # a built-in layout (the default)
# board = "~/.config/neonwatch/board.toml"       # or your own file
```

The built-in `atx` is a generic ATX board: positions are typical, not your board's.
[`examples/boards/`](../examples/boards/) has a worked layout for a common board to copy from. A
layout is read once when the service starts, and a bad one stops the service with a message that
names the key at fault.

Most people will have an AI assistant write theirs. This page is written so that one can: the
steps, the exact rules for every key, a prompt to start from, and how to check the result.

## The steps

1. **Collect the facts** about your machine (below). None of these commands needs root.
2. **Give an assistant this page and those facts**, plus the board's manual if you have it (the
   page with the board layout drawing). The prompt below is a starting point.
3. **Put it in place** as `~/.config/neonwatch/board.toml`, and **check it** with the one-line
   validator under "Check it". Fix what it names, and run it again until it says OK.
4. **Set `[web] board`** to its path and restart `neonwatch service`. Open the Board view and
   compare it with your board: the validator checks the rules, not whether things are where your
   board has them.

### The facts to collect

```sh
cat /sys/class/dmi/id/board_vendor /sys/class/dmi/id/board_name     # which board
ls -l /sys/block/ | grep nvme                                        # each NVMe drive's PCI path
lspci -tv                                                            # what hangs off what
nvidia-smi --query-gpu=index,name,pci.bus_id,pcie.link.width.current,pcie.link.width.max \
  --format=csv                                                       # GPUs, if NVIDIA
sensors -j | grep -o '"\(Tctl\|Tdie\|Tccd[0-9]*\|Package id [0-9]*\)"' | sort -u   # CPU sensors
```

What each one settles:

- **The board name** tells the assistant which manual and which layout drawing to use.
- **A drive's PCI path** (`../devices/pci0000:00/0000:00:01.1/0000:01:00.0/nvme/…`) says where its
  lanes come from. Count the addresses of the form `0000:00:01.1`, not the leading
  `pci0000:00`. Two of them (a root port, then the drive) mean a CPU root port, so its slot is
  `attach = "cpu"`, with one exception: a root port on device `1b`, `1c` or `1d` of bus 0 (such
  as `0000:00:1c.4`) is Intel's chipset, so `attach = "chipset"`. Three or more addresses mean it
  sits behind a switch, almost always the chipset: `attach = "chipset"`. The last address is the drive's own, and it is what a drive's `pin`
  takes, exactly as written there (lower case, four-digit domain).
- **Slot names** are the manual's, as printed on the board (`M2_2`, `PCI_E3`). When a user says
  "the second M.2 slot", ask whether they mean the one labelled `M2_2` or the second from the top.
- **A GPU's current link width** decides which `pcie` slot it lands in: a card at x4 goes to the
  slot whose `lanes = 4`. Its `index` column is what a GPU's `pin` takes, as `gpu:<index>`; a GPU
  cannot be pinned by its bus id.
- **The CPU sensor labels** are what `[socket] die` entries may name. AMD Ryzen reports `Tctl`
  and `Tccd1`, `Tccd2`…, one per chiplet. Intel reports `Package id 0`.

### A prompt to start from

> Write a NeonWatch board layout TOML for my motherboard, following `docs/board-layouts.md`
> exactly (the rules table is authoritative). The board is *\<vendor and model\>*. Use its
> manual's layout drawing for positions in millimetres from the top-left corner, with the rear
> I/O on the left. Here is the output of the commands under "The facts to collect": *\<paste\>*.
> Name the slots as the manual does. Set each M.2 slot's `attach` from the PCI paths, and each
> PCIe slot's `lanes` from the manual's electrical widths. Check it with the validator under
> "Check it" and fix what it reports. Pin each drive to the slot it is
> physically in: *\<say which, if you know\>*. Give the CPU `die` entries only for sensor labels
> in the output above. Return only the TOML.

## Coordinates and drawing conventions

- **Origin and units.** Millimetres from the board's top-left corner, as seen from above with
  the rear I/O on the left. ATX is 244 wide and 305 tall; micro-ATX 244 x 244; mini-ITX 170 x
  170; E-ATX 305 x 330. Every rectangle is `x`, `y`, `w`, `h`.
- **Accuracy.** Close is enough. The caption says positions are approximate, and the drawing is
  for recognising your board, not for measuring it. Every rectangle must lie on the board
  (`x + w` at most `width`, `y + h` at most `height`); the GPU's overhang is drawn for you.
- **No manual?** Start from the built-in generic layout, `neonwatch/web/boards/atx.toml`, and move
  what you know. Expansion slots are 20.32 mm (0.8 in) apart on every ATX-family board, the
  first one about 133 mm from the top; M.2 slots usually lie between them or beside the socket.
  The vendor's product page lists each slot's electrical width and how lanes are shared, and
  `sudo dmidecode -t slot` lists the slots the firmware knows (the one step here that needs root,
  and optional).
- **PCIe slots** are thin strips: `h` about 6, `w` about 89 for a full-length (x16 or x8 physical)
  slot and about 26 for an x1 slot. A GPU is drawn by the page, not by you: it covers about 34 mm
  below its slot's top and runs off the board's right edge, so leave room for that.
- **M.2 slots** are the drive's footprint. The built-in layouts draw a 2280 drive as `w = 80`,
  `h = 11` (half its real 22 mm width, which keeps the slots beneath visible). Place it where the
  drive lies, including under a heatsink.
- **The socket** is the CPU's square. A die is a small rectangle *inside* it, in board
  coordinates, not relative to the socket. AMD AM4/AM5: about 40 x 40 mm, with one `Tccd` die
  per chiplet and the `Tctl` I/O die below them. Intel LGA1700/1851: about 37.5 x 45 mm, and one
  `Package id 0` die covering most of it. No dies at all is fine: the whole socket is then
  coloured by the hottest CPU reading.
- **Static parts** (`[[part]]`) are what helps you recognise the board: rear I/O, VRMs, the
  chipset, DIMM slots, power connectors, audio. Give `no_sensor` to a part that has no
  temperature reading here, and it is hatched with that explanation. Static parts never show a
  temperature; `no_sensor` is for the ones a reader would expect one on (the VRM, the chipset,
  DIMMs), so the drawing says why there is none.

## The rules, exactly

The file is read with a closed schema: an unknown key, a value outside its range or a missing
required key stops the service with a message naming the key.

| Where | Key | Required | Type and limits |
| --- | --- | --- | --- |
| top level | `name` | yes | string, at most 200 characters |
| top level | `width`, `height` | yes | number of mm, above 0, at most 600 |
| top level | `caption` | no | string, at most 200 characters |
| top level | `holes` | no | list of up to 200 `[x, y]` pairs, each 0 to 600 |
| top level | `traces` | no | list of up to 200 strings of SVG path data: only `M L H V Z`, their lower case, digits, spaces, `.`, `,` and `-`; at most 200 characters each |
| `[socket]` | `x`, `y` | yes | number of mm, 0 to 600 |
| `[socket]` | `w`, `h` | yes | number of mm, above 0, at most 600 |
| `[socket]` | `die` | no | list of up to 200 tables, each with `sensor` (a CPU sensor label: letters, digits, spaces, `_ . -`, at most 32) and `x`, `y`, `w`, `h` |
| `[[part]]` | `kind` | yes | one of `io`, `vrm`, `conn`, `audio`, `chipset`, `dimm`, `other` |
| `[[part]]` | `x`, `y`, `w`, `h` | yes | as for the socket |
| `[[part]]` | `label` | no | string, at most 200 characters |
| `[[part]]` | `label_at` | no | `[x, y]`: where the label goes; otherwise centred, and turned for a part much taller than wide |
| `[[part]]` | `no_sensor` | no | string, at most 200 characters: hatches the part and explains why |
| `[[slot]]` | `name` | yes | unique; letters, digits, `_ . -`, 1 to 24 characters |
| `[[slot]]` | `kind` | yes | `m2` or `pcie` |
| `[[slot]]` | `x`, `y`, `w`, `h` | yes | as for the socket |
| `[[slot]]` | `attach` | for `m2` | `"cpu"` or `"chipset"`. Allowed on `pcie` as a note; placement ignores it there |
| `[[slot]]` | `lanes` | for `pcie` | `1`, `2`, `4`, `8` or `16`: the slot's **electrical** width, not its length. Where the board shares lanes (a slot that drops to x2 when another is used), give the width it runs at on your machine |
| `[[slot]]` | `pin` | no | a drive: `"disk:nvme0n1"` or its PCI address like `"0000:05:00.0"`; a GPU: `"gpu:<index>"`. No two slots may pin the same thing |

There can be any number of `[[part]]` and `[[slot]]` tables, up to 200 each. A minimal valid
file is just `name`, `width`, `height` and a `[socket]`.

```toml
name = "My board"
width = 244
height = 305
caption = "My board: positions approximate."

[socket]
x = 74
y = 44
w = 44
h = 44
die = [{ sensor = "Tccd1", x = 79, y = 50, w = 16, h = 12 }]

[[part]]
kind = "chipset"
x = 168
y = 168
w = 52
h = 60
label = "chipset"
no_sensor = "This chipset reports no temperature to Linux."

[[slot]]
name = "M2_1"
kind = "m2"
attach = "cpu"
pin = "0000:01:00.0"
x = 46
y = 111
w = 80
h = 11

[[slot]]
name = "PCIE1"
kind = "pcie"
lanes = 16
x = 34
y = 133
w = 89
h = 6
```

## Check it

From the clone's root, as yourself:

```sh
.venv/bin/python -c 'import sys; from neonwatch.web import board
try: l = board.load(sys.argv[1])
except board.BoardError as bad: sys.exit(str(bad))
print(l["name"], "OK:", len(l["slots"]), "slots,", len(l["parts"]), "parts")' ~/.config/neonwatch/board.toml
```

It checks the rules above and that everything lies on the board. It does not check that
rectangles don't overlap (a GPU is drawn over its slot on purpose) or that they are where your
board has them: the Board view is the check for that. Give it the layout's path as its last
argument. On a valid file it prints
`My board OK: 2 slots, 1 parts` and exits 0. Otherwise it prints the first problem, after the
file's path, and exits 1. Some examples:

| It says | Meaning |
| --- | --- |
| `…: slot[2] is missing ['h']` | the third `[[slot]]` has no `h` |
| `…: part[0] has unknown key(s) ['colour']` | a key the schema doesn't have, often a typo |
| `…: slot[1]: a pcie slot needs lanes (its electrical width)` | add `lanes` |
| `…: slot[0]: an m2 slot needs attach ("cpu" or "chipset")` | add `attach` |
| `…: slot[3].name 'M2_1' is used by another slot` | slot names must be unique |
| `…: slot[1].lanes must be 1, 2, 4, 8 or 16` | the electrical width, as a number |
| `…: socket.die[0].sensor 'Tctl:' does not match …` | a sensor label with a character it can't have |
| `…: slot[4] (PCIE5) runs off the board: x + w = 270 is past width 244` | a coordinate or size past the board's edge |
| `…: slot[2].pin '00000000:0a:00.0' does not match …` | a GPU pinned by bus id; use `gpu:<index>` |

## How parts find their slots

Software can tell where a device's PCIe lanes come from, but not which physical slot it sits in.
So the service places each part like this, and the page marks a placement **assumed** when it
could not tell two slots apart:

- The **CPU** is drawn in the socket.
- An **NVMe drive** goes to a free `m2` slot with the same `attach`, worked out from its PCI path
  as under "The facts to collect". Drives go in PCI address
  order, into the slots in the order the file lists them. Assumed when more than one such slot
  was free.
- A **GPU** goes to a free `pcie` slot whose `lanes` equal its current link width (a card in a
  chipset x4 slot reports x4). Assumed when several slots match. Failing that, it takes the
  widest free slot, assumed.
- A part with nowhere to go is not drawn, and its detail panel says so. SATA drives are never
  placed (they have no M.2 footprint).

`pin` settles a placement, and wins over `attach`: a pinned drive goes to its slot whatever
that slot's `attach` says. It takes a part key (`disk:nvme0n1` or `gpu:1`) or a drive's PCI
address (`0000:05:00.0`, the stabler choice, since `nvme0n1` can change between boots). Pins are
applied first, and a pin that names no present part leaves its slot to the rules above. If the
Board view draws a drive in the wrong M.2 slot, pin it. If a GPU's link width matches no slot
(a shared slot running narrower than its `lanes`), it takes the widest free slot, marked
assumed; pin it with `gpu:<index>` to put it where it is.
