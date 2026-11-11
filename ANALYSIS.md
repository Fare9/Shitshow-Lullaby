# Seedsow Lullaby — Exploit Research Analysis

**Target:** Seedsow Lullaby Demo (Title ID `0x010042D022AEA000`)
**Engine:** Artemis (by mikage), embedding Lua 5.1 + luaponte + pluto
**Platform:** Nintendo Switch (tested on Switch 1; binary from Switch 1 demo)
**Goal:** Full filesystem access via `fsp-srv` IPC, eventually reaching the `Path::Normalize` heap overflow used by ns2jb

---

## Credits and Acknowledgments

This project builds on an enormous amount of prior work. None of this would be possible without the people who came before.

### Core Exploit Chain

- **[pepsipu](https://pepsipu.com)** — Created **ns2jb**, the original Switch 2 software-only jailbreak: the `Path::Normalize` heap overflow in `fs`, the race engine, and the [write-up](https://pepsipu.com/blog/2026-10-switch2-jailbreak-ns2jb/). The end goal of this entire project is to reach that same `fs` overflow from a different entry point. ([upstream](https://gitlab.com/pepsipu/ns2jb))
- **[kurumuz](https://gitlab.com/kurumuz)** — Maintained the ns2jb fork this ecosystem ships by default: memory-layout fixes, reliability improvements, and the five-argument bootstrap. ([upstream](https://gitlab.com/kurumuz/ns2jb))
- **[alula](https://github.com/alula)** — Created **seedsowhax**, the Lua sandbox escape that provides the `n2h` native R/W primitives used in Slot 7. This is the Stage 2 engine that makes everything else possible.

### Tooling and Infrastructure

- **[Seedsow Lua Editor contributors](https://github.com/)** (DiallingSpoon527 et al.) — The Lua text editor injected via BOWS save modification. Without this, there is no way to run custom Lua inside Seedsow. Licensed 0BSD. ([repo](https://github.com/))
- **[dougchansan](https://github.com/)** — Created **ns2-savekit**, the tool for reading, backing up, and restoring save data on any Switch 2 title over a live ns2jb session, plus the Artemis save retargeting that makes the "save launch" flow work. Licensed MIT.
- **[Luminger](https://github.com/Luminger)** — Created **balatro-switch-rce**: the JankFFI dispatch chain and BC_FUNCC hijack technique for LuaJIT on Switch. The Gravity Circuit RCE work (which informed early approaches here) is entirely based on their architecture.

### Reference Implementations (IPC)

- **[slapah](https://github.com/slapah)** — Ported ns2jb Stage 2 engine to **CivSwitch** (Civilization VII entry point). Their IPC implementation in `civswitch-kit` was a critical reference for understanding SVC #0x22 dispatch and CMIF packet structure.
- **[mza1010](https://gitee.com/mza1010)** — Maintained **civswitch-kit**, the packaged CivSwitch port with 8 patches on top of slapah's work. Their session.cjs (page-aligned memory + SDK `allocate`) directly informed Hypothesis A. Licensed GPL-2.0.
- **[byizmysh / IZ2S Platform](https://github.com/byizmysh/IZ2S-Platform)** — The IZCIVSwitch launcher and panel used for CivSwitch deployment and testing.

### Broader Community

- **[Netflix-N-Hack](https://github.com/NetflixNHack/Netflix-N-Hack)** and **[ufm42](https://github.com/ufm42)** — The JS exploit core referenced by CivSwitch.
- **[Element2424](https://github.com/Element2424)** — Pico-Switch-Controller, basis for PicoSwitch firmware in CivSwitch.
- **Switch2Brew** community — Homebrew launcher and platform documentation.
- **Switchbrew wiki** — IPC protocol documentation, sysmodule specs, and SVC reference.

### Tools Used in Analysis

- **Binary Ninja** — Static analysis of SDK NSO and main executable
- **Unicorn Engine** — aarch64 emulation harness for offline testing of Lua VM primitives
- **JKSV** — Save data management on console

---

## Table of Contents

1. [Credits and Acknowledgments](#credits-and-acknowledgments)
2. [Exploit Architecture](#exploit-architecture)
3. [What Each File Does](#what-each-file-does)
4. [n2h API Reference](#n2h-api-reference)
5. [How the Exploit Works — Stage by Stage](#how-the-exploit-works)
6. [IPC Research — What Was Tried](#ipc-research)
7. [Current Blocker](#current-blocker)
8. [Hypotheses and Next Steps](#hypotheses-and-next-steps)
9. [Reference: SDK Offsets](#reference-sdk-offsets)
10. [Reference: Earlier Exploit Stages (Lua-only)](#reference-earlier-stages)

---

## Exploit Architecture

```
┌─────────────────────────────────────────────────────┐
│  Switch Hardware                                    │
│  ┌───────────────────────────────────────────────┐  │
│  │  Seedsow Lullaby (Artemis Engine)             │  │
│  │  ┌─────────────┐  ┌──────────────────────────┐│  │
│  │  │ Slot 7      │  │ Slot 8                   ││  │
│  │  │ seedsowhax  │→ │ TCP REPL :8080           ││  │
│  │  │ Stage 2     │  │ Accepts Lua commands     ││  │
│  │  │ → _G.n2h    │  │ Uses n2h for native exec ││  │
│  │  └─────────────┘  └──────────┬───────────────┘│  │
│  └──────────────────────────────┼────────────────┘  │
│                                 │ TCP               │
└─────────────────────────────────┼───────────────────┘
                                  │
┌─────────────────────────────────┼───────────────────┐
│  PC                             │                   │
│  seedsow_repl.py ───────────────┘                   │
│  Sends Lua code → gets results                      │
│  IPC attack commands (sdk-get, test-ipc, etc.)      │
└─────────────────────────────────────────────────────┘
```

**Deployment flow:**
1. Build the modified save via seedsow-lua-editor (BOWS format)
2. Place `sscode007.lua` (slot 7) and `sscode008.lua` (slot 8) in the save
3. JKSV restore the save to the Switch
4. In-game: run slot 7 (installs n2h), then slot 8 (starts REPL)
5. From PC: `python3 seedsow_repl.py <switch_ip> <command>`

---

## What Each File Does

### deploy/slot7/sscode007.lua — Stage 2 Exploit

The core exploit that achieves native code execution from the Lua sandbox.

**Technique:** Uses hand-crafted Lua 5.1 bytecodes (`HELPER_READ` / `HELPER_WRITE`) loaded via `loadstring()` to manipulate hash table node pointers, achieving arbitrary 8-byte read/write. Then:

1. **addrof()** — `tostring(obj)` → parse hex address from `"table: 0xNNN"`
2. **f2i/i2f** — Encode integers as IEEE 754 denormalized doubles (`x * 2^-1074`)
3. **prim(target)** — Create a 2-entry hash table whose node layout places `target` at a controlled offset
4. **r64/w64** — Arbitrary read/write via HELPER_READ/HELPER_WRITE bytecodes that exploit hash table node manipulation
5. **Module base leak** — Read the `lua_CFunction` pointer from a `coroutine.wrap` CClosure (+0x20), subtract known offset → main_base. GOT read for `math.acos` → sdk_base
6. **ROP chain** — Corrupt `lua_State.errorJmp` to point to a forged `lua_longjmp` struct. When `error()` fires, `longjmp` jumps to our ROP chain in a scratch string's data area
7. **call_deep** — Allocates a 128KB deep stack, runs ROP chain at the top, lets SDK functions use the lower portion as their call stack

**Output:** Populates `_G.n2h` with all primitives.

### deploy/slot8/sscode008.lua — TCP REPL Server

Opens a TCP socket on port 8080 using the nn::socket SDK functions. Accepts connections and evaluates Lua code line-by-line, returning results.

**Key tricks:**
- Uses `h.str_addr()` to get the TString* of a Lua string, then `nn::socket::Recv` writes directly into the string's data buffer at TString+24, bypassing Lua's immutable string semantics
- Send buffer is a heap allocation written via `h.write_bytes()`
- Logs to `save:/s3log.txt` and commits via `nn::fs::CommitSaveData`

### deploy/pc/seedsow_repl.py — PC Analysis Client

Consolidates all the REPL attack scripts into one. Commands:

| Command | Description |
|---------|-------------|
| `shell` | Interactive Lua REPL |
| `diag` | Verify primitives (read, write, call_deep, run_chain) |
| `sdk-get [name]` | Get a service handle via `nn::sm::detail::GetServiceHandle` |
| `test-ipc` | Get fsp-srv handle + send CMIF test packet |
| `test-svc22` | Direct SVC #0x22 test bypassing SDK wrapper |
| `fsp-init <h>` | Send SetCurrentProcess (cmd=1) to fsp-srv |
| `fsp-probe <h>` | Probe fsp-srv CMIF commands |
| `full` | Complete chain: get handle → init → probe |

---

## n2h API Reference

After slot 7 runs, `_G.n2h` provides:

| Function | Signature | Description |
|----------|-----------|-------------|
| `peek(addr)` | `addr → number\|nil` | Read 8 bytes (destructive: sets tt=3 at addr+8) |
| `poke(addr, val)` | `addr, val →` | Write 8 bytes + 4-byte type tag at addr+8 (corrupts bytes 8-15!) |
| `write_bytes(addr, s)` | `addr, string →` | Write raw bytes in 4-byte LE chunks via poke |
| `str_addr(s)` | `string → TString*` | Get heap address of a Lua string's GCObject |
| `alloc(size)` | `size → addr` | malloc from the main exe's allocator |
| `free(ptr)` | `addr →` | free |
| `call_deep(target, a0-a4)` | `addr, args → x0` | Call any native function with up to 5 args + 128KB stack |
| `run_chain(emit)` | `fn(E) →` | Run a multi-operation ROP chain (E has :call3, :call_native, :peek) |
| `new_emitter(...)` | | Create a ROP chain emitter for custom chains |
| `addrof(obj)` | `obj → addr` | Get heap address of any GC object |
| `sdk(name)` | `string → addr` | Resolve SDK offset to runtime address |

**Important limitations:**
- `peek/poke` work through Lua table hash manipulation → only reaches **heap memory**, not TLS
- `poke` writes a 16-byte TValue (8B value + 4B type tag + 4B padding), corrupting addr+8 through addr+15
- `call_deep` returns x0 as a Lua number via `i2f()` — values with exponent bits ≠ 0 overflow (e.g., "fsp-srv" bytes read back wrong)

---

## How the Exploit Works

### Stage 1: Save File Modification (seedsow-lua-editor)

The Artemis engine stores game progress in BOWS-format save files. Each save contains a script pointer to an ASB (Artemis Script Binary). The editor:
1. Redirects the script pointer from `system/script.asb` → `save:/sed01.asb`
2. The custom ASB uses `lua`/`calllua` commands to bootstrap a Lua text editor
3. Code slots (sscode007.lua, sscode008.lua) are stored in the save and executed on demand

### Stage 2: Lua Sandbox Escape (seedsowhax by alula)

**bytecode helpers:** HELPER_READ and HELPER_WRITE are pre-compiled Lua 5.1 bytecodes (not source). They exploit the Lua VM's hash table implementation:
- Create tables with exactly 2 entries keyed by denormalized doubles
- The hash function maps these keys to specific node slots
- Reading/writing the node's value field at a computed offset achieves arb R/W

**ROP mechanism:**
1. Create a coroutine (fresh `lua_State`)
2. Read its `errorJmp` pointer (the longjmp buffer used by `pcall`)
3. Capture the full jmp_buf register set
4. Build a forged `lua_longjmp` in the scratch string's data area
5. Write ROP frames: `g_load_x19` → `g_call3_void` / `call_native` → `longjmp` (restore)
6. Overwrite the coroutine's `errorJmp` to point to our forged struct
7. Trigger `error("meow")` → longjmp fires → lands in our ROP chain
8. Chain epilogue restores original jmp_buf → Lua resumes normally

### Stage 3: TCP REPL + IPC

The REPL provides remote access. From PC, the Python script sends Lua code that invokes `n2h` functions to:
1. **Get service handles** via `nn::sm::detail::GetServiceHandle` (SDK function at +0x14cc90)
2. **Send IPC packets** to those handles
3. **Eventually:** filesystem operations via `fsp-srv`

---

## IPC Research

### What Works

- **SM handle confirmed** at SDK+0xb5459c, value typically 0x101FE, init_count=24
- **SDK's GetServiceHandle** works reliably via `call_deep(SDK+0x14cc90, out, name, len)` — returns valid fsp-srv handles every time
- **Handle validation confirmed** — SVC returns desc=123 (not desc=114 InvalidHandle), proving the handle exists
- **Switch TIPC format discovered** via Binary Ninja: SM uses type = `0x10 + cmd_id` (not old type=0xF)
- **TLS race condition solved** — combining memcpy→TLS + SVC + memcpy←TLS in a single Lua expression prevents game thread interference

### What Was Tried and Failed

| Attempt | Method | Result |
|---------|--------|--------|
| CMIF via SVC #0x21 (TLS) | memcpy packet to TLS, svcSendSyncRequest | **0xF601** (desc=123). Packet in response was our SFCI unchanged. Kernel rejects CMIF type=4 via SVC #0x21 on this firmware |
| CMIF via SDK wrapper (sub_14bb90) | SDK dispatches to SVC #0x22 for heap buffers | **0x25a0b** (SDK's transform of 0xF601). Same transport rejection |
| CMIF via direct SVC #0x22 | Page-aligned malloc buffer, direct SVC call | **0xF601**. Kernel still rejects |
| CMIF data word count = 8 | Match civswitch's `ceil((32+0)/4)` | Same error |
| CMIF data word count = 10 | Original calculation | Same error |

### Binary Ninja Analysis

Key findings from SDK NSO disassembly:

- **sub_14bb90** (runtime 0x14ba90): SDK IPC wrapper. Reads TPIDRRO_EL0, compares to buffer address. If same → SVC #0x21; if different → SVC #0x22. Also converts error 0xF601 → 0x25a0b
- **sub_14cd90** (runtime 0x14cc90): `nn::sm::detail::GetServiceHandle` — writes TIPC type=0x11, 2 data words = service name, to TLS, calls SVC #0x21 with SM handle
- **sub_14cc20** (runtime 0x14cb20): SM Init — writes type=0x10 (RegisterClient), send_pid=1

---

## Current Blocker

**Both SVC #0x21 and SVC #0x22 return 0xF601 for CMIF (type=4) packets sent to fsp-srv.**

The kernel rejects the message at the transport level — the response buffer shows the original packet unchanged (no processing occurred).

The fsp-srv handle is valid (confirmed by error code). The issue is specifically with **sending CMIF-format IPC messages** to it.

---

## Hypotheses and Next Steps

### Hypothesis A: Memory Attributes

`malloc` returns memory from nn::mem's allocator. civswitch uses `nn::os::AllocateMemoryPages` (verified via `svcQueryMemory` to be type=5, permissions=3, no special attributes). Our malloc might return memory with different kernel attributes that SVC #0x22 rejects.

**Test:** Call `svcQueryMemory` on the malloc'd IPC buffer and compare attributes to TLS memory. Or find the SDK's page allocator and use it instead.

### Hypothesis B: Session Type Mismatch

The fsp-srv handle obtained via `GetServiceHandle` might be a different session type than what the game uses internally. On newer firmware, service sessions might need additional initialization (domain conversion, etc.) before accepting CMIF.

**Test:** Use BN to trace how the game's own fsp-srv calls set up and use IPC. Look at xrefs to sub_14bb90 to see how legitimate callers prepare buffers.

### Hypothesis C: CMIF Needs TIPC Wrapping

On this firmware, ALL service IPC might need the new TIPC format. The SM examples prove TIPC works (type=0x10+cmd). fsp-srv might need TIPC-wrapped CMIF or pure TIPC.

**Test:** Try sending TIPC format (type=0x10+cmd) to fsp-srv directly, with the CMIF command ID in the TIPC type field.

### Hypothesis D: Domain Session Required

The game's fsp-srv session might be a domain session (ConvertCurrentObjectToDomain was called). New handles from GetServiceHandle are plain sessions. Need to check if fsp-srv requires domain-mode IPC.

**Test:** Look for `ConvertCurrentObjectToDomain` in BN, check if it's called on the fsp-srv handle path.

### Hypothesis E: Use the Game's Existing fsp-srv Handle

Instead of getting a new handle, find the game's already-initialized fsp-srv session in memory. The game already does FS operations through it. Brute-force handles 1-64 sending CMIF GetGlobalAccessLogMode (cmd 1006) — only fsp-srv would respond with SFCO.

**Test:** Already attempted in stage3_fspsrv_overflow.lua (Method 3). But that used SVC #0x21 which fails for CMIF. Try the same scan but via SVC #0x22 with proper buffer.

### Alternative Path: civswitch-kit Techniques

civswitch-kit (different game, same console) successfully does IPC:
- Uses SDK's `getService` at offset 0x140510 (their SDK)
- Uses SVC #0x22 directly for CMIF
- Allocates page-aligned memory and verifies with `svcQueryMemory`
- Key difference: their `allocate` function ensures memory has proper attributes

Porting their approach requires finding our SDK's equivalent `allocate` function.

### Nuclear Option: Bundled Library CVEs

If IPC remains blocked, target the game's bundled 2016-era libraries:
- **zlib 1.2.8** — CVE-2016-9840..9843
- **libpng 1.6.21** — CVE-2018-13785, CVE-2019-7317
- **FreeType ~2016** — extensive CVE surface (best target if reachable from Lua)
- **libjpeg 9b** — multiple CVEs

These would need to be triggered through engine commands that process attacker-controlled image/font/compressed data.

---

## Reference: SDK Offsets

All offsets are relative to SDK NSO base. BN address = runtime offset + 0x100.

```
nn::sm::detail::GetServiceHandle    0x14cc90
nn::sm::detail::Initialize          0x14cb20
SDK IPC send wrapper                0x14ba90
MRS TPIDRRO_EL0; RET                0x14ba80
SVC #0x21 (svcSendSyncRequest)      0x168c4c
SVC #0x22 (svcSendSyncRequestUB)    0x168c54
SVC #0x16 (svcCloseHandle)          0x168be4
SVC #0x29 (svcGetInfo)              0x168ca4
SM handle (.bss)                    0xb5459c
SM init count (.bss)                0xb54598
nn::fs::CommitSaveData              0x0a7f70
nn::os::GetThreadId (read gadget)   0x1371f0
vcall8_restore                      0x3d9e54
longjmp                             0x5511b4
nn::socket::* (Initialize, Socket, Bind, Listen, Accept, Recv, Send, Close)
  at 0x14d960, 0x14d4c0, 0x14d3b0, 0x14d440, 0x14d380, 0x14d300, 0x14d350, 0x14d510
memcpy (main PLT)                   0x262480
malloc (main PLT)                   0x262160
free (main PLT)                     0x2621b0
```

---

## Reference: Earlier Stages (Lua-only)

These stages were explored before seedsowhax was available. They are documented in CLAUDE.md and are superseded by the current approach.

| Stage | Technique | Status |
|-------|-----------|--------|
| Pluto bytecode bypass | `pluto.unpersist` loads full function prototypes bypassing `loadstring` parser check | Confirmed (hw) |
| Blob binary patching | Patch pluto blob type tag 03→02 for lightuserdata pointer fabrication | Confirmed (hw) |
| Bytecode injection | Replace Proto instruction block in pluto blob | Confirmed (hw) |
| OOB register R/W | Patch maxstacksize in blob, MOVE/GETUPVAL beyond frame | Confirmed (hw) |
| Pluto case 6 raw userdata | Tag 7 flag=0 creates userdata with controlled content | Confirmed (hw) |
| Heap feng shui | Coroutine 720B stack spray, cross-coroutine OOB R/W | Confirmed (hw) |
| Carrier userdata (Path F) | 680B userdata with forged TValue for type confusion | Planned (v0.26) |
| Direct fs path overflow | Paths >769B through engine functions | Failed — SDK normalizes before IPC |
| Bytecode loading | `loadstring(bytecode)` | Blocked — parser checks 0x1b magic byte |
| string.format overflow | Width/precision exploitation | Patched |
| io.popen | Shell access | Stubbed ("not supported") |

The Lua-only path (stages 0-1 in CLAUDE.md) would achieve the same goal via a different route: type confusion through carrier userdata → fake Table/TString → arbitrary R/W → CClosure overwrite → native exec. seedsowhax bypasses all of that by using `loadstring(bytecodes)` directly.
