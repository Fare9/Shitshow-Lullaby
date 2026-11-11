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
- **Handle validity confirmed** — handles can be closed with svcCloseHandle (rc=0), proving they exist in the kernel handle table
- **Switch TIPC format discovered** via Binary Ninja: SM uses type = `0x10 + cmd_id` (not old type=0xF)
- **SVC stub addresses verified** on hardware by reading code bytes: SVC #0x21 at 0x168c4c, SVC #0x22 at 0x168c54

### Key Discoveries

#### Type Tag Corruption (poke/write_bytes)

`n2h.poke(addr, val)` writes a 16-byte TValue (8B value + 4B type tag 0x03 + 4B padding), corrupting bytes addr+8..addr+15. `write_bytes`/`wstr` iterates via poke in 4-byte chunks, so every chunk corrupts its +8..+11 bytes (only the LAST chunk's tag persists). This made all early IPC packets corrupt — discovered by dumping buffer bytes.

**Fix:** Build IPC packet as a Lua string (`string.char(...)`) and memcpy from the TString data region (`str_addr(s) + 24`). Zero type tag pollution. All subsequent tests use this clean method.

#### TLS Race Condition

Between separate `call_deep` calls (memcpy→TLS, then SVC#21), the game's own IPC activity can overwrite TLS. Confirmed by snapshotting TLS after memcpy vs after SVC — TLS showed game's SFCO response, not our packet.

**Fix:** Run memcpy→TLS + SVC + memcpy←response in a single Lua expression or `run_chain` for atomic execution. Clean-test uses single-expression approach.

#### SVC #0x22 Buffer Requirements

Kernel requires **page-aligned buffer** (0x1000) and **page-aligned size** (0x1000) for SVC #0x22. Size=256 returns 0xca01 (InvalidSize, desc=101). Fixed by allocating 0x2000 and aligning to 0x1000 boundary.

#### SM Handle is Shared

Closing the SM handle (0x101FE) via svcCloseHandle CRASHES the game. The SM session is shared by the game — never close it. Only close handles we ourselves obtained from GetServiceHandle.

### Definitive IPC Test Results (clean-test)

The `clean-test` command performs a comprehensive, controlled IPC test:
- Clean byte source (Lua string → memcpy, no poke/write_bytes)
- Fresh fsp-srv handle from GetServiceHandle
- Three IPC formats × two SVC paths = 6 tests
- Handle cleanup (svcCloseHandle) after all tests

#### Formats tested:

| Format | Word 0 | Word 1 | SFCI offset | Notes |
|--------|--------|--------|-------------|-------|
| CMIF aligned | 0x00000004 | 0x00000006 | 16 | Standard: 8B padding for 16-byte SFCI alignment |
| CMIF compact | 0x00000004 | 0x00000004 | 8 | No padding: SFCI immediately after HIPC header |
| TIPC | 0x000003F9 | 0x00000000 | N/A | type = 0x10 + 1001 = 0x3F9, raw data, no SFCI |

#### Results:

| Format | SVC #0x21 (TLS+SDK wrapper) | SVC #0x22 (page-aligned heap) |
|--------|---------------------------|-------------------------------|
| CMIF aligned (SFCI@16) | **0x25a0b** (= SDK's 0xF601) | **0xF601** |
| CMIF compact (SFCI@8) | **0x25a0b** (= SDK's 0xF601) | **0xF601** |
| TIPC (cmd=1001) | **0x25a0b** (= SDK's 0xF601) | **0xF601** |

**All 6 tests return 0xF601 (kernel module=1, desc=123, InvalidState).** Response buffers contain original packet bytes unchanged — the kernel rejects before forwarding to fsp-srv.

### Binary Ninja Analysis

Key findings from SDK NSO disassembly:

- **sub_14bb90** (runtime 0x14ba90): SDK IPC wrapper. Reads TPIDRRO_EL0, compares to buffer address. If same → SVC #0x21; if different → SVC #0x22. Also converts error 0xF601 → 0x25a0b
- **sub_14cd90** (runtime 0x14cc90): `nn::sm::detail::GetServiceHandle` — writes TIPC type=0x11, 2 data words = service name, to TLS, calls SVC #0x21 with SM handle
- **sub_14cc20** (runtime 0x14cb20): SM Init — writes type=0x10 (RegisterClient), send_pid=1

---

## Current Blocker

**Error 0xF601 (InvalidState) on ALL IPC formats to fsp-srv.**

The kernel rejects the message before it reaches the fsp-srv service process. Response buffers are unchanged (clean bytes confirmed). The handle is valid (close succeeds). GetServiceHandle itself works (it internally uses SVC #0x21 TIPC to SM).

### Root Cause Analysis

0xF601 = Horizon kernel error, module 1, description 123 (InvalidState). The kernel returns this from svcSendSyncRequest / svcSendSyncRequestWithUserBuffer when:

1. **Session not fully connected** — server hasn't called svcAcceptSession on its port end
2. **Server closed its end** — fsp-srv rejected the session after SM created the pair
3. **IPC message header malformed** — kernel can't parse the HIPC structure

Since we tested three completely different header formats (CMIF aligned, CMIF compact, TIPC) and all fail identically, option 3 is unlikely. **The session itself is in an invalid state.**

### Why the session might be broken

When we call GetServiceHandle("fsp-srv"), SM creates a session pair and returns our client handle. But fsp-srv must **accept** the session on its server port. If fsp-srv:
- Has hit its maximum session count (game already holds sessions)
- Rejects based on process-level checks
- Is slow to accept (race between SM return and our first IPC)

...the client handle exists (closeable) but the session is "pending" or "disconnected", and the kernel returns InvalidState.

---

## Hypotheses and Next Steps (Prioritized)

### Hypothesis A: Use the Game's Existing fsp-srv Session (Most Promising)

The game already has an initialized, working fsp-srv session (it loads saves, processes assets, etc.). Instead of obtaining a new session that might be rejected, **find and reuse the game's existing fsp-srv handle**.

Approaches:
1. **Scan BSS/data** for stored handle values — the SDK stores IFS* client handles in globals
2. **Handle brute-force** — iterate handles 1-64, for each: try svcGetInfo or check handle type via kernel
3. **Trace xrefs** in BN — follow nn::fs initialization to find where the fsp-srv handle is stored
4. **Read the game's IPC client objects** in memory — SDK IPC client structs contain the handle at a known offset

### Hypothesis B: SetCurrentProcess Initialization

fsp-srv requires `SetCurrentProcess` (cmd 1) with PID right after session creation. This is the standard initialization protocol for fsp-srv. Even if the session is connected, fsp-srv rejects commands without this handshake.

**BUT:** This is a chicken-and-egg problem — we can't send SetCurrentProcess if the kernel rejects the IPC before it reaches fsp-srv. This hypothesis only matters AFTER the kernel-level issue (0xF601) is resolved.

**Test (if kernel issue resolves):** Send CMIF cmd=1 with has_special_header=1, has_pid=1 before any other fsp-srv command.

### Hypothesis C: Memory Attributes (SVC #0x22 only)

`malloc` returns memory from nn::mem's allocator. The kernel might require specific memory attributes (set via svcSetMemoryAttribute) for SVC #0x22 user buffers.

**Test:** Call `svcQueryMemory` on malloc'd buffer vs TLS memory, compare type/permissions/attributes. Find the SDK's page allocator (nn::os::AllocateMemoryPages).

Note: This doesn't explain why SVC #0x21 (TLS) also fails — TLS memory should always have correct attributes.

### Hypothesis D: Domain Session Required

fsp-srv might require domain mode. The game's fsp-srv session likely had `ConvertCurrentObjectToDomain` called on it. New sessions from GetServiceHandle are plain sessions.

**Test:** Find `ConvertCurrentObjectToDomain` in BN, check if the game calls it on the fsp-srv handle path.

### Hypothesis E: Session Acceptance Race

GetServiceHandle returns before fsp-srv accepts the session on its server port. Adding a delay (or retry loop) between GetServiceHandle and the first IPC send might fix the timing issue.

**Test:** Add `os.execute("sleep 1")` (or a busy-loop) between GetServiceHandle and the first IPC call. Or retry the send 10 times with small delays.

### Alternative Path: civswitch-kit Techniques

civswitch-kit (different game, same console) successfully does IPC:
- Uses SDK's `getService` at offset 0x140510 (their SDK) — might do more initialization than bare GetServiceHandle
- Uses SVC #0x22 directly for CMIF
- Allocates page-aligned memory and verifies with `svcQueryMemory`
- Key difference: their `allocate` function ensures memory has proper attributes

Porting their approach requires finding our SDK's equivalent functions. Focus on what `getService` does beyond what `GetServiceHandle` does.

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
