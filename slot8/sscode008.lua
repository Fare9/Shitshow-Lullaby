-- Slot 8: TCP REPL server (v13b) — remote command line into the Switch
-- Requires: Slot 7 (sscode007.lua) must run first to populate _G.n2h
-- Opens port 8080, accepts TCP connections, evaluates Lua over the wire
--
-- Deploy: JKSV save restore → save slot 8
-- Usage: run slot 7 first, then slot 8; connect with: nc <switch_ip> 8080

local h = _G.n2h
if not h then print("[!] n2h not available — run slot 7 first"); return end
collectgarbage("stop")

local SDK = h.sdk_base
local mb = h.alloc(16)
h.write_bytes(mb, "save\0")
local FS_COMMIT = SDK + 0x0a7f70

local ll = {}
local function L(m) ll[#ll + 1] = m; pcall(print, m) end
local function flush()
    local ok, f = pcall(io.open, "save:/s3log.txt", "w")
    if ok and f then
        f:write(table.concat(ll, "\n") .. "\n")
        f:close()
        pcall(function() h.call_deep(FS_COMMIT, mb, 0, 0, 0, 0) end)
    end
end

L("=== v13b REPL ===")
L(string.format("sdk=0x%x", SDK))
flush()

-- nifm + socket init
h.call_deep(SDK + 0x3a3100, 0, 0, 0, 0, 0)
h.call_deep(SDK + 0x3a4180, 0, 0, 0, 0, 0)
L("nifm ok")

local is_init = h.call_deep(SDK + 0x14d930, 0, 0, 0, 0, 0)
if not is_init or is_init == 0 then
    local raw = h.alloc(0x100000 + 0x4000)
    local pool = math.floor((raw + 0x3FFF) / 0x4000) * 0x4000
    local rc = h.call_deep(SDK + 0x14d960, pool, 0x100000, 0x20000, 8, 0)
    L(string.format("sock_init rc=%d", rc or -1))
end
flush()

local fd = h.call_deep(SDK + 0x14d4c0, 2, 1, 6, 0, 0)
local sa = h.alloc(16)
h.poke(sa, 0); h.poke(sa + 8, 0)
h.write_bytes(sa, string.char(
    0x10, 0x02, 0x1F, 0x90,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
))
local rc = h.call_deep(SDK + 0x14d3b0, fd, sa, 16, 0, 0)
if rc and rc < 0 then
    h.poke(sa, 0); h.poke(sa + 8, 0)
    h.write_bytes(sa, string.char(
        0x02, 0x00, 0x1F, 0x90,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ))
    h.call_deep(SDK + 0x14d3b0, fd, sa, 16, 0, 0)
end
h.call_deep(SDK + 0x14d440, fd, 5, 0, 0, 0)
L(">>> REPL on :8080 <<<")
flush()

local RBUF_SIZE = 1024
local recv_str = string.rep("\0", RBUF_SIZE)
local recv_ts = h.str_addr(recv_str)
local recv_data = recv_ts + 24
L(string.format("recv_buf ts=0x%x data=0x%x", recv_ts, recv_data))
flush()

local sbuf = h.alloc(2048)

while true do
    L("waiting...")
    flush()
    local cfd = h.call_deep(SDK + 0x14d380, fd, 0, 0, 0, 0)
    if cfd and cfd >= 0 then
        L(string.format("client fd=%d", cfd))

        local banner = "seedsow-repl v13b\n> "
        h.write_bytes(sbuf, banner)
        h.call_deep(SDK + 0x14d350, cfd, sbuf, #banner, 0, 0)

        local linebuf = ""
        local alive = true
        while alive do
            local n = h.call_deep(SDK + 0x14d300, cfd, recv_data, RBUF_SIZE, 0, 0)
            if not n or n == 0 or n > 0x7FFFFFFF then
                L("disconnect")
                alive = false
            else
                local data = recv_str:sub(1, n)
                linebuf = linebuf .. data

                while true do
                    local nl = linebuf:find("\n")
                    if not nl then break end
                    local line = linebuf:sub(1, nl - 1):gsub("\r", "")
                    linebuf = linebuf:sub(nl + 1)

                    if line == "exit" or line == "quit" then
                        local bye = "bye\n"
                        h.write_bytes(sbuf, bye)
                        h.call_deep(SDK + 0x14d350, cfd, sbuf, #bye, 0, 0)
                        alive = false
                        break
                    end

                    if line ~= "" then
                        L("exec: " .. line)
                        local fn, err = loadstring("return " .. line)
                        if not fn then fn, err = loadstring(line) end

                        local out
                        if fn then
                            local ok, res = pcall(fn)
                            if ok then
                                out = tostring(res) .. "\n"
                            else
                                out = "ERR: " .. tostring(res) .. "\n"
                            end
                        else
                            out = "PARSE: " .. tostring(err) .. "\n"
                        end

                        h.write_bytes(sbuf, out)
                        h.call_deep(SDK + 0x14d350, cfd, sbuf, #out, 0, 0)
                        L("  => " .. out:sub(1, -2))
                    end

                    local prompt = "> "
                    h.write_bytes(sbuf, prompt)
                    h.call_deep(SDK + 0x14d350, cfd, sbuf, #prompt, 0, 0)
                end
            end
        end

        h.call_deep(SDK + 0x14d510, cfd, 0, 0, 0, 0)
        L("closed")
        flush()
    end
end
