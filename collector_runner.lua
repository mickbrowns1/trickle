-- collector_runner.lua: runs a DPM collector (start / fetch / emit / checkpoints) against Trickle's mock API.
--
-- Usage: luajit collector_runner.lua collector.lua settings.json
-- It talks to Trickle over stdin/stdout, one JSON object per line:
--   out: {"t":"req","n":1,"params":{...},"fn":"callback"}   a fetch{} request; Trickle answers on stdin with
--        {"status":200,"body":"...","headers":{...}}
--   out: {"t":"emit","log":{...}}  {"t":"log","level":"warn","msg":"..."}  {"t":"error",...}  {"t":"done",...}

local script_dir = (arg[0] or ""):match("^(.*)/[^/]*$") or "."
local col_path, set_path = arg[1], arg[2]

-- reuse the JSON encoder and decoder from lua_runner.lua so both runners agree
local f = assert(io.open(script_dir .. "/lua_runner.lua", "rb"))
local src = f:read("*a")
f:close()
local a = src:find("local NULL = io.stdout", 1, true)
local b = src:find("-- ------------------------------------------------------------ module stubs", 1, true)
assert(a and b, "lua_runner.lua layout changed")
local compile = loadstring or load
local loader = assert(compile(src:sub(a, b - 1) .. "\nreturn encode, decode, NULL", "json"))
local encode, decode, NULL = loader()

local function send(t)
  io.stdout:write(encode(t), "\n")
  io.stdout:flush()
end

package.loaded["json"] = { encode = encode, decode = decode, null = NULL }
local function logger(level)
  return function(m) send({ t = "log", level = level, msg = tostring(m) }) end
end
package.loaded["log"] = { debug = logger("debug"), info = logger("info"), warn = logger("warn"), error = logger("error") }

-- hmac and codec: pure Lua on LuaJIT's bit library, enough for signed APIs (HMAC-SHA1 and HMAC-SHA256).
-- Names other than the ones below raise a clear error, so a script never passes here on a guess that DPM would reject.
do
  local ok_bit, bit = pcall(require, "bit")
  local function unavailable() error("hmac and codec need LuaJIT (the bit library). Install it with: brew install luajit", 3) end
  local band, bor, bxor, bnot, lshift, rshift, rol, ror, tobit
  if ok_bit then
    band, bor, bxor, bnot, lshift, rshift, rol, ror, tobit = bit.band, bit.bor, bit.bxor, bit.bnot, bit.lshift, bit.rshift, bit.rol, bit.ror, bit.tobit
  end
  local function be32(n)
    return string.char(band(rshift(n, 24), 255), band(rshift(n, 16), 255), band(rshift(n, 8), 255), band(n, 255))
  end
  local function pad(msg)
    local len = #msg
    local bits = len * 8
    return msg .. "\128" .. string.rep("\0", (55 - len) % 64) .. be32(math.floor(bits / 4294967296)) .. be32(bits % 4294967296)
  end
  local function words(msg, chunk)
    local w = {}
    for i = 0, 15 do
      local a, b, c, d = msg:byte(chunk + i * 4, chunk + i * 4 + 3)
      w[i] = bor(lshift(a, 24), lshift(b, 16), lshift(c, 8), d)
    end
    return w
  end
  local function sha1(msg)
    local h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    msg = pad(msg)
    for chunk = 1, #msg, 64 do
      local w = words(msg, chunk)
      for i = 16, 79 do w[i] = rol(bxor(w[i - 3], w[i - 8], w[i - 14], w[i - 16]), 1) end
      local a, b, c, d, e = h0, h1, h2, h3, h4
      for i = 0, 79 do
        local f, k
        if i < 20 then f = bor(band(b, c), band(bnot(b), d)); k = 0x5A827999
        elseif i < 40 then f = bxor(b, c, d); k = 0x6ED9EBA1
        elseif i < 60 then f = bor(band(b, c), band(b, d), band(c, d)); k = 0x8F1BBCDC
        else f = bxor(b, c, d); k = 0xCA62C1D6 end
        local t = tobit(rol(a, 5) + f + e + k + w[i])
        e, d, c, b, a = d, c, rol(b, 30), a, t
      end
      h0, h1, h2, h3, h4 = tobit(h0 + a), tobit(h1 + b), tobit(h2 + c), tobit(h3 + d), tobit(h4 + e)
    end
    return be32(h0) .. be32(h1) .. be32(h2) .. be32(h3) .. be32(h4)
  end
  local K256, H256
  local function sha256(msg)
    if not K256 then
      local primes, n = {}, 2
      while #primes < 64 do
        local isp = true
        for _, p in ipairs(primes) do if p * p > n then break end; if n % p == 0 then isp = false; break end end
        if isp then primes[#primes + 1] = n end
        n = n + 1
      end
      K256, H256 = {}, {}
      for i = 1, 64 do K256[i] = tobit(math.floor((primes[i] ^ (1 / 3) % 1) * 4294967296)) end
      for i = 1, 8 do H256[i] = tobit(math.floor((primes[i] ^ 0.5 % 1) * 4294967296)) end
    end
    local h = { unpack(H256) }
    msg = pad(msg)
    for chunk = 1, #msg, 64 do
      local w = words(msg, chunk)
      for i = 16, 63 do
        local s0 = bxor(ror(w[i - 15], 7), ror(w[i - 15], 18), rshift(w[i - 15], 3))
        local s1 = bxor(ror(w[i - 2], 17), ror(w[i - 2], 19), rshift(w[i - 2], 10))
        w[i] = tobit(w[i - 16] + s0 + w[i - 7] + s1)
      end
      local a, b, c, d, e, f, g, hh = unpack(h)
      for i = 0, 63 do
        local S1 = bxor(ror(e, 6), ror(e, 11), ror(e, 25))
        local ch = bxor(band(e, f), band(bnot(e), g))
        local t1 = tobit(hh + S1 + ch + K256[i + 1] + w[i])
        local S0 = bxor(ror(a, 2), ror(a, 13), ror(a, 22))
        local maj = bxor(band(a, b), band(a, c), band(b, c))
        local t2 = tobit(S0 + maj)
        hh, g, f, e, d, c, b, a = g, f, e, tobit(d + t1), c, b, a, tobit(t1 + t2)
      end
      local v = { a, b, c, d, e, f, g, hh }
      for i = 1, 8 do h[i] = tobit(h[i] + v[i]) end
    end
    local out = {}
    for i = 1, 8 do out[i] = be32(h[i]) end
    return table.concat(out)
  end
  local function hmac_with(hash)
    return function(key, msg)
      if not ok_bit then unavailable() end
      key, msg = tostring(key or ""), tostring(msg or "")
      if #key > 64 then key = hash(key) end
      key = key .. string.rep("\0", 64 - #key)
      local ik, ok_ = {}, {}
      for i = 1, 64 do
        local c = key:byte(i)
        ik[i] = string.char(bxor(c, 0x36))
        ok_[i] = string.char(bxor(c, 0x5c))
      end
      return hash(table.concat(ok_) .. hash(table.concat(ik) .. msg))
    end
  end
  local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local function guarded(name, fns)
    return setmetatable(fns, { __index = function(_, k)
      local known = {}
      for n in pairs(fns) do known[#known + 1] = n end
      table.sort(known)
      error(name .. "." .. tostring(k) .. " is not available in Trickle. Known here: " .. table.concat(known, ", ") .. ". Check the DPM docs for the real name.", 2)
    end })
  end
  -- scol-std: in-memory token locks, same calls as the DPM module (try_acquire_token, renew_token, release_token)
  local locks = {}
  package.loaded["__trickle_locks"] = locks
  local counter = 0
  local function new_token() counter = counter + 1; return "tok-" .. counter .. "-" .. os.time() end
  package.loaded["scol-std"] = {
    lock = guarded("scol-std lock", {
      try_acquire_token = function(key, ttl)
        local cur = locks[key]
        if cur and cur.expires > os.time() then return false, nil end
        local tok = new_token()
        locks[key] = { token = tok, expires = os.time() + (tonumber(ttl) or 600) }
        return true, tok
      end,
      renew_token = function(key, token, ttl)
        local cur = locks[key]
        if not cur or cur.token ~= token then return false, nil end
        cur.token = new_token()
        cur.expires = os.time() + (tonumber(ttl) or 600)
        return true, cur.token
      end,
      release_token = function(key, token)
        local cur = locks[key]
        if cur and cur.token == token then locks[key] = nil; return true end
        return false
      end,
    }),
  }
  package.loaded["hmac"] = guarded("hmac", { sha1 = hmac_with(sha1), sha256 = hmac_with(sha256) })
  package.loaded["codec"] = guarded("codec", {
    hex_lower_encode = function(s) return (tostring(s):gsub(".", function(c) return string.format("%02x", c:byte()) end)) end,
    hex_upper_encode = function(s) return (tostring(s):gsub(".", function(c) return string.format("%02X", c:byte()) end)) end,
    base64_encode = function(data)
      data = tostring(data)
      local out = {}
      for i = 1, #data, 3 do
        local b1, b2, b3 = data:byte(i, i + 2)
        local n = b1 * 65536 + (b2 or 0) * 256 + (b3 or 0)
        local c1, c2, c3, c4 = math.floor(n / 262144) % 64, math.floor(n / 4096) % 64, math.floor(n / 64) % 64, n % 64
        out[#out + 1] = B64:sub(c1 + 1, c1 + 1) .. B64:sub(c2 + 1, c2 + 1) .. (b2 and B64:sub(c3 + 1, c3 + 1) or "=") .. (b3 and B64:sub(c4 + 1, c4 + 1) or "=")
      end
      return table.concat(out)
    end,
  })
end

local sf = assert(io.open(set_path, "rb"))
local settings = decode(sf:read("*a"))
sf:close()
local config = settings.config or {}
local allowed = {}
for _, k in ipairs(settings.chkpt_keys or {}) do allowed[k] = true end
local MAX_REQUESTS = settings.max_requests or 50

-- checkpoints: keys must be registered, values must be strings
local store = {}
for k, v in pairs(settings.chkpt_seed or {}) do
  if allowed[k] and type(v) == "string" then store[k] = v end
end
function set_chkpt(key, value)
  if not allowed[key] then error("NotFoundChkptId key: ComponentKey id: " .. tostring(key) .. " (register it under Checkpoint keys)", 2) end
  if type(value) ~= "string" then error("checkpoint values must be strings, got " .. type(value) .. " (json.encode structured data)", 2) end
  store[key] = value
end
function get_chkpt(key)
  if not allowed[key] then error("NotFoundChkptId key: ComponentKey id: " .. tostring(key) .. " (register it under Checkpoint keys)", 2) end
  return store[key]
end

local queue = {}
function fetch(spec)
  if type(spec) ~= "table" or type(spec.params) ~= "table" or type(spec.params.url) ~= "string" then
    error("fetch needs params.url", 2)
  end
  if type(spec.fn) ~= "string" then error("fetch needs fn = the name of the callback function", 2) end
  queue[#queue + 1] = spec
end

function emit(spec)
  if type(spec) ~= "table" or spec.log == nil then error("emit needs log = event_table", 2) end
  send({ t = "emit", log = spec.log })
end

-- The DPM config loader runs variable substitution over the whole source: $$ becomes one literal $ and any
-- $name is a required environment variable that is not set (rule 7). Mirror that so Entra style $$top works.
local cf = assert(io.open(col_path, "rb"))
local csrc = cf:read("*a")
cf:close()
local escaped = csrc:gsub("%$%$", "\1")
local missing = escaped:match("%$([%a_][%w_]*)")
if missing then
  send({ t = "fatal", error = "Invalid dataplane configuration: Missing environment variable in config. name = \"" .. missing .. "\" (a $name token anywhere in the Lua, comments included, is treated as an env var; write $$ for a literal $)" })
  os.exit(1)
end
local chunk, err = (loadstring or load)((escaped:gsub("\1", "$")), "=collector")
if not chunk then send({ t = "fatal", error = tostring(err) }); os.exit(1) end
local ok, e = pcall(chunk)
if not ok then send({ t = "fatal", error = tostring(e) }); os.exit(1) end
if type(start) ~= "function" then send({ t = "fatal", error = "the collector must define function start(config)" }); os.exit(1) end

ok, e = pcall(start, config)
if not ok then send({ t = "error", where = "start", error = tostring(e) }) end

local calls = 0
while #queue > 0 do
  if calls >= MAX_REQUESTS then
    send({ t = "error", where = "runner", error = "stopped after " .. MAX_REQUESTS .. " requests (a paging loop that never ends?)" })
    break
  end
  calls = calls + 1
  local req = table.remove(queue, 1)
  send({ t = "req", n = calls, params = req.params, fn = req.fn })
  local line = io.read("*l")
  if not line then break end
  local resp = decode(line)
  resp.headers = resp.headers or {}
  local cb = _G[req.fn]
  if type(cb) ~= "function" then
    send({ t = "error", where = req.fn, error = "callback function is not defined: " .. req.fn })
  else
    local cok, cerr = pcall(cb, config, resp, req.context or {})
    if not cok then send({ t = "error", where = req.fn, error = tostring(cerr) }) end
  end
end
for key, cur in pairs(package.loaded["__trickle_locks"] or {}) do
  send({ t = "log", level = "warn", msg = "lock " .. key .. " was still held when the run ended: a path that returns without release_token stalls that stream until the TTL expires" })
end
send({ t = "done", requests = calls })
