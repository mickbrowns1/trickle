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

local sf = assert(io.open(set_path, "rb"))
local settings = decode(sf:read("*a"))
sf:close()
local config = settings.config or {}
local allowed = {}
for _, k in ipairs(settings.chkpt_keys or {}) do allowed[k] = true end
local MAX_REQUESTS = settings.max_requests or 50

-- checkpoints: keys must be registered, values must be strings
local store = {}
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

local chunk, err = loadfile(col_path)
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
send({ t = "done", requests = calls })
