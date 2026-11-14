-- NginxionS: File Security of a practice of the WAF policy (docs/WAF-POLICY.md): the body of an upload (POST, PUT,
-- PATCH) is streamed to clamd of the clamav container (INSTREAM) before the request goes on. A virus is refused (403,
-- the block page) or only logged, by the confidence of its signature and the actions of the practice; the
-- findings are written to /data/nginx/logs/nginxions-files.log, read into the security events (waf/files.js).
-- The rules per host come from /data/nginxions/files-security.json (waf/files.js), read once per worker: nginx
-- is reloaded when they change. Called by the access_by_lua_block of _common.conf of a host that has File Security.
local cjson = require "cjson.safe"

local M = {}

local CONF_FILE = "/data/nginxions/files-security.json"
local LOG_FILE = "/data/nginx/logs/nginxions-files.log"
local CHUNK = 65536

local conf = nil
local log_handle = nil

local function load()
  local f = io.open(CONF_FILE, "r")
  if not f then return { hosts = {} } end
  local text = f:read("*a")
  f:close()
  local data = cjson.decode(text)
  if type(data) ~= "table" or type(data.hosts) ~= "table" then
    ngx.log(ngx.ERR, "[NginxionS files] ", CONF_FILE, " is not valid")
    return { hosts = {} }
  end
  return data
end

--- the rule of the request: the longest path prefix among the rules of the host
local function rule_of(rules, uri)
  local best, best_len = nil, -1
  for _, r in ipairs(rules) do
    local p = r.path or ""
    if (p == "" or uri:sub(1, #p) == p) and #p > best_len then
      best, best_len = r, #p
    end
  end
  return best
end

--- confidence of a signature of ClamAV: potentially unwanted programs medium, heuristics low, the rest high
local function confidence_of(name)
  if name:match("^PUA%.") then return "medium" end
  if name:match("^Heuristics%.") or name:match("%.Heuristic") then return "low" end
  return "high"
end

local function log_event(event)
  if not log_handle then
    log_handle = io.open(LOG_FILE, "a")
    if not log_handle then
      ngx.log(ngx.ERR, "[NginxionS files] cannot open ", LOG_FILE)
      return
    end
    log_handle:setvbuf("line")
  end
  event.time = ngx.utctime():gsub(" ", "T") .. "Z"
  event.ip = ngx.var.remote_addr
  event.host = ngx.var.host
  event.method = ngx.req.get_method()
  event.uri = ngx.var.request_uri
  event.ua = ngx.var.http_user_agent
  local line = cjson.encode(event)
  if line then log_handle:write(line, "\n") end
end

--- the body as chunks: from memory or from the temporary file of nginx
local function body_reader()
  local data = ngx.req.get_body_data()
  if data then
    local sent = false
    return function()
      if sent then return nil end
      sent = true
      return data
    end, #data
  end
  local name = ngx.req.get_body_file()
  if not name then return nil, 0 end
  local f = io.open(name, "rb")
  if not f then return nil, 0 end
  local size = f:seek("end")
  f:seek("set", 0)
  return function()
    local chunk = f:read(CHUNK)
    if not chunk then f:close() end
    return chunk
  end, size
end

local function u32be(n)
  return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

--- the verdict of clamd on the body: "OK", the name of a signature, or nil and an error
local function scan(reader, rule)
  local sock = ngx.socket.tcp()
  sock:settimeouts(rule.connect_ms or 2000, rule.send_ms or 30000, rule.read_ms or 30000)
  local ok, err = sock:connect(rule.clamd_host or "clamav", rule.clamd_port or 3310)
  if not ok then return nil, "clamd unreachable: " .. tostring(err) end
  local sent, serr = sock:send("zINSTREAM\0")
  if not sent then sock:close() return nil, serr end
  while true do
    local chunk = reader()
    if not chunk then break end
    -- clamd takes chunks up to its StreamMaxLength in total; a chunk is a 4-byte length and the data
    local pos = 1
    while pos <= #chunk do
      local part = chunk:sub(pos, pos + CHUNK - 1)
      sent, serr = sock:send({ u32be(#part), part })
      if not sent then sock:close() return nil, serr end
      pos = pos + CHUNK
    end
  end
  sent, serr = sock:send(u32be(0))
  if not sent then sock:close() return nil, serr end
  local reply, rerr = sock:receive("*a")
  sock:close()
  if not reply then return nil, rerr end
  reply = reply:gsub("%z", "")
  if reply:match("OK$") then return "OK" end
  local virus = reply:match("^stream: (.+) FOUND$")
  if virus then return virus end
  if reply:match("size limit exceeded") then return nil, "size limit" end
  return nil, reply
end

local function act(action, event)
  event.action = action
  log_event(event)
  if action == "prevent" then
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end
end

--- the check of a request (access phase)
function M.check()
  local host_id = ngx.var.nginxions_files_host
  if not host_id or host_id == "" then return end
  local method = ngx.req.get_method()
  if method ~= "POST" and method ~= "PUT" and method ~= "PATCH" then return end
  conf = conf or load()
  local rules = conf.hosts[host_id]
  if type(rules) ~= "table" then return end
  local rule = rule_of(rules, ngx.var.uri or "/")
  if not rule or rule.mode == "inactive" then return end

  ngx.req.read_body()
  local reader, size = body_reader()
  if not reader or size == 0 then return end

  if rule.max_bytes and size > rule.max_bytes then
    local action = rule.large_action or "inactive"
    if action ~= "inactive" then
      return act(action, { engine = "file-security", mode = rule.mode, size = size, reason = "file over the size limit" })
    end
    return
  end

  local verdict, err = scan(reader, rule)
  if not verdict then
    -- clamd down or busy: the request goes on (fail-open, as the agent), the error is logged
    ngx.log(ngx.ERR, "[NginxionS files] no scan of ", ngx.var.request_uri, ": ", err)
    if err == "size limit" and (rule.large_action or "inactive") ~= "inactive" then
      return act(rule.large_action, { engine = "file-security", mode = rule.mode, size = size,
        reason = "file over the size limit of clamd" })
    end
    return
  end
  if verdict == "OK" then return end
  local confidence = confidence_of(verdict)
  local action = (rule.actions or {})[confidence] or rule.mode
  if action == "inactive" then return end
  return act(action, { engine = "file-security", mode = rule.mode, size = size, signature = verdict,
    confidence = confidence })
end

return M
