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

--- the severity of a signature of ClamAV by its kind of malware (Platform.Category.Name-Id-Rev, "Heuristics.*",
--- "PUA.*"): minSeverityLevel of the practice leaves out those below it
local CRITICAL = { Ransomware = 1, Backdoor = 1, Rootkit = 1, Exploit = 1, Worm = 1, Virus = 1 }
local HIGH = { Trojan = 1, Downloader = 1, Dropper = 1, Loader = 1, Infostealer = 1, Keylogger = 1, Spyware = 1,
  Malware = 1, Ircbot = 1, Macro = 1, Coinminer = 1, Webshell = 1 }
local LOW = { Adware = 1, Joke = 1, File = 1, Filetype = 1, Revoked = 1 }
local RANK = { low = 1, medium = 2, high = 3, critical = 4 }
local function severity_of(name)
  if name:match("^PUA%.") then return "low" end
  if name:match("^Heuristics%.") then return "medium" end
  local category = name:match("^[^.]+%.([^.]+)%.")
  if category and CRITICAL[category] then return "critical" end
  if category and HIGH[category] then return "high" end
  if category and LOW[category] then return "low" end
  -- phishing, packers, tools, test files (EICAR is Win.Test.EICAR_HDB-1) and the rest
  return "medium"
end

--- an archive, by its first bytes: zip (and its documents), gzip, bzip2, xz, 7-Zip, RAR, cab, tar
local function is_archive(head)
  if not head or #head < 4 then return false end
  local four = head:sub(1, 4)
  if four == "PK\3\4" or four == "PK\5\6" or head:sub(1, 2) == "\31\139" or head:sub(1, 3) == "BZh"
    or head:sub(1, 6) == "\253" .. "7zXZ\0" or head:sub(1, 6) == "7z\188\175\39\28" or head:sub(1, 4) == "Rar!"
    or four == "MSCF" or head:sub(258, 262) == "ustar" then
    return true
  end
  return false
end

local ARCHIVE_EXT = { zip = 1, jar = 1, war = 1, apk = 1, gz = 1, tgz = 1, bz2 = 1, xz = 1, ["7z"] = 1, rar = 1,
  tar = 1, cab = 1, iso = 1, zst = 1 }
--- an archive inside a zip: the names of its entries (local file headers)
local function has_nested(data)
  local pos = 1
  while true do
    local at = data:find("PK\3\4", pos, true)
    if not at or at + 30 > #data then return false end
    local b1, b2 = data:byte(at + 26, at + 27)
    local name = data:sub(at + 30, at + 29 + b1 + b2 * 256):lower()
    local ext = name:match("%.([%w]+)$")
    if ext and ARCHIVE_EXT[ext] then return true end
    pos = at + 4
  end
end

--- the name of the uploaded file is known: multipart parts with a filename, Content-Disposition, or a path ending
--- with a file name; text, forms and JSON are not files
local NOT_FILES = { "^text/", "^application/json", "%+json", "^application/xml", "%+xml",
  "^application/x%-www%-form%-urlencoded", "^application/graphql", "^application/javascript" }
local function unnamed(data)
  local ctype = (ngx.var.content_type or ""):lower()
  if ctype:find("^multipart/") then
    if not data then return false end
    -- a part with a type of its own and no file name
    for headers in ("\r\n" .. data):gmatch("\r\n%-%-[^\r\n]*\r\n(.-)\r\n\r\n") do
      local h = headers:lower()
      if h:find("content%-disposition") and not h:find("filename") and h:find("content%-type:")
        and not h:find("content%-type:%s*text/") then
        return true
      end
    end
    return false
  end
  for _, p in ipairs(NOT_FILES) do
    if ctype:find(p) then return false end
  end
  local disposition = ngx.var.http_content_disposition or ""
  if disposition:lower():find("filename") then return false end
  if (ngx.var.uri or ""):match("/[^/]+%.%w+$") then return false end
  return true
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

--- the body whole (up to limit bytes), for the checks of its archives and parts; nil above it
local function body_data(limit)
  local data = ngx.req.get_body_data()
  if data then return data end
  local name = ngx.req.get_body_file()
  if not name then return nil end
  local f = io.open(name, "rb")
  if not f then return nil end
  local size = f:seek("end")
  if size > limit then f:close() return nil end
  f:seek("set", 0)
  data = f:read("*a")
  f:close()
  return data
end

--- the first bytes of the body
local function body_head()
  local data = ngx.req.get_body_data()
  if data then return data:sub(1, 512) end
  local name = ngx.req.get_body_file()
  if not name then return nil end
  local f = io.open(name, "rb")
  if not f then return nil end
  local head = f:read(512)
  f:close()
  return head
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

  local base = { engine = "file-security", mode = rule.mode, size = size }
  local function with(t)
    for k, v in pairs(base) do t[k] = v end
    return t
  end
  local archives = rule.archives or {}
  local archive = is_archive(body_head())
  if archive then
    -- an archive is opened (and scanned) only when the practice asks it, up to its size
    if not archives.extract or size > (archives.max_bytes or 10485760) then return end
    local action = archives.nested_action or "inactive"
    if action ~= "inactive" then
      local data = body_data(archives.max_bytes or 10485760)
      if data and has_nested(data) then
        return act(action, with({ reason = "an archive inside an archive" }))
      end
    end
  end

  local verdict, err = scan(reader, rule)
  if not verdict then
    -- clamd down or busy: the request goes on (fail-open, as the agent), the error is logged
    ngx.log(ngx.ERR, "[NginxionS files] no scan of ", ngx.var.request_uri, ": ", err)
    if err == "size limit" and (rule.large_action or "inactive") ~= "inactive" then
      return act(rule.large_action, with({ reason = "file over the size limit of clamd" }))
    end
    return
  end
  -- the deep static analysis (threatEmulationEnabled of the practice): off, its findings are left out
  local deep = verdict ~= "OK" and (verdict:match("^Heuristics%.OLE2%.ContainsMacros")
    or verdict:match("^Heuristics%.Broken%.") or verdict:match("^Heuristics%.PartitionIntersection"))
  if deep then
    if not rule.deep then
      verdict = "OK"
    else
      local action = (rule.actions or {}).high or rule.mode
      if action == "inactive" then return end
      return act(action, with({ signature = verdict, confidence = "high", reason = "threat emulation" }))
    end
  end
  if verdict ~= "OK" then
    -- an archive clamd could not open (encrypted, over its limits)
    if verdict:match("^Heuristics%.Encrypted") or verdict:match("^Heuristics%.Limits%.Exceeded") then
      local action = archive and archives.failed_action or rule.large_action or "inactive"
      if action == "inactive" then return end
      return act(action, with({ signature = verdict, reason = "the content of the archive could not be extracted" }))
    end
    local severity = severity_of(verdict)
    if RANK[severity] < (RANK[rule.min_severity or "medium"] or 2) then return end
    local confidence = confidence_of(verdict)
    local action = (rule.actions or {})[confidence] or rule.mode
    if action == "inactive" then return end
    return act(action, with({ signature = verdict, confidence = confidence, severity = severity }))
  end

  local action = rule.unnamed_action or "inactive"
  if action ~= "inactive" and unnamed(body_data(rule.max_bytes or 10485760)) then
    return act(action, with({ reason = "a file with no name" }))
  end
end

return M
