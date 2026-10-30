-- NPMOS: the block page (conf.d/npmos-block-page.conf). The page is rendered by the backend of NPMOS from
-- the settings of Agents → Block page; it is read again when the file changes (checked every 5 s).
local M = {}
local FILE = "/data/npmos/block-page.html"
local cached, checked, stamp = nil, 0, nil

-- HTML-escaped, and safe as the replacement of gsub (no "%")
local function escape(s)
  local out = tostring(s or ""):gsub("[&<>\"'%%]", {
    ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&#39;", ["%"] = "%%25",
  })
  return out
end

function M.page()
  local now = ngx.now()
  if now - checked < 5 then return cached end
  checked = now
  local f = io.open(FILE, "r")
  if not f then
    cached = nil
    return nil
  end
  local size = f:seek("end")
  local key = tostring(size)
  if key ~= stamp or not cached then
    f:seek("set", 0)
    cached = f:read("*a")
    stamp = key
  end
  f:close()
  if cached == "" then cached = nil end
  return cached
end

-- the details of the request on the page
function M.fill(page)
  return (page
    :gsub("{{ip}}", escape(ngx.var.remote_addr))
    :gsub("{{time}}", escape(ngx.var.time_iso8601))
    :gsub("{{id}}", escape(ngx.var.request_id))
    :gsub("{{host}}", escape(ngx.var.host)))
end

return M
