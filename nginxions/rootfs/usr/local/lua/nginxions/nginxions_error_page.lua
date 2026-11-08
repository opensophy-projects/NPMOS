-- NginxionS: the page of an error nginx answers itself (conf.d/nginxions-block-page.conf): 502 when the server of a site does
-- not answer, 504, 401 of an access list, 404 of a file, 413, 429… get the page of NginxionS (html/nginxions-error.html)
-- in place of the bare "502 Bad Gateway / nginx". An answer of the server of the site is never replaced.
local M = {}
local FILE = "/usr/local/nginx/html/nginxions-error.html"
local template

-- [code] = { en title, en text, ru title, ru text }
local TEXTS = {
  [400] = { "Bad request", "The server could not understand the request of the browser.",
    "Неверный запрос", "Сервер не смог разобрать запрос браузера." },
  [401] = { "Sign-in required", "This site asks for a login and a password.",
    "Нужен вход", "Сайт запрашивает логин и пароль." },
  [404] = { "Page not found", "There is no page at this address. Check the address.",
    "Страница не найдена", "По этому адресу страницы нет. Проверьте адрес." },
  [405] = { "Method not allowed", "The site does not accept requests of this kind at this address.",
    "Метод не разрешён", "Сайт не принимает такие запросы по этому адресу." },
  [408] = { "Request timeout", "The browser took too long to send the request. Try again.",
    "Время запроса истекло", "Браузер слишком долго отправлял запрос. Попробуйте ещё раз." },
  [413] = { "Request too large", "The request (for example, an uploaded file) is larger than the site accepts.",
    "Слишком большой запрос", "Запрос (например, загружаемый файл) больше, чем принимает сайт." },
  [414] = { "Address too long", "The address of the request is longer than the site accepts.",
    "Слишком длинный адрес", "Адрес запроса длиннее, чем принимает сайт." },
  [429] = { "Too many requests", "Too many requests came from your address. Wait a little and try again.",
    "Слишком много запросов", "С вашего адреса пришло слишком много запросов. Подождите немного и попробуйте снова." },
  [500] = { "Server error", "Something went wrong on the server. Try again later.",
    "Ошибка сервера", "На сервере что-то пошло не так. Попробуйте позже." },
  [502] = { "The site does not answer", "The server of this site cannot be reached right now. Try again in a few minutes.",
    "Сайт не отвечает", "Сервер этого сайта сейчас недоступен. Попробуйте через несколько минут." },
  [503] = { "Site unavailable", "The site is temporarily unavailable. Try again later.",
    "Сайт недоступен", "Сайт временно недоступен. Попробуйте позже." },
  [504] = { "The site answers too slowly", "The server of this site did not answer in time. Try again in a few minutes.",
    "Сайт не ответил вовремя", "Сервер этого сайта не ответил вовремя. Попробуйте через несколько минут." },
}
local OTHER_4XX = { "Request refused", "The site cannot answer this request.",
  "Запрос не выполнен", "Сайт не может ответить на этот запрос." }
local OTHER_5XX = { "Server error", "The site cannot answer right now. Try again later.",
  "Ошибка сервера", "Сайт сейчас не может ответить. Попробуйте позже." }

-- pages that are NginxionS's already (404 host, default site, mTLS)
local OWN = { ["/dead.html"] = true, ["/default.html"] = true }

local function escape(s)
  local out = tostring(s or ""):gsub("[&<>\"'%%]", {
    ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&#39;", ["%"] = "%%25",
  })
  return out
end

--- the error is nginx's own: no server of the site answered (none asked, or the last one did not send headers)
local function own_error()
  local upstream = ngx.var.upstream_status
  if upstream == nil or upstream == "" then return true end
  local last = (ngx.var.upstream_header_time or ""):match("([^,:%s]+)%s*$")
  return last == nil or last == "-"
end

--- whether the answer gets the page (called in the header filter; 403 is the block page's)
function M.wanted()
  local status = ngx.status
  if status < 400 or status == 403 or status == 444 or status == 499 or status > 599 then return false end
  local uri = ngx.var.uri or ""
  if OWN[uri] or string.sub(uri, 1, 8) == "/.nginxions/" then return false end
  local ctype = ngx.header["Content-Type"]
  if type(ctype) == "table" then ctype = ctype[1] end
  if ctype ~= nil and not string.find(ctype, "^text/html") then return false end
  return own_error()
end

function M.page()
  if not template then
    local f = io.open(FILE, "r")
    if not f then return nil end
    template = f:read("*a")
    f:close()
  end
  local status = ngx.status
  local t = TEXTS[status] or (status >= 500 and OTHER_5XX or OTHER_4XX)
  return (template
    :gsub("{{title}}", escape(status .. " · " .. t[1]))
    :gsub("{{code}}", escape(status))
    :gsub("{{en_title}}", escape(t[1]))
    :gsub("{{en_text}}", escape(t[2]))
    :gsub("{{ru_title}}", escape(t[3]))
    :gsub("{{ru_text}}", escape(t[4]))
    :gsub("{{host}}", escape(ngx.var.host))
    :gsub("{{time}}", escape(ngx.var.time_iso8601))
    :gsub("{{id}}", escape(ngx.var.request_id)))
end

return M
