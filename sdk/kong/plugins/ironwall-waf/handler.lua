-- IronWall-WAF — Kong Gateway Plugin
-- Integrates IronWall-WAF detection engine into Kong API Gateway.
-- Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
--
-- Installation:
--   1. Copy this file to /usr/local/share/lua/5.1/kong/plugins/ironwall-waf/handler.lua
--   2. Copy schema.lua to the same directory
--   3. Add "ironwall-waf" to Kong's plugins list in kong.conf
--   4. Enable plugin on a Service or Route via Admin API

local http   = require "resty.http"
local json   = require "cjson"
local sha256 = require "resty.sha256"
local str    = require "resty.string"

local IronWallHandler = {
  PRIORITY = 900,   -- Run before authentication (850) but after logging (10000)
  VERSION  = "1.0.0",
}

-- ── Request inspection ────────────────────────────────────────────────────────

function IronWallHandler:access(conf)
  local ngx    = ngx
  local req    = ngx.req

  req.read_body()
  local body      = req.get_body_data() or ""
  local headers   = req.get_headers()
  local uri       = ngx.var.request_uri
  local method    = ngx.req.get_method()
  local client_ip = ngx.var.remote_addr

  -- Build inspection payload
  local payload = {
    ip     = client_ip,
    method = method,
    path   = uri,
    query  = ngx.var.query_string or "",
    body   = conf.inspect_body and body or "",
    headers = {
      ["user-agent"]   = headers["user-agent"] or "",
      ["content-type"] = headers["content-type"] or "",
      ["referer"]      = headers["referer"] or "",
      ["x-forwarded-for"] = headers["x-forwarded-for"] or client_ip,
    },
    session_id = headers["x-request-id"] or ngx.var.request_id or "",
  }

  -- ── 1. GeoIP check ─────────────────────────────────────────────────────────
  if conf.geoip_enabled then
    local geo_result = self:call_ironwall(conf, "/api/open/geoip/evaluate", { ip = client_ip })
    if geo_result and geo_result.action == "block" then
      self:block(conf, "geoip", geo_result.reason, geo_result.lookup)
      return
    end
    if geo_result and geo_result.lookup then
      ngx.req.set_header("X-IronWall-Country",    geo_result.lookup.country_code or "XX")
      ngx.req.set_header("X-IronWall-Risk-Score", tostring(geo_result.lookup.risk_score or 0))
    end
  end

  -- ── 2. Threat Intel IP check ───────────────────────────────────────────────
  if conf.threat_intel_enabled then
    local ti_result = self:call_ironwall(conf, "/api/open/threat-intel/check", { ip = client_ip })
    if ti_result and ti_result.blocked then
      self:block(conf, "threat_intel", "IP in threat intelligence feed", { ip = client_ip })
      return
    end
  end

  -- ── 3. Rate limiting ───────────────────────────────────────────────────────
  if conf.rate_limit_enabled then
    local rl_result = self:call_ironwall(conf, "/api/open/ratelimit/check", {
      ip       = client_ip,
      path     = uri,
      method   = method,
      token    = headers["authorization"] or "",
    })
    if rl_result and not rl_result.allowed then
      ngx.header["Retry-After"]            = tostring(rl_result.retry_after or 60)
      ngx.header["X-RateLimit-Limit"]      = tostring(rl_result.limit or 0)
      ngx.header["X-RateLimit-Remaining"]  = "0"
      ngx.header["X-RateLimit-Reset"]      = tostring(rl_result.reset_at or 0)
      self:block_status(conf, 429, "rate_limit", "Rate limit exceeded")
      return
    end
  end

  -- ── 4. Deep Packet Inspection ─────────────────────────────────────────────
  if conf.dpi_enabled and (method == "POST" or method == "PUT" or method == "PATCH") then
    local dpi_result = self:call_ironwall(conf, "/api/open/inspect", payload)
    if dpi_result and dpi_result.blocked then
      self:block(conf, dpi_result.findings and dpi_result.findings[1] and
        dpi_result.findings[1].category or "dpi",
        "Deep packet inspection — threat score: " .. tostring(dpi_result.score),
        dpi_result)
      return
    end
    if dpi_result then
      ngx.req.set_header("X-IronWall-Threat-Score", tostring(dpi_result.score or 0))
    end
  end

  -- ── 5. License validation (optional) ─────────────────────────────────────
  if conf.license_check_header then
    local lic_key = headers[conf.license_check_header]
    if lic_key then
      local lic_result = self:call_ironwall(conf, "/api/v1/licensing/validate", {
        license_key = lic_key,
        feature     = conf.license_required_feature,
      })
      if not lic_result or not lic_result.valid then
        self:block_status(conf, 403, "license", "Invalid or missing IronWall license")
        return
      end
      ngx.req.set_header("X-IronWall-License-Tier", lic_result.tier or "unknown")
    end
  end

  -- ── 6. Honeypot path check ────────────────────────────────────────────────
  if conf.honeypot_enabled then
    local hp_result = self:call_ironwall(conf, "/api/open/honeypot/check", { path = uri })
    if hp_result and hp_result.is_trap then
      self:block(conf, "honeypot", "Honeypot trap triggered — path: " .. uri, { path = uri })
      return
    end
  end

  -- All checks passed — add IronWall inspection header
  ngx.req.set_header("X-IronWall-Inspected", "1")
  ngx.req.set_header("X-IronWall-Version",   "1.0.0")
end

-- ── HTTP call to IronWall API ─────────────────────────────────────────────────

function IronWallHandler:call_ironwall(conf, path, body)
  local httpc = http.new()
  httpc:set_timeout(conf.timeout_ms or 50)

  local ok, err = httpc:connect(conf.ironwall_host, conf.ironwall_port or 9443)
  if not ok then
    kong.log.warn("[ironwall] connection failed: ", err)
    return nil
  end

  local res, err = httpc:request({
    method  = "POST",
    path    = path,
    body    = json.encode(body),
    headers = {
      ["Content-Type"] = "application/json",
      ["X-Admin-Key"]  = conf.admin_key or "",
    },
    ssl_verify = false,
  })

  if not res then
    kong.log.warn("[ironwall] request failed: ", err)
    return nil
  end

  local response_body = res:read_body()
  httpc:close()

  local ok, decoded = pcall(json.decode, response_body)
  if not ok then return nil end
  return decoded
end

-- ── Block helpers ─────────────────────────────────────────────────────────────

function IronWallHandler:block(conf, reason_code, reason_msg, details)
  self:block_status(conf, conf.block_status or 403, reason_code, reason_msg, details)
end

function IronWallHandler:block_status(conf, status, reason_code, reason_msg, details)
  ngx.header["X-IronWall-Blocked"]       = "1"
  ngx.header["X-IronWall-Block-Reason"]  = reason_code
  ngx.header["X-IronWall-Request-Id"]    = ngx.var.request_id or ""

  if conf.block_response_json then
    ngx.header["Content-Type"] = "application/json"
    ngx.say(json.encode({
      error     = "Request blocked by IronWall-WAF",
      code      = "IRONWALL_BLOCKED",
      reason    = reason_code,
      message   = reason_msg,
      request_id = ngx.var.request_id or "",
      support   = "https://www.optimiumnexus.com",
    }))
  else
    ngx.say(conf.block_message or "Access Denied")
  end

  kong.log.warn(string.format(
    "[ironwall] BLOCKED ip=%s path=%s reason=%s",
    ngx.var.remote_addr, ngx.var.request_uri, reason_code
  ))

  return ngx.exit(status)
end

return IronWallHandler
