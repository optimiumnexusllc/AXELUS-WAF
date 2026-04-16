-- AXELUS-WAF Kong Plugin — Schema
-- Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
local typedefs = require "kong.db.schema.typedefs"

return {
  name = "axelus-waf",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
      type = "record",
      fields = {
        -- Connection
        { axelus_host = { type = "string", required = true, default = "127.0.0.1" } },
        { axelus_port = { type = "integer", default = 9443 } },
        { admin_key     = { type = "string", required = true, encrypted = true } },
        { timeout_ms    = { type = "integer", default = 50, between = { 10, 5000 } } },

        -- Feature toggles
        { geoip_enabled        = { type = "boolean", default = true } },
        { threat_intel_enabled = { type = "boolean", default = true } },
        { dpi_enabled          = { type = "boolean", default = true } },
        { rate_limit_enabled   = { type = "boolean", default = true } },
        { honeypot_enabled     = { type = "boolean", default = false } },
        { inspect_body         = { type = "boolean", default = true } },

        -- Blocking behaviour
        { block_status         = { type = "integer", default = 403, one_of = { 400, 403, 429, 503 } } },
        { block_response_json  = { type = "boolean", default = true } },
        { block_message        = { type = "string",  default = "Access Denied by AXELUS-WAF" } },

        -- License check (optional)
        { license_check_header    = { type = "string" } },
        { license_required_feature = { type = "string" } },

        -- Fail-open / fail-closed
        { fail_open = { type = "boolean", default = true,
          description = "If true, allow requests when AXELUS is unreachable (fail-open). Set false for fail-closed." } },
      },
    }},
  },
}
