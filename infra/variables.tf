variable "aws_region" {
  type    = string
  default = "us-west-2"
}

variable "name" {
  type    = string
  default = "aigw-byo-guardrail"
}

# Log the gateway's request and response objects (prompt and tool content) to CloudWatch. Testing only.
variable "log_payload" {
  type    = bool
  default = false
}

# See webhook/handler.py for the schema.
variable "policy" {
  type = object({
    ip_headers   = optional(list(string), ["cf-connecting-ip"])
    trusted_hops = optional(number, 0)
    allow_cidrs  = optional(list(string), [])
    deny_cidrs   = optional(list(string), [])
    header_rules = optional(list(object({
      header  = string
      require = optional(string)
      deny    = optional(string)
    })), [])
  })
}

# Prisma AIRS scan of MCP tool calls (webhook/airs.py). null = off.
variable "airs" {
  type = object({
    profile        = optional(string)
    input_profile  = optional(string)
    output_profile = optional(string)
    content        = optional(string)
    fail           = optional(string)
    max_bytes      = optional(number)
    timeout_ms     = optional(number)
    base_url       = optional(string)
    app_name       = optional(string)
  })
  default = null
}

# AIRS runtime API key. Pass it as TF_VAR_airs_api_key rather than writing it to a tfvars file. It ends up in the
# Lambda's environment and the Terraform state.
variable "airs_api_key" {
  type      = string
  default   = ""
  sensitive = true
}
