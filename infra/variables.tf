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
