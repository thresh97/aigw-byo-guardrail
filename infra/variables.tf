variable "aws_region" {
  type    = string
  default = "us-west-2"
}

variable "name" {
  type    = string
  default = "aigw-byo-guardrail"
}

# See webhook/handler.py for the schema.
variable "policy" {
  type = object({
    ip_headers  = optional(list(string), ["cf-connecting-ip"])
    allow_cidrs = optional(list(string), [])
    deny_cidrs  = optional(list(string), [])
    header_rules = optional(list(object({
      header  = string
      require = optional(string)
      deny    = optional(string)
    })), [])
  })
}
