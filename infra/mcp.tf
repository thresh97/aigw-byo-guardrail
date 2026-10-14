# Optional probe MCP server (mcp/server.py) for testing MCP guardrails. Off unless mcp_server = true.

variable "mcp_server" {
  type    = bool
  default = false
}

# Optional probe modes (EXTRA_TOOL, JWT_SERVERS, OAUTH_SERVERS, JWT_JWKS, JWT_ISSUER, ...), see mcp/server.py.
variable "mcp_env" {
  type    = map(string)
  default = {}
}

locals {
  mcp_name = "${var.name}-mcp"
  mcp      = var.mcp_server ? 1 : 0
}

# Static header the MCP integration sends in x-mcp-token.
resource "random_password" "mcp_token" {
  count   = local.mcp
  length  = 48
  special = false
}

data "archive_file" "mcp" {
  type        = "zip"
  source_file = "${path.module}/../mcp/server.py"
  output_path = "${path.module}/.build/mcp.zip"
}

resource "aws_iam_role" "mcp" {
  count = local.mcp
  name  = local.mcp_name
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "mcp_logs" {
  count      = local.mcp
  role       = aws_iam_role.mcp[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_cloudwatch_log_group" "mcp" {
  count             = local.mcp
  name              = "/aws/lambda/${local.mcp_name}"
  retention_in_days = 14
}

resource "aws_lambda_function" "mcp" {
  count            = local.mcp
  function_name    = local.mcp_name
  role             = aws_iam_role.mcp[0].arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "server.handler"
  filename         = data.archive_file.mcp.output_path
  source_code_hash = data.archive_file.mcp.output_base64sha256
  timeout          = 5
  memory_size      = 128

  environment {
    variables = merge(var.mcp_env, { TOKEN = random_password.mcp_token[0].result })
  }

  depends_on = [aws_cloudwatch_log_group.mcp, aws_iam_role_policy_attachment.mcp_logs]
}

resource "aws_lambda_function_url" "mcp" {
  count              = local.mcp
  function_name      = aws_lambda_function.mcp[0].function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "mcp_url" {
  count                  = local.mcp
  statement_id           = "FunctionURLAllowPublicAccess"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.mcp[0].function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "mcp_url_invoke" {
  count                    = local.mcp
  statement_id             = "FunctionURLInvokeAllowPublicAccess"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.mcp[0].function_name
  principal                = "*"
  invoked_via_function_url = true
}

output "mcp_url" {
  value = var.mcp_server ? aws_lambda_function_url.mcp[0].function_url : null
}

output "mcp_token" {
  value     = var.mcp_server ? random_password.mcp_token[0].result : null
  sensitive = true
}

output "mcp_log_group" {
  value = var.mcp_server ? aws_cloudwatch_log_group.mcp[0].name : null
}
