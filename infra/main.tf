terraform {
  required_version = ">= 1.5"

  # Remote state: copy backend.tf.example to backend.tf (gitignored).

  required_providers {
    aws     = { source = "hashicorp/aws", version = ">= 6.46.0, < 7.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.0" }
    random  = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = { project = "aigw-byo-guardrail", managed_by = "terraform" }
  }
}

# Shared secret the gateway sends in x-guardrail-token (guardrail "headers" parameter).
resource "random_password" "token" {
  length  = 48
  special = false
}

data "archive_file" "webhook" {
  type        = "zip"
  source_file = "${path.module}/../webhook/handler.py"
  output_path = "${path.module}/.build/webhook.zip"
}

resource "aws_iam_role" "webhook" {
  name = var.name
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.webhook.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_cloudwatch_log_group" "webhook" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = 14
}

resource "aws_lambda_function" "webhook" {
  function_name    = var.name
  role             = aws_iam_role.webhook.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  filename         = data.archive_file.webhook.output_path
  source_code_hash = data.archive_file.webhook.output_base64sha256
  timeout          = 5
  memory_size      = 128

  environment {
    variables = {
      TOKEN  = random_password.token.result
      POLICY = jsonencode(var.policy)
    }
  }

  depends_on = [aws_cloudwatch_log_group.webhook, aws_iam_role_policy_attachment.logs]
}

# Public HTTPS endpoint the SaaS gateway can reach. Auth is the shared token, checked in the handler.
resource "aws_lambda_function_url" "webhook" {
  function_name      = aws_lambda_function.webhook.function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "url" {
  statement_id           = "FunctionURLAllowPublicAccess"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.webhook.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

# Since Oct 2025 public function URLs also need lambda:InvokeFunction scoped to URL invocations.
resource "aws_lambda_permission" "url_invoke" {
  statement_id             = "FunctionURLInvokeAllowPublicAccess"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.webhook.function_name
  principal                = "*"
  invoked_via_function_url = true
}
