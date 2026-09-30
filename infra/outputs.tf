output "webhook_url" {
  value = aws_lambda_function_url.webhook.function_url
}

output "webhook_token" {
  value     = random_password.token.result
  sensitive = true
}

output "log_group" {
  value = aws_cloudwatch_log_group.webhook.name
}
