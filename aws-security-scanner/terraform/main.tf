terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region"        { default = "us-east-1" }
variable "lambda_zip_path"   { default = "../scanner.zip" }
variable "report_bucket_name" { default = "aws-security-scanner-reports" }
variable "alert_email"        { default = "" }

# ── S3 bucket for reports ──────────────────────────────────────────────────
resource "aws_s3_bucket" "reports" {
  bucket        = var.report_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# ── SNS topic for alerts ───────────────────────────────────────────────────
resource "aws_sns_topic" "security_alerts" {
  name = "aws-security-scanner-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── IAM role for Lambda ────────────────────────────────────────────────────
resource "aws_iam_role" "lambda" {
  name = "aws-security-scanner-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "basic_execution" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_extras" {
  name = "lambda-scanner-extras"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.reports.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# ── Lambda function ────────────────────────────────────────────────────────
resource "aws_lambda_function" "scanner" {
  filename         = var.lambda_zip_path
  function_name    = "aws-security-scanner"
  role             = aws_iam_role.lambda.arn
  handler          = "lambda_handler.lambda_handler"
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 512
  source_code_hash = filebase64sha256(var.lambda_zip_path)

  environment {
    variables = {
      SNS_TOPIC_ARN    = aws_sns_topic.security_alerts.arn
      REPORT_S3_BUCKET = aws_s3_bucket.reports.id
      SERVICES         = "s3,iam,ec2,rds,vpc,cloudtrail"
    }
  }
}

# ── EventBridge daily schedule ─────────────────────────────────────────────
resource "aws_cloudwatch_event_rule" "daily" {
  name                = "security-scanner-daily"
  description         = "Trigger AWS Security Scanner daily at 2 AM UTC"
  schedule_expression = "cron(0 2 * * ? *)"
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.daily.name
  target_id = "SecurityScanner"
  arn       = aws_lambda_function.scanner.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily.arn
}

# ── Outputs ────────────────────────────────────────────────────────────────
output "lambda_function_arn" { value = aws_lambda_function.scanner.arn }
output "sns_topic_arn"       { value = aws_sns_topic.security_alerts.arn }
output "report_bucket"       { value = aws_s3_bucket.reports.id }
