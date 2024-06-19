provider "aws" {
  region = "us-east-1"  # Specify your AWS region
}

resource "aws_sns_topic" "aws_health_notifications" {
  name = "AWSHealthNotifications-tf"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.aws_health_notifications.arn
  protocol  = "email"
  endpoint  = "sanjanamahajan2001@gmail.com"  
}

resource "aws_cloudwatch_event_rule" "aws_health_event_rule" {
  name        = "AWSHealthEventRule-tf"
  description = "Rule to capture AWS Health events"
  event_pattern = jsonencode({
    "source": ["aws.health"],
    "detail-type": ["AWS Health Event"]
  })
}

resource "aws_cloudwatch_event_target" "sns_target" {
  rule      = aws_cloudwatch_event_rule.aws_health_event_rule.name
  target_id = "SNS"
  arn       = aws_sns_topic.aws_health_notifications.arn
}

output "sns_topic_arn" {
  value = aws_sns_topic.aws_health_notifications.arn
}

output "cloudwatch_event_rule_name" {
  value = aws_cloudwatch_event_rule.aws_health_event_rule.name
}

