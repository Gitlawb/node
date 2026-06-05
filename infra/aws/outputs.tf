output "elastic_ip" {
  description = "Public IP of the node"
  value       = aws_eip.node.public_ip
}

output "api_url" {
  description = "HTTP API endpoint (honors the public_url override)"
  value       = local.public_url
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.node.id
}

output "data_volume_id" {
  description = "Persistent EBS data volume (protected by prevent_destroy)"
  value       = aws_ebs_volume.data.id
}

output "postgres_password_ssm_param" {
  description = "SSM parameter holding the postgres password (value not shown)"
  value       = aws_ssm_parameter.postgres_password.name
}

output "ssm_session_command" {
  description = "Open a shell on the instance"
  value       = "aws ssm start-session --target ${aws_instance.node.id} --region ${var.region}"
}

output "upgrade_command" {
  description = "Pull the latest node image and restart the stack"
  value       = "aws ssm send-command --document-name ${aws_ssm_document.upgrade.name} --targets Key=InstanceIds,Values=${aws_instance.node.id} --region ${var.region}"
}
