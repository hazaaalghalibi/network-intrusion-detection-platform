output "instance_public_ip" {
  description = "Public IP of the demo instance"
  value       = aws_instance.nidr.public_ip
}

output "grafana_url" {
  description = "Grafana dashboards (admin/admin — change before leaving this running)"
  value       = "http://${aws_instance.nidr.public_ip}/grafana/"
}

output "api_url" {
  description = "Analyst REST API"
  value       = "http://${aws_instance.nidr.public_ip}/api/alerts"
}

output "ssh_command" {
  value = "ssh ubuntu@${aws_instance.nidr.public_ip}"
}
