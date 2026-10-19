variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type. OpenSearch alone wants >=2GB heap, so t3.large (8GB) is the practical minimum."
  type        = string
  default     = "t3.large"
}

variable "key_name" {
  description = "Name of an existing EC2 key pair, for SSH access"
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed to SSH in, e.g. your IP as x.x.x.x/32. Never leave this as 0.0.0.0/0."
  type        = string
}

variable "repo_url" {
  description = "Git URL of this repo (your fork/push of it) that the instance clones and runs on boot"
  type        = string
}

variable "root_volume_size_gb" {
  description = "Root EBS volume size — container images + OpenSearch/Postgres data need headroom"
  type        = number
  default     = 30
}
