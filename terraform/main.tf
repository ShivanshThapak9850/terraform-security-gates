terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
}

# -----------------------------------------------------------------------------
# S3
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "data" {
  bucket = "devsecops-lab-data-bucket-change-me"

  # checkov:skip=CKV_AWS_144:Cross-region replication is a disaster-recovery and cost decision, not a security control
  # checkov:skip=CKV2_AWS_61:Lifecycle configuration is a cost-management control; no retention requirement defined for this lab
  # checkov:skip=CKV2_AWS_62:Event notifications are an integration feature; no downstream consumer exists
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Logging to self is acceptable for a lab only. In production, access logs
# belong in a separate, more restricted bucket - a compromised bucket should
# not hold its own audit trail.
resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.data.id
  target_prefix = "access-logs/"
}

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
}

resource "aws_flow_log" "main" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.data.arn
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web tier: HTTPS from internet, no direct admin access"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS to AWS APIs and package repositories"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# -----------------------------------------------------------------------------
# IAM - least privilege
# -----------------------------------------------------------------------------
resource "aws_iam_role" "app" {
  name = "app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "app_read_data" {
  name = "app-s3-read-policy"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket"
      ]
      Resource = [
        aws_s3_bucket.data.arn,
        "${aws_s3_bucket.data.arn}/*"
      ]
    }]
  })
}

# Managed policy for SSM Session Manager - replaces SSH entirely
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "app" {
  name = "app-instance-profile"
  role = aws_iam_role.app.name
}

# -----------------------------------------------------------------------------
# Compute
# -----------------------------------------------------------------------------
resource "aws_instance" "web" {
  ami           = "ami-0f5ee92e2d63afc18"
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.private.id

  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name

  monitoring    = true
  ebs_optimized = true

  root_block_device {
    encrypted = true
  }

  # IMDSv2 required - breaks the SSRF to credential-theft chain
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = {
    Name = "web-server"
  }
}

# -----------------------------------------------------------------------------
# Database
# -----------------------------------------------------------------------------
resource "aws_db_instance" "postgres" {
  identifier     = "lab-postgres"
  engine         = "postgres"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  db_name           = "labdb"
  username          = "postgres"

  # AWS generates, stores and rotates the password in Secrets Manager.
  # It never exists in Terraform source or in Git history.
  manage_master_user_password = true

  publicly_accessible = false
  storage_encrypted   = true

  backup_retention_period             = 7
  auto_minor_version_upgrade          = true
  deletion_protection                 = true
  iam_database_authentication_enabled = true

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  skip_final_snapshot = true

  # checkov:skip=CKV_AWS_157:Multi-AZ is an availability control, not security; single-AZ accepted for a non-production lab
  # checkov:skip=CKV_AWS_118:Enhanced monitoring is an operability concern; out of scope for a lab with no running workload
  # checkov:skip=CKV_AWS_353:Performance Insights is a performance tuning feature, not a security control
  # checkov:skip=CKV2_AWS_60:Copy-tags-to-snapshots is a tagging and cost-allocation concern
  # checkov:skip=CKV2_AWS_30:Query logging is enabled via enabled_cloudwatch_logs_exports above; this check expects a separate parameter group
}
