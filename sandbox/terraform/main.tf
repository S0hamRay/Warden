terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "warden-sandbox-${random_id.suffix.hex}"
  tags = {
    Project     = "WardenSandbox"
    Environment = "demo"
    Warning     = "IntentionallyMisconfigured"
  }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# --- Intentionally public S3 bucket ---
resource "aws_s3_bucket" "public" {
  bucket = "${local.name_prefix}-public"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "public" {
  bucket = aws_s3_bucket.public.id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "public" {
  bucket = aws_s3_bucket.public.id
  rule {
    object_ownership = "ObjectWriter"
  }
}

resource "aws_s3_bucket_acl" "public" {
  depends_on = [
    aws_s3_bucket_ownership_controls.public,
    aws_s3_bucket_public_access_block.public,
  ]
  bucket = aws_s3_bucket.public.id
  acl    = "public-read"
}

resource "aws_s3_bucket_policy" "public" {
  depends_on = [aws_s3_bucket_public_access_block.public]
  bucket     = aws_s3_bucket.public.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadGetObject"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public.arn}/*"
    }]
  })
}

# --- Over-permissioned IAM role (PassRole + CreateFunction + wildcards) ---
resource "aws_iam_role" "overprivileged" {
  name = "${local.name_prefix}-overpriv"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "overprivileged" {
  name = "dangerous"
  role = aws_iam_role.overprivileged.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole",
          "lambda:CreateFunction",
          "ec2:RunInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

# --- Open security group + EC2 with IMDSv1 allowed ---
resource "aws_security_group" "open_ssh" {
  name        = "${local.name_prefix}-open-ssh"
  description = "Warden sandbox intentionally open SSH"
  vpc_id      = data.aws_vpc.default.id
  tags        = local.tags

  ingress {
    description = "SSH from world (intentional misconfig)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "imdsv1" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.open_ssh.id]
  tags                   = merge(local.tags, { Name = "${local.name_prefix}-imdsv1" })

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }
}

output "public_bucket" {
  value = aws_s3_bucket.public.bucket
}

output "overprivileged_role" {
  value = aws_iam_role.overprivileged.arn
}

output "instance_id" {
  value = aws_instance.imdsv1.id
}

output "security_group_id" {
  value = aws_security_group.open_ssh.id
}
