# Single-EC2 gitlawb node: Docker compose (node + postgres) on Amazon Linux 2023,
# persistent EBS data volume, Elastic IP, SSM access, daily snapshots.

# ---------------------------------------------------------------------------
# Network placement (default VPC unless subnet_id is set)
# ---------------------------------------------------------------------------

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

locals {
  subnet_id      = coalesce(var.subnet_id, sort(data.aws_subnets.default.ids)[0])
  expose_metrics = var.metrics_ingress_cidr != null
  common_tags    = merge({ Project = "gitlawb-node", ManagedBy = "terraform" }, var.tags)
}

data "aws_subnet" "selected" {
  id = local.subnet_id
}

# Latest Amazon Linux 2023 arm64 AMI (pairs with t4g/Graviton; node image is
# multi-arch). ignore_changes on the instance AMI avoids churn on AL releases.
data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

# ---------------------------------------------------------------------------
# Secrets (SSM Parameter Store — never baked into user-data)
# ---------------------------------------------------------------------------

resource "random_password" "postgres" {
  length  = 32
  special = false
}

resource "aws_ssm_parameter" "postgres_password" {
  name   = "/${var.name_prefix}/postgres_password"
  type   = "SecureString"
  key_id = var.ssm_kms_key_id
  value  = random_password.postgres.result
  tags   = local.common_tags
}

resource "aws_ssm_parameter" "operator_key" {
  count  = var.operator_private_key != "" ? 1 : 0
  name   = "/${var.name_prefix}/operator_private_key"
  type   = "SecureString"
  key_id = var.ssm_kms_key_id
  value  = var.operator_private_key
  tags   = local.common_tags
}

resource "aws_ssm_parameter" "pinata_jwt" {
  count  = var.pinata_jwt != "" ? 1 : 0
  name   = "/${var.name_prefix}/pinata_jwt"
  type   = "SecureString"
  key_id = var.ssm_kms_key_id
  value  = var.pinata_jwt
  tags   = local.common_tags
}

resource "aws_ssm_parameter" "s3_secret" {
  count  = var.s3_secret_access_key != "" ? 1 : 0
  name   = "/${var.name_prefix}/s3_secret_access_key"
  type   = "SecureString"
  key_id = var.ssm_kms_key_id
  value  = var.s3_secret_access_key
  tags   = local.common_tags
}

resource "aws_ssm_parameter" "s3_access_key" {
  count  = var.s3_access_key_id != "" ? 1 : 0
  name   = "/${var.name_prefix}/s3_access_key_id"
  type   = "SecureString"
  key_id = var.ssm_kms_key_id
  value  = var.s3_access_key_id
  tags   = local.common_tags
}

locals {
  secret_param_arns = concat(
    [aws_ssm_parameter.postgres_password.arn],
    aws_ssm_parameter.operator_key[*].arn,
    aws_ssm_parameter.pinata_jwt[*].arn,
    aws_ssm_parameter.s3_secret[*].arn,
    aws_ssm_parameter.s3_access_key[*].arn,
  )
}

# ---------------------------------------------------------------------------
# IAM: SSM Session Manager access + least-privilege read of our parameters.
# The AWS-managed aws/ssm KMS key needs no explicit kms:Decrypt grant; a
# customer-managed key (ssm_kms_key_id) gets one scoped to that key.
# ---------------------------------------------------------------------------

data "aws_kms_key" "ssm" {
  count  = var.ssm_kms_key_id != null ? 1 : 0
  key_id = var.ssm_kms_key_id
}

resource "aws_iam_role" "node" {
  name = "${var.name_prefix}-instance"
  tags = local.common_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "ssm_params_read" {
  name = "read-gitlawb-secrets"
  role = aws_iam_role.node.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = local.secret_param_arns
      }],
      var.ssm_kms_key_id != null ? [{
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [data.aws_kms_key.ssm[0].arn]
        # Only via Parameter Store, and only for this stack's parameters —
        # not arbitrary ciphertext encrypted under the same CMK.
        Condition = {
          StringEquals = {
            "kms:ViaService"                      = "ssm.${var.region}.amazonaws.com"
            "kms:EncryptionContext:PARAMETER_ARN" = local.secret_param_arns
          }
        }
      }] : []
    )
  })
}

resource "aws_iam_instance_profile" "node" {
  name = "${var.name_prefix}-instance"
  role = aws_iam_role.node.name
}

# ---------------------------------------------------------------------------
# Security group
# ---------------------------------------------------------------------------

resource "aws_security_group" "node" {
  name        = "${var.name_prefix}-sg"
  description = "gitlawb node: HTTP API + libp2p UDP"
  vpc_id      = data.aws_subnet.selected.vpc_id # follows subnet_id overrides into non-default VPCs
  tags        = local.common_tags

  ingress {
    description = "HTTP API + git smart-HTTP"
    from_port   = var.gitlawb_port
    to_port     = var.gitlawb_port
    protocol    = "tcp"
    cidr_blocks = [var.api_ingress_cidr]
  }

  ingress {
    description = "libp2p QUIC"
    from_port   = var.gitlawb_p2p_port
    to_port     = var.gitlawb_p2p_port
    protocol    = "udp"
    cidr_blocks = [var.p2p_ingress_cidr]
  }

  dynamic "ingress" {
    for_each = var.domain_name != "" ? [80, 443] : []
    content {
      description = "Caddy HTTP/HTTPS (TLS for ${var.domain_name})"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "ingress" {
    for_each = local.expose_metrics ? [1] : []
    content {
      description = "Prometheus metrics"
      from_port   = var.metrics_port
      to_port     = var.metrics_port
      protocol    = "tcp"
      cidr_blocks = [var.metrics_ingress_cidr]
    }
  }

  dynamic "ingress" {
    for_each = var.ssh_ingress_cidr != null ? [1] : []
    content {
      description = "SSH (prefer SSM Session Manager)"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [var.ssh_ingress_cidr]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------------
# Persistent data volume — survives instance replacement. prevent_destroy
# guards repos, postgres data, and the node identity key (/data/keys).
# ---------------------------------------------------------------------------

resource "aws_ebs_volume" "data" {
  availability_zone = data.aws_subnet.selected.availability_zone
  size              = var.data_volume_size_gb
  type              = var.data_volume_type
  encrypted         = true
  tags = merge(local.common_tags, {
    Name     = "${var.name_prefix}-data"
    Snapshot = "true" # targeted by the DLM snapshot policy
  })

  lifecycle {
    prevent_destroy = true
  }
}

# ---------------------------------------------------------------------------
# Instance + Elastic IP
# ---------------------------------------------------------------------------

resource "aws_eip" "node" {
  domain = "vpc"
  tags   = merge(local.common_tags, { Name = var.name_prefix })
}

# ---------------------------------------------------------------------------
# Optional private ECR repository — self-contained image hosting in this
# account instead of an external registry. Push with: see README "Building
# and pushing the image".
# ---------------------------------------------------------------------------

resource "aws_ecr_repository" "node" {
  count = var.create_ecr_repo ? 1 : 0
  name  = var.name_prefix
  tags  = local.common_tags

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_iam_role_policy_attachment" "ecr_read" {
  count      = var.create_ecr_repo ? 1 : 0
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

locals {
  image_repo   = var.create_ecr_repo ? aws_ecr_repository.node[0].repository_url : var.image_repo
  ecr_registry = var.create_ecr_repo ? split("/", aws_ecr_repository.node[0].repository_url)[0] : ""
}

locals {
  public_url = (
    var.public_url != "" ? var.public_url :
    var.domain_name != "" ? "https://${var.domain_name}" :
    "http://${aws_eip.node.public_ip}:${var.gitlawb_port}"
  )

  compose_yaml = templatefile("${path.module}/compose.yaml.tftpl", {
    image_repo     = local.image_repo
    image_tag      = var.image_tag
    domain_name    = var.domain_name
    db_host        = var.use_rds ? aws_db_instance.node[0].address : ""
    gitlawb_port   = var.gitlawb_port
    p2p_port       = var.gitlawb_p2p_port
    metrics_port   = var.metrics_port
    expose_metrics = local.expose_metrics
    pg_user        = var.postgres_user
    pg_db          = var.postgres_db
  })

  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    region                = var.region
    pg_password_param     = aws_ssm_parameter.postgres_password.name
    operator_key_param    = try(aws_ssm_parameter.operator_key[0].name, "")
    pinata_jwt_param      = try(aws_ssm_parameter.pinata_jwt[0].name, "")
    s3_secret_param       = try(aws_ssm_parameter.s3_secret[0].name, "")
    s3_access_key_param   = try(aws_ssm_parameter.s3_access_key[0].name, "")
    public_url            = local.public_url
    bootstrap_peers       = var.bootstrap_peers
    auto_sync             = var.auto_sync
    max_pack_bytes        = var.max_pack_bytes
    chain_rpc_url         = var.chain_rpc_url
    contract_node_staking = var.contract_node_staking
    tigris_bucket         = var.tigris_bucket
    s3_endpoint_url       = var.s3_endpoint_url
    ecr_registry          = local.ecr_registry
    compose_yaml          = local.compose_yaml
  })
}

resource "aws_instance" "node" {
  ami                    = nonsensitive(data.aws_ssm_parameter.al2023_arm64.value)
  instance_type          = var.instance_type
  subnet_id              = local.subnet_id
  vpc_security_group_ids = [aws_security_group.node.id]
  iam_instance_profile   = aws_iam_instance_profile.node.name
  key_name               = var.ssh_key_name
  user_data              = local.user_data
  tags                   = merge(local.common_tags, { Name = var.name_prefix })

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2 only
  }

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = true
  }

  lifecycle {
    # ami: new AL2023 releases shouldn't churn the instance; replace
    # deliberately for OS upgrades.
    # user_data: only runs at first boot, so re-rendering it on a live
    # instance is a pointless stop/start. Config changes that feed user-data
    # (bootstrap peers, integrations, image tag) require a deliberate
    # `terraform apply -replace=aws_instance.node` — see README "Changing
    # configuration".
    ignore_changes = [ami, user_data]
  }
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdf" # presented as /dev/nvme1n1 on Nitro; user-data discovers it
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.node.id
}

resource "aws_eip_association" "node" {
  instance_id   = aws_instance.node.id
  allocation_id = aws_eip.node.id
}

# ---------------------------------------------------------------------------
# Daily EBS snapshots of the data volume (DLM)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "dlm" {
  name = "${var.name_prefix}-dlm"
  tags = local.common_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "dlm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "dlm" {
  role       = aws_iam_role.dlm.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}

resource "aws_dlm_lifecycle_policy" "data" {
  description        = "Daily snapshots of the gitlawb data volume"
  execution_role_arn = aws_iam_role.dlm.arn
  state              = "ENABLED"
  tags               = local.common_tags

  policy_details {
    resource_types = ["VOLUME"]
    # Name makes the target stack-specific — a bare Snapshot=true would also
    # match unrelated tagged volumes in a shared account.
    target_tags = {
      Snapshot = "true"
      Name     = "${var.name_prefix}-data"
    }

    schedule {
      name = "daily"

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["05:00"]
      }

      retain_rule {
        count = var.snapshot_retain_count
      }

      copy_tags = true
    }
  }
}

# ---------------------------------------------------------------------------
# Upgrade runbook as code: pull + restart the compose stack via SSM
# ---------------------------------------------------------------------------

resource "aws_ssm_document" "upgrade" {
  name            = "${var.name_prefix}-upgrade"
  document_type   = "Command"
  document_format = "JSON"
  tags            = local.common_tags

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Pull the latest gitlawb node image and restart the compose stack"
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "upgrade"
      inputs = {
        runCommand = [
          "cd /opt/gitlawb && docker compose pull && docker compose up -d --remove-orphans && docker image prune -f"
        ]
      }
    }]
  })
}
