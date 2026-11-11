# Optional managed Postgres (use_rds = true): the database survives instance
# loss independently, with automated backups / point-in-time recovery. The
# in-Docker postgres service is dropped from the compose stack when enabled.

data "aws_subnets" "node_vpc" {
  filter {
    name   = "vpc-id"
    values = [data.aws_subnet.selected.vpc_id]
  }
}

resource "aws_db_subnet_group" "node" {
  count      = var.use_rds ? 1 : 0
  name       = "${var.name_prefix}-db"
  subnet_ids = data.aws_subnets.node_vpc.ids
  tags       = local.common_tags
}

resource "aws_security_group" "rds" {
  count       = var.use_rds ? 1 : 0
  name        = "${var.name_prefix}-rds"
  description = "Postgres, reachable only from the node instance"
  vpc_id      = data.aws_subnet.selected.vpc_id
  tags        = local.common_tags

  ingress {
    description     = "Postgres from the node"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.node.id]
  }
}

resource "aws_db_instance" "node" {
  count             = var.use_rds ? 1 : 0
  identifier        = "${var.name_prefix}-db"
  engine            = "postgres"
  engine_version    = "16"
  instance_class    = var.rds_instance_class
  allocated_storage = var.rds_allocated_storage_gb
  storage_type      = "gp3"
  storage_encrypted = true

  db_name  = var.postgres_db
  username = var.postgres_user
  password = random_password.postgres.result

  db_subnet_group_name   = aws_db_subnet_group.node[0].name
  vpc_security_group_ids = [aws_security_group.rds[0].id]

  backup_retention_period   = var.rds_backup_retention_days
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name_prefix}-db-final"
  apply_immediately         = true
  tags                      = local.common_tags
}
