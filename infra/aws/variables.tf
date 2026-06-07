# ---------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------

variable "region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for resource names and tags"
  type        = string
  default     = "gitlawb-node"
}

variable "tags" {
  description = "Extra tags applied to all resources"
  type        = map(string)
  default     = {}
}

variable "subnet_id" {
  description = "Subnet to launch into. Defaults to the first subnet of the default VPC."
  type        = string
  default     = null
}

# ---------------------------------------------------------------------------
# Compute & storage
# ---------------------------------------------------------------------------

variable "instance_type" {
  description = "EC2 instance type (ARM/Graviton — the node image is multi-arch)"
  type        = string
  default     = "t4g.small"
}

variable "data_volume_size_gb" {
  description = "Size of the persistent /data EBS volume in GB (repos, identity key, postgres)"
  type        = number
  default     = 20
}

variable "data_volume_type" {
  description = "EBS volume type for the data volume"
  type        = string
  default     = "gp3"
}

variable "snapshot_retain_count" {
  description = "How many daily EBS snapshots of the data volume to retain"
  type        = number
  default     = 7

  validation {
    condition     = var.snapshot_retain_count >= 1 && var.snapshot_retain_count <= 1000
    error_message = "snapshot_retain_count must be between 1 and 1000 (DLM retain rule limits)."
  }
}

# ---------------------------------------------------------------------------
# Node image
# ---------------------------------------------------------------------------

variable "image_repo" {
  description = "Container image repository for the node. Ignored when create_ecr_repo is true (the module-managed ECR repo is used instead)."
  type        = string
  default     = "ghcr.io/gitlawb/node"
}

variable "create_ecr_repo" {
  description = "Create a private ECR repository in this account and pull the node image from it (instance role gets pull rights via a credential helper). Push images with scripts in the README."
  type        = bool
  default     = false
}

variable "image_tag" {
  description = "Image tag to run. After changing, run the upgrade SSM command (see outputs) — user-data only runs at first boot."
  type        = string
  default     = "latest"
}

# ---------------------------------------------------------------------------
# Networking / ingress
# ---------------------------------------------------------------------------

variable "gitlawb_port" {
  description = "HTTP API port"
  type        = number
  default     = 7545
}

variable "gitlawb_p2p_port" {
  description = "libp2p UDP port"
  type        = number
  default     = 7546
}

variable "metrics_port" {
  description = "Prometheus metrics port"
  type        = number
  default     = 9091
}

variable "api_ingress_cidr" {
  description = "CIDR allowed to reach the HTTP API (public node by default)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "p2p_ingress_cidr" {
  description = "CIDR allowed to reach the p2p UDP port"
  type        = string
  default     = "0.0.0.0/0"
}

variable "metrics_ingress_cidr" {
  description = "CIDR allowed to scrape /metrics. null = metrics port not exposed."
  type        = string
  default     = null
}

variable "ssh_ingress_cidr" {
  description = "CIDR allowed to SSH. null = no SSH (use SSM Session Manager)."
  type        = string
  default     = null
}

variable "ssh_key_name" {
  description = "Existing EC2 key pair name for SSH. Only used if ssh_ingress_cidr is set."
  type        = string
  default     = null
}

# ---------------------------------------------------------------------------
# Node configuration (defaults mirror infra/fly/fly.toml)
# ---------------------------------------------------------------------------

variable "public_url" {
  description = "Public URL of this node (GITLAWB_PUBLIC_URL). Leave empty to default to http://<elastic-ip>:<port> after apply — set a real DNS name for production."
  type        = string
  default     = ""
}

variable "bootstrap_peers" {
  description = "Comma-separated bootstrap peer URLs (GITLAWB_BOOTSTRAP_PEERS)"
  type        = string
  default     = "https://node.gitlawb.com,https://node2.gitlawb.com,https://node3.gitlawb.com"
}

variable "auto_sync" {
  description = "GITLAWB_AUTO_SYNC"
  type        = string
  default     = "true"
}

variable "max_pack_bytes" {
  description = "GITLAWB_MAX_PACK_BYTES (500MB, matching the Fly deployment)"
  type        = string
  default     = "524288000"
}

variable "ssm_kms_key_id" {
  description = "Customer-managed KMS key (ID, alias, or ARN) for encrypting the SSM SecureString secrets. null = AWS-managed aws/ssm key."
  type        = string
  default     = null
}

# ---------------------------------------------------------------------------
# Postgres
# ---------------------------------------------------------------------------

variable "postgres_user" {
  description = "Postgres user for the node database"
  type        = string
  default     = "gitlawb"
}

variable "postgres_db" {
  description = "Postgres database name"
  type        = string
  default     = "gitlawb"
}

# ---------------------------------------------------------------------------
# Optional integrations (all off by default; see .env.example at repo root)
# ---------------------------------------------------------------------------

variable "chain_rpc_url" {
  description = "Base L2 RPC URL (optional, PoS operator)"
  type        = string
  default     = ""
}

variable "contract_node_staking" {
  description = "Node staking contract address (optional)"
  type        = string
  default     = ""
}

variable "operator_private_key" {
  description = "PoS operator private key (optional). Stored in SSM, not in user-data."
  type        = string
  default     = ""
  sensitive   = true
}

variable "pinata_jwt" {
  description = "Pinata JWT for IPFS pinning (optional). Stored in SSM, not in user-data."
  type        = string
  default     = ""
  sensitive   = true
}

variable "tigris_bucket" {
  description = "S3-compatible bucket for pack storage (optional, GITLAWB_TIGRIS_BUCKET)"
  type        = string
  default     = ""
}

variable "s3_access_key_id" {
  description = "Access key for the S3-compatible bucket (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "s3_secret_access_key" {
  description = "Secret key for the S3-compatible bucket (optional). Stored in SSM, not in user-data."
  type        = string
  default     = ""
  sensitive   = true
}

variable "s3_endpoint_url" {
  description = "Custom S3 endpoint URL (optional, AWS_ENDPOINT_URL_S3)"
  type        = string
  default     = ""
}
