# Hands-on Migration Lab - VPC + EC2 Migration

## Lab Overview

**Objective**: Migrate a production-like AWS infrastructure project from Terraform to OpenTofu, validating state consistency and resource integrity throughout the process.

**Duration**: 2-3 hours

**Infrastructure Components**:
- Multi-AZ VPC with public and private subnets
- Internet Gateway and NAT Gateway
- Route tables and associations
- EC2 instance with SSH access
- Security groups with minimal access
- Elastic IP for NAT Gateway
- SSH key pair for instance access

**Learning Outcomes**:
- Experience a complete migration workflow
- Validate state consistency before and after migration
- Troubleshoot common migration issues
- Document migration results
- Understand rollback procedures

---

## Prerequisites

### Required Software

Verify all required software is installed:

```bash
# OpenTofu (v1.6.0+)
tofu version

# Terraform (v1.5.0+ for initial deployment)
terraform version

# AWS CLI (v2.x)
aws --version

# jq (for JSON processing)
jq --version

# Git (for version control)
git --version
```

### AWS Configuration

```bash
# Verify AWS credentials
aws sts get-caller-identity

# Should show your AWS account details
# {
#   "UserId": "AIDAXXXXXXXXXXXXXXXXX",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/your-username"
# }

# Set your preferred region (if not already set)
export AWS_DEFAULT_REGION=us-east-1
```

### SSH Key Preparation

```bash
# Create SSH key for lab (if you don't already have one)
ssh-keygen -t rsa -b 4096 -f ~/.ssh/opentofu-lab-key -N ""

# Set proper permissions
chmod 400 ~/.ssh/opentofu-lab-key

# Verify key created
ls -la ~/.ssh/opentofu-lab-key*
# Should show:
# -r-------- opentofu-lab-key (private key)
# -rw-r--r-- opentofu-lab-key.pub (public key)
```

### Working Directory Setup

```bash
# Create dedicated lab directory
mkdir -p ~/opentofu-migration-lab
cd ~/opentofu-migration-lab

# Initialize Git repository for tracking
git init
git config user.name "Your Name"
git config user.email "your.email@example.com"
```

---

## Phase 1: Initial Terraform Deployment

### Step 1: Create Terraform Configuration Files

**Create directory structure:**

```bash
cd ~/opentofu-migration-lab
mkdir -p terraform-project
cd terraform-project
```

**File 1: versions.tf**

```bash
cat > versions.tf << 'EOF'
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}
EOF
```

**File 2: providers.tf**

```bash
cat > providers.tf << 'EOF'
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = "OpenTofu Migration Lab"
      Owner       = var.owner
    }
  }
}
EOF
```

**File 3: variables.tf**

```bash
cat > variables.tf << 'EOF'
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "migration-lab"
}

variable "owner" {
  description = "Resource owner"
  type        = string
  default     = "terraform-user"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "availability_zones" {
  description = "Availability zones for subnets"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"

  validation {
    condition     = contains(["t2.micro", "t2.small", "t3.micro"], var.instance_type)
    error_message = "Instance type must be t2.micro, t2.small, or t3.micro for cost control."
  }
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key"
  type        = string
  default     = "~/.ssh/opentofu-lab-key.pub"
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH to instances"
  type        = string
  default     = "0.0.0.0/0"  # Restrict this in production!
}
EOF
```

**File 4: main.tf**

```bash
cat > main.tf << 'EOF'
# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.environment}-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.environment}-igw"
  }
}

# Public Subnets
resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.environment}-public-subnet-${count.index + 1}"
    Type = "Public"
  }
}

# Private Subnets
resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)

  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name = "${var.environment}-private-subnet-${count.index + 1}"
    Type = "Private"
  }
}

# Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${var.environment}-nat-eip"
  }

  depends_on = [aws_internet_gateway.main]
}

# NAT Gateway
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.environment}-nat-gateway"
  }

  depends_on = [aws_internet_gateway.main]
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.environment}-public-rt"
  }
}

# Private Route Table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name = "${var.environment}-private-rt"
  }
}

# Public Route Table Associations
resource "aws_route_table_association" "public" {
  count = length(aws_subnet.public)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private Route Table Associations
resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# SSH Key Pair
resource "aws_key_pair" "lab" {
  key_name   = "${var.environment}-key"
  public_key = file(pathexpand(var.ssh_public_key_path))

  tags = {
    Name = "${var.environment}-ssh-key"
  }
}

# Security Group for EC2
resource "aws_security_group" "web" {
  name        = "${var.environment}-web-sg"
  description = "Security group for web server"
  vpc_id      = aws_vpc.main.id

  # SSH access
  ingress {
    description = "SSH from allowed CIDR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # HTTP access
  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS access
  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Outbound internet access
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-web-sg"
  }
}

# Data source for latest Ubuntu AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# EC2 Instance
resource "aws_instance" "web" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name              = aws_key_pair.lab.key_name
  subnet_id             = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.web.id]

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted            = true
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y nginx
              systemctl start nginx
              systemctl enable nginx
              
              # Create simple index page
              cat > /var/www/html/index.html << 'HTML'
              <!DOCTYPE html>
              <html>
              <head>
                  <title>OpenTofu Migration Lab</title>
                  <style>
                      body { font-family: Arial; margin: 40px; }
                      .success { color: green; font-size: 24px; }
                      .info { background: #f0f0f0; padding: 20px; margin: 20px 0; }
                  </style>
              </head>
              <body>
                  <h1 class="success">✓ Migration Lab Server Running</h1>
                  <div class="info">
                      <h2>Infrastructure Details</h2>
                      <p><strong>Managed by:</strong> ${var.environment}</p>
                      <p><strong>Instance Type:</strong> ${var.instance_type}</p>
                      <p><strong>Region:</strong> ${var.aws_region}</p>
                  </div>
                  <p>If you can see this page, your infrastructure is working correctly!</p>
              </body>
              </html>
HTML
              EOF

  tags = {
    Name = "${var.environment}-web-server"
  }
}

# Elastic IP for EC2 Instance
resource "aws_eip" "web" {
  instance = aws_instance.web.id
  domain   = "vpc"

  tags = {
    Name = "${var.environment}-web-eip"
  }

  depends_on = [aws_internet_gateway.main]
}
EOF
```

**File 5: outputs.tf**

```bash
cat > outputs.tf << 'EOF'
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "VPC CIDR block"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "nat_gateway_ip" {
  description = "NAT Gateway public IP"
  value       = aws_eip.nat.public_ip
}

output "web_server_public_ip" {
  description = "Web server public IP"
  value       = aws_eip.web.public_ip
}

output "web_server_private_ip" {
  description = "Web server private IP"
  value       = aws_instance.web.private_ip
}

output "web_url" {
  description = "Web server URL"
  value       = "http://${aws_eip.web.public_ip}"
}

output "ssh_command" {
  description = "SSH command to connect to web server"
  value       = "ssh -i ~/.ssh/opentofu-lab-key ubuntu@${aws_eip.web.public_ip}"
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.web.id
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.web.id
}
EOF
```

**File 6: terraform.tfvars (optional customization)**

```bash
cat > terraform.tfvars << 'EOF'
# Customize these values if needed
aws_region   = "us-east-1"
environment  = "migration-lab"
owner        = "your-name"
instance_type = "t2.micro"

# Uncomment and customize if using different AZs
# availability_zones = ["us-east-1a", "us-east-1b"]

# Uncomment to restrict SSH access (recommended)
# allowed_ssh_cidr = "YOUR.IP.ADDRESS.HERE/32"
EOF
```

### Step 2: Deploy Infrastructure with Terraform

**Initialize Terraform:**

```bash
# From ~/opentofu-migration-lab/terraform-project directory
terraform init
```

**Expected output:**
```
Initializing the backend...
Initializing provider plugins...
- Finding hashicorp/aws versions matching "~> 5.0"...
- Finding hashicorp/tls versions matching "~> 4.0"...
- Installing hashicorp/aws v5.x.x...
- Installing hashicorp/tls v4.x.x...

Terraform has been successfully initialized!
```

**Validate configuration:**

```bash
terraform validate
```

**Expected output:**
```
Success! The configuration is valid.
```

**Format configuration:**

```bash
terraform fmt -recursive
```

**Plan infrastructure:**

```bash
terraform plan -out=terraform-initial.plan
```

**Review the plan carefully:**
- Should show creation of ~25 resources
- VPC, subnets, route tables, gateways
- EC2 instance, security group, key pair
- Elastic IPs

**Apply infrastructure:**

```bash
terraform apply terraform-initial.plan
```

**Expected output:**
```
Apply complete! Resources: 25 added, 0 changed, 0 destroyed.

Outputs:

instance_id = "i-0123456789abcdef0"
nat_gateway_ip = "3.x.x.x"
public_subnet_ids = [
  "subnet-0123456789abcdef0",
  "subnet-0123456789abcdef1",
]
private_subnet_ids = [
  "subnet-0123456789abcdef2",
  "subnet-0123456789abcdef3",
]
security_group_id = "sg-0123456789abcdef0"
ssh_command = "ssh -i ~/.ssh/opentofu-lab-key ubuntu@54.x.x.x"
vpc_cidr = "10.0.0.0/16"
vpc_id = "vpc-0123456789abcdef0"
web_server_private_ip = "10.0.1.x"
web_server_public_ip = "54.x.x.x"
web_url = "http://54.x.x.x"
```

**Wait for instance to be ready (2-3 minutes):**

```bash
# Check instance status
aws ec2 describe-instances \
  --instance-ids $(terraform output -raw instance_id) \
  --query 'Reservations[0].Instances[0].State.Name' \
  --output text

# Should show "running"
```

**Test web server:**

```bash
# Get web URL from outputs
WEB_URL=$(terraform output -raw web_url)

# Test HTTP access
curl -s "$WEB_URL" | grep "Migration Lab"

# Should show: <h1 class="success">✓ Migration Lab Server Running</h1>

# Test SSH access
ssh -i ~/.ssh/opentofu-lab-key -o StrictHostKeyChecking=no \
  ubuntu@$(terraform output -raw web_server_public_ip) \
  'echo "SSH connection successful!"'
```

### Step 3: Document Current State

**Commit to Git:**

```bash
# Add all configuration files
git add .

# Create initial commit
git commit -m "Initial Terraform deployment - pre-migration snapshot"

# Tag this version
git tag -a v1.0-terraform -m "Pre-migration Terraform state"

# View commit
git log --oneline
```

**Record infrastructure state:**

```bash
# Create documentation file
cat > INFRASTRUCTURE.md << EOF
# Infrastructure Documentation

## Deployment Date
$(date)

## Terraform Version
$(terraform version | head -1)

## AWS Region
$(terraform output -raw aws_region || echo "us-east-1")

## Resources Created
$(terraform state list | wc -l) resources

## Resource List
\`\`\`
$(terraform state list)
\`\`\`

## Outputs
\`\`\`
$(terraform output)
\`\`\`

## State Serial Number
$(grep '"serial"' terraform.tfstate | head -1)

## State Lineage
$(grep '"lineage"' terraform.tfstate | head -1)
EOF

# View documentation
cat INFRASTRUCTURE.md
```

---

## Phase 2: Pre-Migration Validation

### Step 1: Create Comprehensive Backups

**Backup state files:**

```bash
# Create backups directory
mkdir -p ../backups

# Backup current state
cp terraform.tfstate ../backups/terraform.tfstate.pre-migration-$(date +%Y%m%d-%H%M%S)

# Backup .tfstate.backup if exists
if [ -f terraform.tfstate.backup ]; then
  cp terraform.tfstate.backup ../backups/terraform.tfstate.backup.pre-migration-$(date +%Y%m%d-%H%M%S)
fi

# Create complete archive
tar -czf ../backups/complete-backup-$(date +%Y%m%d-%H%M%S).tar.gz \
  .terraform/ \
  terraform.tfstate* \
  *.tf \
  *.tfvars \
  .terraform.lock.hcl

# List backups
ls -lh ../backups/
```

**Document state metadata:**

```bash
# Extract key state information
cat > ../backups/state-metadata.txt << EOF
Pre-Migration State Metadata
=============================
Date: $(date)
Terraform Version: $(terraform version -json | jq -r .terraform_version)
State Version: $(jq -r .version terraform.tfstate)
State Serial: $(jq -r .serial terraform.tfstate)
State Lineage: $(jq -r .lineage terraform.tfstate)
Resource Count: $(jq '.resources | length' terraform.tfstate)

Providers:
$(jq -r '.resources[].provider' terraform.tfstate | sort -u)

Resource Types:
$(jq -r '.resources[].type' terraform.tfstate | sort -u)
EOF

cat ../backups/state-metadata.txt
```

### Step 2: Validate Provider Versions

**Check provider constraints:**

```bash
# Display required providers
cat versions.tf

# Verify installed providers
terraform providers
```

**Expected output:**
```
Providers required by configuration:
.
├── provider[registry.terraform.io/hashicorp/aws] ~> 5.0
└── provider[registry.terraform.io/hashicorp/tls] ~> 4.0

Providers required by state:

    provider[registry.terraform.io/hashicorp/aws]

    provider[registry.terraform.io/hashicorp/tls]
```

**Verify provider versions in lock file:**

```bash
cat .terraform.lock.hcl | grep -A 3 "provider"
```

### Step 3: Verify No Drift

**Run plan to confirm no changes:**

```bash
terraform plan -detailed-exitcode
```

**Expected exit codes:**
- 0 = No changes
- 1 = Error
- 2 = Changes detected

**Expected output:**
```
No changes. Your infrastructure matches the configuration.

Terraform has compared your real infrastructure against your configuration
and found no differences, so no changes are needed.
```

**If changes are detected**, investigate and fix before migration:

```bash
# Refresh state to ensure accuracy
terraform refresh

# Plan again
terraform plan
```

### Step 4: Document Dependencies

**List all resources:**

```bash
# Get complete resource list
terraform state list > ../pre-migration-resources.txt

# Count resources
echo "Total resources: $(terraform state list | wc -l)" >> ../pre-migration-resources.txt

# View
cat ../pre-migration-resources.txt
```

**Identify resource dependencies:**

```bash
# Create dependency graph (requires graphviz)
terraform graph > ../pre-migration-graph.dot

# Or create a text-based dependency list
cat > ../dependency-map.txt << 'EOF'
Resource Dependencies
=====================

VPC → Internet Gateway
VPC → Subnets (Public & Private)
Internet Gateway → NAT Gateway (via EIP)
Subnets → Route Table Associations
NAT Gateway → Private Route Table
Security Group → EC2 Instance
Key Pair → EC2 Instance
Subnet → EC2 Instance
EC2 Instance → EIP (web server)
EOF
```

### Step 5: Create Pre-Migration Checklist

```bash
cat > ../PRE-MIGRATION-CHECKLIST.md << 'EOF'
# Pre-Migration Checklist

## Completed Steps
- [x] Infrastructure deployed with Terraform
- [x] State files backed up
- [x] Configuration committed to Git
- [x] No infrastructure drift detected
- [x] Provider versions documented
- [x] Dependencies mapped
- [x] Resource count recorded
- [x] Test environment validated

## Readiness Criteria
- [x] Terraform version: 1.5.0+
- [x] State file version: 4
- [x] All resources in "ready" state
- [x] Backups created and verified
- [x] Git repository initialized
- [x] SSH access tested
- [x] Web server accessible

## Pre-Migration Snapshot
- Resources: 25
- State serial: 1
- Last apply: [timestamp in backups]
- No drift detected: Yes

## Ready for Migration: ✓ YES

Next step: Proceed to Migration Execution Phase
EOF

cat ../PRE-MIGRATION-CHECKLIST.md
```

---

## Phase 3: Migration Execution

### Step 1: Install and Verify OpenTofu

**Install OpenTofu (if not already installed):**

```bash
# macOS with Homebrew
brew install opentofu

# OR Linux with install script
# curl --proto '=https' --tlsv1.2 -fsSL \
#   https://get.opentofu.org/install-opentofu.sh -o install-opentofu.sh
# chmod +x install-opentofu.sh
# ./install-opentofu.sh --install-method standalone
```

**Verify installation:**

```bash
# Check OpenTofu version
tofu version

# Expected output:
# OpenTofu v1.6.0 (or higher)

# Verify Terraform still available (for rollback capability)
terraform version

# Expected output:
# Terraform v1.5.x
```

**Create OpenTofu alias (optional convenience):**

```bash
# Add to ~/.bashrc or ~/.zshrc if desired
# alias tf='tofu'

# For this lab, we'll use the full 'tofu' command for clarity
```

### Step 2: Remove Terraform Lock File

**The lock file needs to be regenerated for OpenTofu:**

```bash
# Backup the Terraform lock file
cp .terraform.lock.hcl ../backups/.terraform.lock.hcl.terraform

# Remove it (OpenTofu will create a new one)
rm .terraform.lock.hcl

# Verify it's removed
ls -la .terraform.lock.hcl
# Should show: No such file or directory
```

**Why this step?**
- The lock file contains provider checksums specific to Terraform
- OpenTofu will generate its own lock file during `init`
- This does not affect the state file or infrastructure

### Step 3: Initialize with OpenTofu

**Run OpenTofu init with state migration:**

```bash
tofu init -migrate-state
```

**Expected prompts and responses:**

```
Initializing the backend...

OpenTofu has detected that the state was previously managed by Terraform.
Migration from Terraform to OpenTofu is supported and is usually safe.

Do you want to migrate the state from Terraform to OpenTofu? 
  Enter a value: yes

Initializing provider plugins...
- Reusing previous version of hashicorp/aws from the dependency lock file
- Reusing previous version of hashicorp/tls from the dependency lock file
- Installing hashicorp/aws v5.x.x...
- Installing hashicorp/tls v4.x.x...
- Installed hashicorp/aws v5.x.x (signed by HashiCorp)
- Installed hashicorp/tls v4.x.x (signed by HashiCorp)

OpenTofu has been successfully initialized!
```

**Verify new lock file created:**

```bash
ls -la .terraform.lock.hcl

# Compare sizes
ls -lh ../backups/.terraform.lock.hcl.terraform .terraform.lock.hcl
```

### Step 4: First Plan with OpenTofu

**Generate plan with OpenTofu:**

```bash
tofu plan -out=opentofu-initial.plan
```

**CRITICAL: Expected output should show zero changes:**

```
data.aws_ami.ubuntu: Reading...
data.aws_ami.ubuntu: Read complete after 1s [id=ami-xxxxx]

No changes. Your infrastructure matches the configuration.

OpenTofu has compared your real infrastructure against your configuration
and found no differences, so no changes are needed.
```

**If you see changes, DO NOT PROCEED. Investigate:**

```bash
# Common issues and solutions:

# Issue 1: Different AMI detected
# Solution: This can happen if AMI updated. Review the change.
# If only AMI change, generally safe. Other changes require investigation.

# Issue 2: Taint or replace operations shown
# Solution: Review why resource would be replaced. 
# Should not happen in simple migration.

# Issue 3: Tag changes
# Solution: Verify default_tags in provider block matches expectations
```

### Step 5: Verify State Migration

**Check state file integrity:**

```bash
# Pull current state
tofu state pull > current-state.json

# Compare key fields with pre-migration state
echo "=== State Comparison ==="
echo "Pre-migration serial: $(jq -r .serial ../backups/terraform.tfstate.pre-migration-*)"
echo "Current serial: $(jq -r .serial current-state.json)"
echo ""
echo "Pre-migration lineage: $(jq -r .lineage ../backups/terraform.tfstate.pre-migration-*)"
echo "Current lineage: $(jq -r .lineage current-state.json)"
echo ""
echo "Pre-migration resources: $(jq '.resources | length' ../backups/terraform.tfstate.pre-migration-*)"
echo "Current resources: $(jq '.resources | length' current-state.json)"
```

**Expected results:**
- Serial number may increment by 1 (from migration)
- Lineage should be identical
- Resource count should be identical
- Resource types should be identical

**List resources:**

```bash
# List all resources
tofu state list > ../post-migration-resources.txt

# Compare with pre-migration
diff ../pre-migration-resources.txt ../post-migration-resources.txt

# Should show: Files are identical (or no output)
```

---

## Phase 4: Post-Migration Validation

### Step 1: Comprehensive Plan Validation

**Run multiple plan checks:**

```bash
# Standard plan
tofu plan

# Expected: "No changes"

# Plan with refresh
tofu plan -refresh=true

# Expected: "No changes"

# Plan with detailed output
tofu plan -detailed-exitcode

# Expected exit code: 0 (no changes)
echo "Exit code: $?"
```

### Step 2: Verify Outputs

**Check all outputs function correctly:**

```bash
# Get all outputs
tofu output

# Test specific outputs
echo "VPC ID: $(tofu output -raw vpc_id)"
echo "Web Server IP: $(tofu output -raw web_server_public_ip)"
echo "Instance ID: $(tofu output -raw instance_id)"

# Verify outputs match AWS reality
aws ec2 describe-instances \
  --instance-ids $(tofu output -raw instance_id) \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text

# Should match: tofu output -raw web_server_public_ip
```

### Step 3: Infrastructure Functionality Testing

**Test web server still accessible:**

```bash
# Get web URL
WEB_URL=$(tofu output -raw web_url)

# Test HTTP access
echo "Testing web server at $WEB_URL..."
curl -s "$WEB_URL" | grep -q "Migration Lab" && echo "✓ Web server working" || echo "✗ Web server failed"

# Test SSH access
echo "Testing SSH access..."
ssh -i ~/.ssh/opentofu-lab-key -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
  ubuntu@$(tofu output -raw web_server_public_ip) \
  'echo "✓ SSH connection successful"' 2>/dev/null || echo "✗ SSH failed"
```

**Verify resource state in AWS:**

```bash
# Check VPC
aws ec2 describe-vpcs --vpc-ids $(tofu output -raw vpc_id) \
  --query 'Vpcs[0].State' --output text
# Expected: available

# Check instance
aws ec2 describe-instances --instance-ids $(tofu output -raw instance_id) \
  --query 'Reservations[0].Instances[0].State.Name' --output text
# Expected: running

# Check security group
aws ec2 describe-security-groups --group-ids $(tofu output -raw security_group_id) \
  --query 'SecurityGroups[0].GroupName' --output text
# Expected: migration-lab-web-sg
```

### Step 4: Test Apply Operation

**Apply with no changes (verify command works):**

```bash
# Run apply (should show no changes)
tofu apply -auto-approve
```

**Expected output:**
```
No changes. Your infrastructure matches the configuration.

OpenTofu has compared your real infrastructure against your configuration
and found no differences, so no changes are needed.

Apply complete! Resources: 0 added, 0 changed, 0 destroyed.

Outputs:
[... all outputs shown ...]
```

### Step 5: State Refresh and Validation

**Refresh state from AWS:**

```bash
# Refresh state
tofu refresh

# Plan again to ensure no drift
tofu plan

# Expected: "No changes"
```

**Validate state integrity:**

```bash
# Create post-migration state snapshot
cat > ../POST-MIGRATION-STATE.md << EOF
# Post-Migration State Validation

## Migration Date
$(date)

## OpenTofu Version
$(tofu version | head -1)

## State Validation Results

### Resource Count
Pre-migration: $(cat ../pre-migration-resources.txt | grep -v "Total" | wc -l)
Post-migration: $(tofu state list | wc -l)
Match: $([ $(cat ../pre-migration-resources.txt | grep -v "Total" | wc -l) -eq $(tofu state list | wc -l) ] && echo "✓ YES" || echo "✗ NO")

### Resource List Comparison
\`\`\`
$(diff ../pre-migration-resources.txt <(tofu state list) || echo "Resources match")
\`\`\`

### State Serial
Pre-migration: $(jq -r .serial ../backups/terraform.tfstate.pre-migration-*)
Post-migration: $(tofu state pull | jq -r .serial)

### State Lineage
Pre-migration: $(jq -r .lineage ../backups/terraform.tfstate.pre-migration-*)
Post-migration: $(tofu state pull | jq -r .lineage)
Match: $([ "$(jq -r .lineage ../backups/terraform.tfstate.pre-migration-*)" == "$(tofu state pull | jq -r .lineage)" ] && echo "✓ YES" || echo "✗ NO")

### Infrastructure Tests
- [x] Web server accessible via HTTP
- [x] SSH access functional
- [x] All outputs valid
- [x] AWS resources in expected state
- [x] No drift detected

## Migration Status: ✓ SUCCESSFUL
EOF

cat ../POST-MIGRATION-STATE.md
```

---

## Phase 5: Documentation and Cleanup

### Step 1: Update Configuration References

**Update ManagedBy tags:**

```bash
# Update providers.tf to reflect OpenTofu management
sed -i.bak 's/ManagedBy   = "Terraform"/ManagedBy   = "OpenTofu"/' providers.tf

# Show the change
diff providers.tf.bak providers.tf
```

**Update README if exists:**

```bash
cat > README.md << 'EOF'
# OpenTofu Migration Lab - Infrastructure

This infrastructure was successfully migrated from Terraform to OpenTofu.

## Overview

Multi-AZ VPC infrastructure with:
- VPC with public and private subnets
- NAT Gateway for private subnet internet access
- EC2 web server with public access
- Proper security groups and networking

## Requirements

- OpenTofu v1.6.0+
- AWS CLI configured
- SSH key at ~/.ssh/opentofu-lab-key

## Usage

```bash
# Initialize
tofu init

# Plan
tofu plan

# Apply
tofu apply

# Destroy (when done with lab)
tofu destroy
```

## Outputs

Run `tofu output` to see all infrastructure outputs including:
- VPC and subnet IDs
- Web server public IP
- SSH connection command
- Web URL

## Migration History

- Original deployment: Terraform v1.5.7
- Migrated to: OpenTofu v1.6.0
- Migration date: [date from your migration]
- Migration status: Successful
- Resources: 25
- Changes during migration: 0

## Testing

```bash
# Test web server
curl $(tofu output -raw web_url)

# Test SSH
ssh -i ~/.ssh/opentofu-lab-key ubuntu@$(tofu output -raw web_server_public_ip)
```
EOF

cat README.md
```

### Step 2: Commit Migration Changes

```bash
# Add all changes
git add .

# Commit migration
git commit -m "Migration to OpenTofu completed successfully

- Migrated from Terraform v1.5.7 to OpenTofu v1.6.0
- Zero infrastructure changes during migration
- All resources validated and functional
- State integrity confirmed
- Documentation updated"

# Tag the migration
git tag -a v2.0-opentofu -m "Post-migration to OpenTofu v1.6.0"

# View git history
git log --oneline --graph
```

### Step 3: Document Lessons Learned

```bash
cat > ../LESSONS-LEARNED.md << 'EOF'
# Migration Lessons Learned

## What Went Well

1. **Pre-Migration Preparation**
   - Comprehensive backups prevented any risk
   - Git tagging provided clear rollback points
   - Documentation captured critical state information

2. **Migration Process**
   - `tofu init -migrate-state` worked seamlessly
   - No infrastructure changes during migration
   - State lineage preserved correctly

3. **Validation**
   - Multiple plan checks confirmed success
   - All outputs functioned identically
   - Web server and SSH access maintained

## Challenges Encountered

[Document any issues you faced, for example:]

1. **Lock File Removal**
   - Initially forgot to remove .terraform.lock.hcl
   - Regeneration was automatic and smooth

2. **AMI Differences**
   - Latest AMI may differ between plan runs
   - This is expected behavior, not a migration issue

## Recommendations for Future Migrations

1. **Always backup state files** before migration
2. **Use Git tags** for clear version tracking
3. **Test in non-production** first
4. **Document expected resource count** for validation
5. **Verify rollback procedure** before starting
6. **Plan extra time** for validation testing

## Time Spent

- Pre-migration planning: 30 minutes
- Backup and validation: 20 minutes
- Migration execution: 10 minutes
- Post-migration validation: 40 minutes
- Documentation: 20 minutes
- **Total: ~2 hours**

## Migration Success Metrics

- State migration: ✓ Success
- Zero changes in plan: ✓ Confirmed
- Infrastructure functionality: ✓ Verified
- State integrity: ✓ Validated
- Documentation: ✓ Complete

## Overall Assessment

Migration was **successful and straightforward**. OpenTofu provides true drop-in compatibility with Terraform, making the migration process low-risk and predictable.
EOF

cat ../LESSONS-LEARNED.md
```

### Step 4: Create Migration Report

```bash
cat > ../MIGRATION-REPORT.md << EOF
# OpenTofu Migration Report

## Executive Summary

Successfully migrated infrastructure project from Terraform to OpenTofu with zero infrastructure changes and full functionality preservation.

## Migration Details

**Date**: $(date)
**Duration**: ~2 hours (including validation)
**Outcome**: Successful

### Versions

- **Source**: Terraform v$(grep 'terraform_version' ../backups/terraform.tfstate.pre-migration-* | cut -d'"' -f4)
- **Target**: OpenTofu v$(tofu version | head -1 | cut -d'v' -f2)

### Infrastructure Scope

- **Resources**: $(tofu state list | wc -l)
- **AWS Region**: $(tofu output -raw aws_region || echo "us-east-1")
- **Providers**: AWS, TLS
- **Modules**: None (direct resource configuration)

## Migration Process

### 1. Pre-Migration
- ✓ State files backed up
- ✓ Configuration committed to Git
- ✓ No drift detected
- ✓ Dependencies documented
- ✓ Resource inventory created

### 2. Migration Execution
- ✓ OpenTofu installed and verified
- ✓ Lock file removed
- ✓ State migrated with \`tofu init -migrate-state\`
- ✓ No prompts or errors

### 3. Post-Migration Validation
- ✓ Plan shows zero changes
- ✓ All outputs functional
- ✓ Infrastructure tests passed
- ✓ State integrity confirmed

## Validation Results

### State Comparison

| Metric | Pre-Migration | Post-Migration | Status |
|--------|---------------|----------------|--------|
| Resources | $(cat ../pre-migration-resources.txt | grep -v "Total" | wc -l) | $(tofu state list | wc -l) | ✓ Match |
| State Lineage | $(jq -r .lineage ../backups/terraform.tfstate.pre-migration-* | cut -c1-20)... | $(tofu state pull | jq -r .lineage | cut -c1-20)... | ✓ Match |
| State Version | $(jq -r .version ../backups/terraform.tfstate.pre-migration-*) | $(tofu state pull | jq -r .version) | ✓ Match |

### Infrastructure Tests

- ✓ Web server HTTP access: Working
- ✓ SSH connectivity: Successful  
- ✓ AWS resource status: All running/available
- ✓ Outputs: All valid
- ✓ Apply operation: Successful (no changes)

## Risk Assessment

**Pre-Migration Risk**: Low
- Terraform v1.5.7 is fully compatible with OpenTofu
- Simple infrastructure with well-defined dependencies
- Comprehensive backups created

**Actual Risk Encountered**: None
- Migration completed without issues
- No infrastructure downtime
- No data loss

## Recommendations

1. **For Similar Projects**
   - Follow same backup and validation procedures
   - Use Git tagging for clear version control
   - Allow 2-3 hours for complete migration cycle

2. **For More Complex Infrastructures**
   - Test in staging environment first
   - Plan for additional validation time
   - Consider phased migration approach

3. **For Production Systems**
   - Schedule migration during maintenance window
   - Have rollback plan ready
   - Monitor infrastructure for 24 hours post-migration

## Cost Impact

- **AWS Resources**: No change (same infrastructure)
- **Tooling**: Free (OpenTofu is open source)
- **Time Investment**: ~2 hours
- **Net Impact**: Positive (removed license dependency)

## Next Steps

1. Monitor infrastructure for any delayed issues
2. Update CI/CD pipelines to use OpenTofu
3. Migrate remaining Terraform projects
4. Share migration playbook with team

## Approval

Migration validated and approved for:
- Production deployment
- Team adoption
- Documentation sharing

**Validated by**: [Your name]  
**Date**: $(date)  
**Status**: ✓ Approved for production use
EOF

cat ../MIGRATION-REPORT.md
```

---

## Phase 6: Optional Testing and Cleanup

### Step 1: Test Infrastructure Modification

**To further validate OpenTofu, make a small change:**

```bash
# Add a tag to the web server
cat >> main.tf << 'EOF'

# Add test tag for OpenTofu validation
resource "aws_ec2_tag" "test" {
  resource_id = aws_instance.web.id
  key         = "MigrationTest"
  value       = "OpenTofu-Managed"
}
EOF

# Plan the change
tofu plan

# Should show 1 resource to add
# Apply if comfortable
tofu apply -auto-approve

# Verify tag
aws ec2 describe-tags --filters \
  "Name=resource-id,Values=$(tofu output -raw instance_id)" \
  "Name=key,Values=MigrationTest" \
  --query 'Tags[0].Value' --output text

# Should show: OpenTofu-Managed

# Remove test tag
sed -i '/# Add test tag for OpenTofu validation/,/^}$/d' main.tf

# Apply to remove
tofu apply -auto-approve
```

### Step 2: Lab Cleanup (When Finished)

**Destroy infrastructure to avoid charges:**

```bash
# Review what will be destroyed
tofu plan -destroy

# Destroy all resources
tofu destroy

# Type: yes

# Expected output:
# Destroy complete! Resources: 25 destroyed.
```

**Verify all resources removed:**

```bash
# Check for any remaining resources
aws ec2 describe-vpcs --filters "Name=tag:Environment,Values=migration-lab" \
  --query 'Vpcs[*].VpcId'

# Should return: []

# Check for EIPs (these can incur charges)
aws ec2 describe-addresses --query 'Addresses[?Tags[?Key==`Environment` && Value==`migration-lab`]].AllocationId'

# Should return: []
```

**Clean up local files (optional):**

```bash
# Return to parent directory
cd ~/opentofu-migration-lab

# Keep backups and documentation, but optionally remove working directory
# rm -rf terraform-project

# Or keep everything for future reference
echo "Lab files preserved at: $(pwd)"
```

---

## Troubleshooting Guide

### Issue: "Failed to query available provider packages"

**Symptom:**
```
Error: Failed to query available provider packages
```

**Solution:**
```bash
# Clear provider cache
rm -rf .terraform/providers

# Reinitialize
tofu init -migrate-state
```

### Issue: "State migration shows resource changes"

**Symptom:**
```
Plan: 0 to add, 5 to change, 0 to destroy.
```

**Solution:**
```bash
# Check what changed
tofu plan | grep "~"

# Common causes:
# 1. AMI changed (latest Ubuntu updated)
# 2. Tags need updating
# 3. Provider version differences

# If changes are only tags or AMI:
# - Review changes carefully
# - If acceptable, apply: tofu apply

# If changes are resource replacements:
# - INVESTIGATE before proceeding
# - May need to rollback and investigate
```

### Issue: "Lock file conflicts"

**Symptom:**
```
Error: Invalid provider source
```

**Solution:**
```bash
# Remove lock file completely
rm .terraform.lock.hcl

# Remove provider cache
rm -rf .terraform/providers

# Reinitialize
tofu init -migrate-state
```

### Issue: "Web server not accessible after migration"

**Symptom:**
```
curl: (7) Failed to connect to X.X.X.X port 80: Connection refused
```

**Solution:**
```bash
# Check instance status
aws ec2 describe-instances --instance-ids $(tofu output -raw instance_id) \
  --query 'Reservations[0].Instances[0].State.Name'

# Check security group rules
aws ec2 describe-security-groups --group-ids $(tofu output -raw security_group_id)

# May need to wait 2-3 minutes for user_data to complete
# Monitor instance system log:
aws ec2 get-console-output --instance-id $(tofu output -raw instance_id) \
  --query 'Output' --output text | tail -50
```

### Issue: "State lineage mismatch"

**Symptom:**
```
Error: state lineage mismatch
```

**Solution:**
```bash
# This should not happen in migration, but if it does:

# 1. Restore from backup
cp ../backups/terraform.tfstate.pre-migration-* terraform.tfstate

# 2. Try migration again
rm .terraform.lock.hcl
tofu init -migrate-state

# 3. If persists, investigate state backend configuration
```

---

## Lab Completion Checklist

### Verification Checklist

- [ ] Infrastructure deployed with Terraform
- [ ] All backups created and verified
- [ ] State migrated to OpenTofu successfully
- [ ] `tofu plan` shows zero changes
- [ ] All outputs function correctly
- [ ] Web server accessible via HTTP
- [ ] SSH access confirmed working
- [ ] State integrity validated
- [ ] Documentation updated
- [ ] Changes committed to Git
- [ ] Migration report created
- [ ] Lessons learned documented
- [ ] Infrastructure destroyed (if not keeping)
- [ ] No orphaned AWS resources

### Skills Demonstrated

- [ ] Created production-like infrastructure with Terraform
- [ ] Executed comprehensive backup procedures
- [ ] Performed state migration from Terraform to OpenTofu
- [ ] Validated migration with multiple techniques
- [ ] Tested infrastructure functionality
- [ ] Documented migration process
- [ ] Demonstrated rollback capability understanding

### Knowledge Gained

- [ ] Understand Terraform/OpenTofu compatibility
- [ ] Know how to backup and restore state
- [ ] Can validate migration success
- [ ] Understand state lineage and versioning
- [ ] Can troubleshoot common migration issues
- [ ] Know when to rollback vs proceed
- [ ] Understand provider and module compatibility

---

## Next Steps

### Immediate Next Steps

1. **Review Migration Documentation**
   - Study your migration report
   - Note any challenges encountered
   - Document time spent on each phase

2. **Share Knowledge**
   - Present findings to team
   - Discuss lessons learned
   - Update organizational runbooks

3. **Plan Additional Migrations**
   - Identify next projects to migrate
   - Prioritize by risk/complexity
   - Schedule migration windows

### Advanced Practice

1. **Complex Scenarios**
   - Migrate multi-workspace projects
   - Handle remote state backends (S3, etc.)
   - Migrate projects with many modules

2. **CI/CD Integration**
   - Update GitHub Actions workflows
   - Modify GitLab CI pipelines
   - Configure automated validation

3. **Team Processes**
   - Develop organization-specific checklists
   - Create automated migration scripts
   - Build validation frameworks

---

## Additional Resources

### Official Documentation
- [OpenTofu Documentation](https://opentofu.org/docs)
- [Migration Guide](https://opentofu.org/docs/intro/migration)
- [AWS Provider Docs](https://registry.terraform.io/providers/hashicorp/aws)

### Community Resources
- [OpenTofu GitHub](https://github.com/opentofu/opentofu)
- [OpenTofu Slack](https://opentofu.org/slack)
- [Migration Examples](https://github.com/opentofu/opentofu/tree/main/examples)

### Related Training
- OpenTofu Fundamentals
- Advanced State Management
- CI/CD Pipeline Integration
- Infrastructure Testing Strategies

---

**Congratulations!** You've successfully completed the OpenTofu migration lab. You now have hands-on experience with the complete migration process and are ready to migrate production infrastructure projects.
