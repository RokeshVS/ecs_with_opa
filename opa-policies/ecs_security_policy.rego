package ecs_security

import data.lib

# ============================================================================
# ECS Security Policy - OPA v1 Rego Format
# ============================================================================
# This policy validates CloudFormation templates for ECS security compliance
# across networking, IAM, container configuration, and resource sizing

default allow = true

# ============================================================================
# VIOLATION 1: Public IP Assignment Detection
# ============================================================================
# ECS Fargate services should not assign public IPs
deny contains msg if {
    service := input.Resources[name]
    service.Type == "AWS::ECS::Service"
    service.Properties.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp == "ENABLED"
    msg := sprintf("VIOLATION: ECS Service '%s' has AssignPublicIp enabled. This is a security risk - disable public IP assignment", [name])
}

# ============================================================================
# VIOLATION 2: Host Network Mode Detection
# ============================================================================
# ECS TaskDefinitions should not use host network mode
deny contains msg if {
    task := input.Resources[name]
    task.Type == "AWS::ECS::TaskDefinition"
    task.Properties.NetworkMode == "host"
    msg := sprintf("VIOLATION: TaskDefinition '%s' uses host network mode. Use 'awsvpc' or 'bridge' instead for container isolation", [name])
}

# ============================================================================
# VIOLATION 3: Sensitive Port Exposure Detection
# ============================================================================
# Block exposure of sensitive ports: SSH (22), MySQL (3306), PostgreSQL (5432),
# Redis (6379), MongoDB (27017), Elasticsearch (9200)
deny contains msg if {
    task := input.Resources[name]
    task.Type == "AWS::ECS::TaskDefinition"
    container := task.Properties.ContainerDefinitions[_]
    port_mapping := container.PortMappings[_]
    sensitive_port := [22, 3306, 5432, 6379, 27017, 9200]
    port_mapping.ContainerPort == sensitive_port[_]
    msg := sprintf("VIOLATION: TaskDefinition '%s' container exposes sensitive port %d. Block database and SSH ports from external access", [name, port_mapping.ContainerPort])
}

# ============================================================================
# VIOLATION 4: Security Group Allow-All Rule Detection
# ============================================================================
# Security groups should not have allow-all ingress rules
deny contains msg if {
    sg := input.Resources[name]
    sg.Type == "AWS::EC2::SecurityGroup"
    ingress := sg.Properties.SecurityGroupIngress[_]
    ingress.IpProtocol == "-1"
    ingress.CidrIp == "0.0.0.0/0"
    msg := sprintf("VIOLATION: SecurityGroup '%s' allows all protocols from 0.0.0.0/0. This is a critical security risk - restrict ingress rules to specific ports and sources", [name])
}

# ============================================================================
# VIOLATION 5: CPU/Memory Limits Validation
# ============================================================================
# ECS TaskDefinitions must have reasonable minimum CPU and memory limits
deny contains msg if {
    task := input.Resources[name]
    task.Type == "AWS::ECS::TaskDefinition"
    cpu := to_number(task.Properties.Cpu)
    cpu < 512
    msg := sprintf("VIOLATION: TaskDefinition '%s' has CPU %s which is below minimum of 512. Increase CPU for adequate performance", [name, task.Properties.Cpu])
}

deny contains msg if {
    task := input.Resources[name]
    task.Type == "AWS::ECS::TaskDefinition"
    memory := to_number(task.Properties.Memory)
    memory < 1024
    msg := sprintf("VIOLATION: TaskDefinition '%s' has Memory %s which is below minimum of 1024 MB. Increase memory for adequate performance", [name, task.Properties.Memory])
}

# ============================================================================
# VIOLATION 6: ECR Image Provenance - Only Use ECR Registry
# ============================================================================
# Container images must come from ECR (Amazon's container registry), not Docker Hub
deny contains msg if {
    task := input.Resources[name]
    task.Type == "AWS::ECS::TaskDefinition"
    container := task.Properties.ContainerDefinitions[_]
    image := container.Image
    not contains(image, ".dkr.ecr.")
    msg := sprintf("VIOLATION: TaskDefinition '%s' container uses non-ECR image '%s'. Only use ECR images for security compliance - push images to ECR registry", [name, image])
}

# ============================================================================
# VIOLATION 7: Required Tags Validation
# ============================================================================
# All resources must have Environment, Application, and CostCenter tags
deny contains msg if {
    resource := input.Resources[name]
    resource.Type in ["AWS::ECS::TaskDefinition", "AWS::EC2::Instance", "AWS::IAM::Role"]
    not has_required_tags(resource.Properties.Tags)
    msg := sprintf("VIOLATION: Resource '%s' is missing required tags (Environment, Application, CostCenter). Add these tags for compliance and cost tracking", [name])
}

# ============================================================================
# VIOLATION 8: Instance Type Restrictions
# ============================================================================
# Block oversized instance types that are too expensive for typical workloads
deny contains msg if {
    instance := input.Resources[name]
    instance.Type == "AWS::EC2::Instance"
    blocked_types := ["r7g.16xlarge", "r6i.16xlarge", "m6i.16xlarge", "c6i.16xlarge", "x2gd.16xlarge"]
    instance.Properties.InstanceType == blocked_types[_]
    msg := sprintf("VIOLATION: EC2 Instance '%s' uses oversized instance type '%s'. Use appropriately-sized instances to control costs", [name, instance.Properties.InstanceType])
}

# ============================================================================
# VIOLATION 9: Container Image Naming Convention
# ============================================================================
# Images should follow semantic versioning or 'latest' for proper tracking
deny contains msg if {
    task := input.Resources[name]
    task.Type == "AWS::ECS::TaskDefinition"
    container := task.Properties.ContainerDefinitions[_]
    image := container.Image
    not regex.match("^.+:[a-zA-Z0-9._-]+$", image)
    msg := sprintf("VIOLATION: Container image '%s' doesn't follow naming convention. Use format: image:tag or image:version", [image])
}

# ============================================================================
# VIOLATION 10: Privileged Mode Disabled
# ============================================================================
# Containers should not run in privileged mode
deny contains msg if {
    task := input.Resources[name]
    task.Type == "AWS::ECS::TaskDefinition"
    container := task.Properties.ContainerDefinitions[_]
    container.Privileged == true
    msg := sprintf("VIOLATION: TaskDefinition '%s' has container with Privileged mode enabled. Disable privilege escalation for security", [name])
}

# ============================================================================
# VIOLATION 11: Non-Root User Enforcement
# ============================================================================
# Containers must not run as root (User: '0')
deny contains msg if {
    task := input.Resources[name]
    task.Type == "AWS::ECS::TaskDefinition"
    container := task.Properties.ContainerDefinitions[_]
    container.User == "0"
    msg := sprintf("VIOLATION: TaskDefinition '%s' container runs as root (UID 0). Run container as non-root user for container isolation", [name])
}

# ============================================================================
# VIOLATION 12: Execution Role Required
# ============================================================================
# ECS TaskDefinitions must have ExecutionRoleArn for CloudWatch Logs access
deny contains msg if {
    task := input.Resources[name]
    task.Type == "AWS::ECS::TaskDefinition"
    not task.Properties.ExecutionRoleArn
    msg := sprintf("VIOLATION: TaskDefinition '%s' is missing ExecutionRoleArn. This role is required for CloudWatch Logs and ECR image pull permissions", [name])
}

# ============================================================================
# VIOLATION 13: IAM Wildcard Permissions Detection
# ============================================================================
# IAM roles should not have wildcard permissions (Action: '*', Resource: '*')
deny contains msg if {
    role := input.Resources[name]
    role.Type == "AWS::IAM::Role"
    policy := role.Properties.Policies[_]
    statement := policy.PolicyDocument.Statement[_]
    statement.Action == "*"
    statement.Resource == "*"
    msg := sprintf("VIOLATION: IAM Role '%s' has wildcard permissions (Action:*, Resource:*). Apply least-privilege access principle - specify exact permissions needed", [name])
}

# ============================================================================
# Helper Functions
# ============================================================================

# Check if resource has all required tags
has_required_tags(tags) if {
    tags != null
    tag_keys := {tag.Key | tag := tags[_]}
    tag_keys["Environment"]
    tag_keys["Application"] 
    tag_keys["CostCenter"]
}

# Overall allow/deny decision
allow = count(deny) == 0
