package ecs_security

# Requirement 1: Block Public IP Assignment
deny["VIOLATION: Fargate service AssignPublicIp is ENABLED. Must be DISABLED"] {
    service := input.Resources[_]
    service.Type == "AWS::ECS::Service"
    service.Properties.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp == "ENABLED"
}

# Requirement 2: Disable Host Network Mode
deny["VIOLATION: TaskDefinition uses host network mode. Use awsvpc instead"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    task_def.Properties.NetworkMode == "host"
}

# Requirement 3: Port Mapping Restrictions - SSH
deny["VIOLATION: Container exposes SSH port (22). Blocked for security"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    port_mapping := container.PortMappings[_]
    port_mapping.ContainerPort == 22
}

# Requirement 3: Port Mapping Restrictions - MySQL
deny["VIOLATION: Container exposes MySQL port (3306). Blocked for security"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    port_mapping := container.PortMappings[_]
    port_mapping.ContainerPort == 3306
}

# Requirement 3: Port Mapping Restrictions - PostgreSQL
deny["VIOLATION: Container exposes PostgreSQL port (5432). Blocked for security"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    port_mapping := container.PortMappings[_]
    port_mapping.ContainerPort == 5432
}

# Requirement 3: Port Mapping Restrictions - Redis
deny["VIOLATION: Container exposes Redis port (6379). Blocked for security"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    port_mapping := container.PortMappings[_]
    port_mapping.ContainerPort == 6379
}

# Requirement 3: Port Mapping Restrictions - MongoDB
deny["VIOLATION: Container exposes MongoDB port (27017). Blocked for security"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    port_mapping := container.PortMappings[_]
    port_mapping.ContainerPort == 27017
}

# Requirement 3: Port Mapping Restrictions - Elasticsearch
deny["VIOLATION: Container exposes Elasticsearch port (9200). Blocked for security"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    port_mapping := container.PortMappings[_]
    port_mapping.ContainerPort == 9200
}

# Requirement 4: Security Group - Allow-all IPv4
deny["VIOLATION: SecurityGroup has allow-all rule (0.0.0.0/0). Use restricted CIDR"] {
    sg := input.Resources[_]
    sg.Type == "AWS::EC2::SecurityGroup"
    ingress_rule := sg.Properties.SecurityGroupIngress[_]
    ingress_rule.CidrIp == "0.0.0.0/0"
}

# Requirement 4: Security Group - Allow-all IPv6
deny["VIOLATION: SecurityGroup has allow-all rule (::/0). Use restricted CIDR"] {
    sg := input.Resources[_]
    sg.Type == "AWS::EC2::SecurityGroup"
    ingress_rule := sg.Properties.SecurityGroupIngress[_]
    ingress_rule.CidrIpv6 == "::/0"
}

# Requirement 5: Resource Limits - CPU defined
deny["VIOLATION: TaskDefinition missing CPU limits. Required for resource management"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    not task_def.Properties.Cpu
}

# Requirement 5: Resource Limits - CPU minimum
deny["VIOLATION: TaskDefinition CPU below minimum (256). Insufficient for containers"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    cpu := to_number(task_def.Properties.Cpu)
    cpu < 256
}

# Requirement 5: Resource Limits - CPU maximum
deny["VIOLATION: TaskDefinition CPU exceeds maximum (4096). Prevents DoS/cost overrun"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    cpu := to_number(task_def.Properties.Cpu)
    cpu > 4096
}

# Requirement 5: Resource Limits - Memory defined
deny["VIOLATION: TaskDefinition missing Memory limits. Required for resource management"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    not task_def.Properties.Memory
}

# Requirement 5: Resource Limits - Memory minimum
deny["VIOLATION: TaskDefinition Memory below minimum (512 MB). Insufficient"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    memory := to_number(task_def.Properties.Memory)
    memory < 512
}

# Requirement 5: Resource Limits - Memory maximum
deny["VIOLATION: TaskDefinition Memory exceeds maximum (30720 MB). Prevents DoS/cost"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    memory := to_number(task_def.Properties.Memory)
    memory > 30720
}

# Requirement 6: Image Provenance - ECR check
deny["VIOLATION: Container image not from internal ECR. Use .dkr.ecr. registry only"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    image := container.Image
    not regex.match(`.*\.dkr\.ecr\..*\.amazonaws\.com/.*`, image)
}

# Requirement 7: Tagging - Environment tag
deny["VIOLATION: Resource missing Environment tag. Required for tracking"] {
    resource := input.Resources[_]
    tags := object.get(resource.Properties, "Tags", [])
    env_tag := [t | t := tags[_]; t.Key == "Environment"]
    count(env_tag) == 0
}

# Requirement 7: Tagging - Application tag
deny["VIOLATION: Resource missing Application tag. Required for tracking"] {
    resource := input.Resources[_]
    tags := object.get(resource.Properties, "Tags", [])
    app_tag := [t | t := tags[_]; t.Key == "Application"]
    count(app_tag) == 0
}

# Requirement 7: Tagging - CostCenter tag
deny["VIOLATION: Resource missing CostCenter tag. Required for cost allocation"] {
    resource := input.Resources[_]
    tags := object.get(resource.Properties, "Tags", [])
    cost_tag := [t | t := tags[_]; t.Key == "CostCenter"]
    count(cost_tag) == 0
}

# Requirement 8: Instance Types - r7g.16xlarge
deny["VIOLATION: Instance uses r7g.16xlarge. Too large, blocks cost control"] {
    instance := input.Resources[_]
    instance.Type == "AWS::EC2::Instance"
    instance.Properties.InstanceType == "r7g.16xlarge"
}

# Requirement 8: Instance Types - r7g.metal
deny["VIOLATION: Instance uses r7g.metal. Too large, blocks cost control"] {
    instance := input.Resources[_]
    instance.Type == "AWS::EC2::Instance"
    instance.Properties.InstanceType == "r7g.metal"
}

# Requirement 8: Instance Types - c7g.metal
deny["VIOLATION: Instance uses c7g.metal. Too large, blocks cost control"] {
    instance := input.Resources[_]
    instance.Type == "AWS::EC2::Instance"
    instance.Properties.InstanceType == "c7g.metal"
}

# Requirement 8: Instance Types - m7g.metal
deny["VIOLATION: Instance uses m7g.metal. Too large, blocks cost control"] {
    instance := input.Resources[_]
    instance.Type == "AWS::EC2::Instance"
    instance.Properties.InstanceType == "m7g.metal"
}

# Requirement 8: Instance Types - x2iedn.32xlarge
deny["VIOLATION: Instance uses x2iedn.32xlarge. Too large, blocks cost control"] {
    instance := input.Resources[_]
    instance.Type == "AWS::EC2::Instance"
    instance.Properties.InstanceType == "x2iedn.32xlarge"
}

# Requirement 9: Image Naming Convention
deny["VIOLATION: Image tag doesn't match convention. Must start with api or ui and end with 6 alphanumeric"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    image := container.Image
    parts := split(image, ":")
    tag := parts[count(parts) - 1]
    not regex.match(`^(api|ui)[a-zA-Z0-9]{6}$`, tag)
}

# Requirement 10: Privileged Mode disabled
deny["VIOLATION: Container has Privileged mode enabled. Grants root access to host"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    container.Privileged == true
}

# Requirement 11: Non-root User - missing User
deny["VIOLATION: Container missing User field. Must specify non-root user"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    not container.User
}

# Requirement 11: Non-root User - UID 0
deny["VIOLATION: Container runs as UID 0 (root). Use non-root user"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    container.User == "0"
}

# Requirement 11: Non-root User - 'root' by name
deny["VIOLATION: Container runs as 'root' user. Use non-root user"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    container.User == "root"
}

# Requirement 11: Non-root User - 0:0
deny["VIOLATION: Container runs as 0:0 (root:root). Use non-root user"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    container.User == "0:0"
}

# Requirement 11: Non-root User - group 0
deny["VIOLATION: Container GID is 0 (root group). Use non-root group"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    container := task_def.Properties.ContainerDefinitions[_]
    user := container.User
    regex.match(`:0$`, user)
}

# Requirement 12: ExecutionRoleArn required
deny["VIOLATION: TaskDefinition missing ExecutionRoleArn. Required for image pull and logging"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    not task_def.Properties.ExecutionRoleArn
}

# Requirement 13: TaskRoleArn - no wildcards
deny["VIOLATION: TaskRoleArn contains wildcard (*). Use least-privilege roles"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    task_role := task_def.Properties.TaskRoleArn
    task_role
    contains(task_role, "*")
}

# Requirement 13: TaskRoleArn - no AdministratorAccess
deny["VIOLATION: TaskRoleArn uses AdministratorAccess. Use least-privilege roles"] {
    task_def := input.Resources[_]
    task_def.Type == "AWS::ECS::TaskDefinition"
    task_role := task_def.Properties.TaskRoleArn
    task_role
    contains(task_role, "AdministratorAccess")
}

# Main allow/deny rules
default allow = true

allow {
    count(deny) == 0
}
