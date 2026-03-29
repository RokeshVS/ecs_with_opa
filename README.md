# ECS with OPA

Automated security compliance checking for AWS ECS CloudFormation templates using Open Policy Agent (OPA).

## Overview

This repository enforces 13 security policies for ECS deployments via OPA/Rego. Policies are automatically validated in CI/CD when CloudFormation templates are pushed or modified.

## Directory Structure

```
├── opa-policies/                    # OPA security policies
│   └── ecs_security_policy.rego     # 13 security rules for ECS
├── cloudformation-templates/        # Sample CloudFormation templates
│   ├── ecs-compliant.yaml          # Example: passes all policies
│   └── ecs-non-compliant.yaml      # Example: violates policies
└── .github/workflows/
    ├── test-compliant.yml          # Tests ecs-compliant.yaml (expects pass)
    └── test-non-compliant.yml      # Tests ecs-non-compliant.yaml (expects fail)
```

## Security Policies Enforced

| # | Policy | Description |
|---|--------|-------------|
| 1 | No Public IPs | Block `AssignPublicIp: ENABLED` in Fargate services |
| 2 | Network Mode | Require `awsvpc` network mode (no host mode) |
| 3 | Port Restrictions | Block dangerous ports (22, 3306, 5432, 6379, 27017, 9200) |
| 4 | Security Groups | Prevent allow-all rules (0.0.0.0/0 and ::/0) |
| 5 | Resource Limits | Enforce CPU (256-4096) and Memory (512-30720 MB) bounds |
| 6 | Image Registry | Require internal ECR (`.dkr.ecr.*.amazonaws.com`) |
| 7 | Tagging | Require tags: `Environment`, `Application`, `CostCenter` |
| 8 | Instance Types | Block oversized instances (r7g.metal, c7g.metal, etc.) |
| 9 | Image Naming | Images must follow `api/uiXXXXXX:tag` pattern |
| 10 | Privileged Mode | Disable privileged container mode |
| 11 | Non-Root User | Containers must run as non-root user (not UID 0) |
| 12 | Execution Role | TaskDefinition must have `ExecutionRoleArn` |
| 13 | Least Privilege | TaskRoleArn cannot use wildcards or AdministratorAccess |

## Usage

### Local Testing

1. **Install OPA:**
   ```bash
   curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
   chmod +x opa
   ```

2. **Run Policy Check:**
   ```bash
   ./opa eval -d opa-policies/ -i cloudformation-templates/ecs-compliant.yaml data
   ```

## CI/CD Workflows

Two automated workflows validate templates:

**1. Compliant Template Test** ([test-compliant.yml](.github/workflows/test-compliant.yml))
- Validates `ecs-compliant.yaml`
- Expected: ✅ PASS (no violations)
- Triggers on changes to compliant template or policies

**2. Non-Compliant Template Test** ([test-non-compliant.yml](.github/workflows/test-non-compliant.yml))
- Validates `ecs-non-compliant.yaml`
- Expected: ❌ FAIL (policy violations detected)
- Triggers on changes to non-compliant template or policies
- Proves policies correctly identify violations

Both workflows:
- Run on PR and push to main
- Use OPA to validate policies
- Show clear pass/fail results

## Examples

**Compliant Template:** [ecs-compliant.yaml](cloudformation-templates/ecs-compliant.yaml)
- Uses ECR images
- Non-root container user
- Required tags
- Private networking
- Appropriate resource limits

**Non-Compliant Template:** [ecs-non-compliant.yaml](cloudformation-templates/ecs-non-compliant.yaml)
- Missing tags
- Privileged mode enabled
- Oversized resources
- Allow-all security group rules
