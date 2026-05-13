# Zero Trust Conditional Access Blueprint

A production-ready Conditional Access policy matrix for Microsoft Entra ID, deployed and managed entirely through Terraform. Implements a comprehensive Zero Trust identity perimeter aligned to **Microsoft Zero Trust principles**, **Australian Essential Eight Maturity Level 2**, and **CIS Microsoft 365 Foundations Benchmark**.

---

## Solution Overview

### Problem Statement
Conditional Access policies are frequently configured manually through the portal, leading to inconsistent policy sets, undocumented decisions, configuration drift, and gaps that attackers exploit. A single misconfigured or missing policy can expose the entire tenant.

### Architecture Approach
This blueprint treats Conditional Access policy as code. Every policy is version-controlled, peer-reviewed, and deployed through a repeatable Terraform workflow. Policies are deployed in report-only mode by default, allowing sign-in impact analysis before enforcement, eliminating the risk of accidental lockout.

```
┌─────────────────────────────────────────────────────────────┐
│              Zero Trust Conditional Access Matrix            │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  CA001  Require MFA - All Users                              │
│  CA002  Phishing-Resistant MFA - Privileged Administrators   │
│  CA003  Block Legacy Authentication - All Users              │
│  CA004  Require Compliant Device - Sensitive Applications    │
│  CA005  Block High Risk Sign-ins - Real-time Risk Signal     │
│  CA006  MFA + Password Change - High Risk Users              │
│  CA007  Block Non-Trusted Countries - Location Control       │
│  CA008  Require MFA - Azure Management Plane                 │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│  Break-Glass Accounts excluded from ALL policies             │
│  Named Locations: Australia + Corporate IP Ranges            │
│  Authentication Strength: FIDO2 + Windows Hello              │
└──────────────────────────────────────────────────────────────┘
```

---

## Policy Matrix

| Policy ID | Name | Users | Apps | Controls |
|-----------|------|-------|------|----------|
| CA001 | Require MFA - All Users | All (excl. break-glass) | All | MFA |
| CA002 | Phishing-Resistant MFA - Admins | Privileged roles | All | FIDO2 or WHfB |
| CA003 | Block Legacy Authentication | All | All | Block |
| CA004 | Require Compliant Device | All | Sensitive apps | Compliant or Hybrid Join |
| CA005 | Block High Risk Sign-ins | All | All | Block (High risk) |
| CA006 | MFA + Password Change - High Risk Users | All | All | MFA + Password change |
| CA007 | Block Non-Trusted Countries | All | All | Block |
| CA008 | Require MFA - Azure Management | All | Azure Portal/API | MFA |

---

## Project Structure

```
zero-trust-conditional-access/
├── terraform/
│   ├── main.tf                      # All Conditional Access policy resources
│   ├── variables.tf                 # Input variable definitions
│   ├── outputs.tf                   # Policy IDs and resource outputs
│   └── terraform.tfvars.example     # Example variable values
├── docs/
│   └── deployment-guide.md          # Step by step deployment instructions
└── README.md
```

---

## Requirements

- Terraform >= 1.5.0
- AzureAD Terraform provider ~> 2.47
- Entra ID P2 licences (required for risk-based policies CA005 and CA006)
- Conditional Access Administrator or Global Administrator role

---

## Deployment

### 1. Initialise Terraform

```bash
cd terraform
terraform init
```

### 2. Configure Variables

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your break-glass UPNs and IP ranges
```

### 3. Deploy in Report-Only Mode First

```bash
# Preview all changes
terraform plan

# Deploy in report-only mode (default)
terraform apply
```

### 4. Validate in Sign-in Logs

Review Entra ID sign-in logs for 7 to 14 days with policies in report-only mode. Confirm no unexpected blocking before enforcing.

### 5. Switch to Enforcement

```bash
# In terraform.tfvars
policy_state = "enabled"

terraform apply
```

---

## Key Design Decisions

**Report-only by default.** The `policy_state` variable defaults to `enabledForReportingButNotEnforced`. This means policies are deployed safely and visible in sign-in logs without blocking any users, allowing impact analysis before enforcement.

**Break-glass accounts excluded from all policies.** Two emergency access accounts are explicitly excluded from every policy using object IDs, not group membership. This ensures administrative access is always available even if identity protection systems malfunction.

**Phishing-resistant MFA for admins.** Standard MFA can be bypassed through real-time phishing proxies. CA002 uses an Authentication Strength policy requiring FIDO2 or Windows Hello, which are hardware-bound and phishing-resistant by design.

**Risk-based policies require Entra ID P2.** CA005 and CA006 use real-time sign-in and user risk signals from Entra ID Protection. These require P2 licencing. The remaining policies function with P1.

**Infrastructure as Code only.** No manual portal changes. All policy changes go through Terraform plan and apply, ensuring every change is reviewed, version-controlled, and auditable.

---

## Roadmap

- Azure DevOps pipeline for automated Terraform plan and apply with approval gate
- Policy gap analysis script to identify user or app scenarios not covered by any policy
- Sentinel analytics rule to alert on break-glass account usage
- Token protection policy addition for high-value application sessions

---

## Author

**Daniel Tousi**
Senior Systems Engineer | Cloud Solution Architect
Azure | Microsoft 365 | Hybrid Infrastructure

[![LinkedIn](https://img.shields.io/badge/LinkedIn-danieltousi-0A66C2?style=flat&logo=linkedin)](https://www.linkedin.com/in/daniel-tousi-19293563/)
[![GitHub](https://img.shields.io/badge/GitHub-danieltousi-181717?style=flat&logo=github)](https://github.com/danieltousi)

---

## References

- [Microsoft Zero Trust Guidance](https://learn.microsoft.com/en-us/security/zero-trust/)
- [Conditional Access Best Practices](https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access)
- [Australian Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight)
- [Entra ID Protection Risk Policies](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-policies)
