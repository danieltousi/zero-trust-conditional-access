variable "policy_state" {
  description = "State of all Conditional Access policies. Use 'enabledForReportingButNotEnforced' for audit mode, 'enabled' for enforcement."
  type        = string
  default     = "enabledForReportingButNotEnforced"

  validation {
    condition     = contains(["enabled", "disabled", "enabledForReportingButNotEnforced"], var.policy_state)
    error_message = "Policy state must be 'enabled', 'disabled', or 'enabledForReportingButNotEnforced'."
  }
}

variable "break_glass_upns" {
  description = "UPNs of emergency access (break-glass) accounts. These are excluded from ALL Conditional Access policies."
  type        = list(string)
  sensitive   = true
}

variable "trusted_ip_ranges" {
  description = "List of trusted corporate IP ranges in CIDR notation."
  type        = list(string)
  default     = []
}

variable "mfa_exclusion_group_ids" {
  description = "Group IDs excluded from the base MFA policy (e.g. service accounts)."
  type        = list(string)
  default     = []
}

variable "privileged_role_ids" {
  description = "Entra ID role IDs considered privileged and subject to phishing-resistant MFA."
  type        = list(string)
  default = [
    "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", # SharePoint Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de", # Exchange Administrator
    "b0f54661-2d74-4c50-afa3-1ec803f12efe", # Billing Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7"  # Cloud Application Administrator
  ]
}

variable "sensitive_app_ids" {
  description = "Application IDs requiring compliant device access."
  type        = list(string)
  default     = ["All"]
}

variable "byod_group_ids" {
  description = "Group IDs for BYOD users excluded from compliant device requirement."
  type        = list(string)
  default     = []
}
