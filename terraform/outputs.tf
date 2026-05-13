output "policy_ids" {
  description = "Map of all deployed Conditional Access policy IDs"
  value = {
    ca001_require_mfa_all_users              = azuread_conditional_access_policy.require_mfa_all_users.id
    ca002_phishing_resistant_mfa_admins      = azuread_conditional_access_policy.require_phishing_resistant_mfa_admins.id
    ca003_block_legacy_auth                  = azuread_conditional_access_policy.block_legacy_auth.id
    ca004_require_compliant_device           = azuread_conditional_access_policy.require_compliant_device.id
    ca005_block_high_risk_signin             = azuread_conditional_access_policy.block_high_risk_signin.id
    ca006_mfa_high_risk_users                = azuread_conditional_access_policy.mfa_high_risk_users.id
    ca007_block_non_trusted_countries        = azuread_conditional_access_policy.block_non_trusted_countries.id
    ca008_require_mfa_azure_mgmt             = azuread_conditional_access_policy.require_mfa_azure_mgmt.id
  }
}

output "named_location_ids" {
  description = "Named location resource IDs"
  value = {
    australia   = azuread_named_location.australia.id
    trusted_ips = azuread_named_location.trusted_ips.id
  }
}

output "authentication_strength_id" {
  description = "Phishing-resistant authentication strength policy ID"
  value       = azuread_authentication_strength_policy.phishing_resistant.id
}
