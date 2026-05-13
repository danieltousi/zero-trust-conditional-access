# Zero Trust Conditional Access Blueprint
# Author: Daniel Tousi
# Description: Production-ready Conditional Access policy matrix for Entra ID
# Aligned to Zero Trust principles, Essential Eight ML2, and Microsoft best practices

terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
  }
  required_version = ">= 1.5.0"

  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "stterraformstate"
    container_name       = "tfstate"
    key                  = "conditional-access/terraform.tfstate"
  }
}

provider "azuread" {}

#region --- Data Sources ---

data "azuread_domains" "default" {
  only_initial = true
}

# Emergency access (break-glass) accounts excluded from all policies
data "azuread_users" "break_glass" {
  user_principal_names = var.break_glass_upns
}

# Named locations
resource "azuread_named_location" "australia" {
  display_name = "Australia - Trusted Locations"
  country {
    countries_and_regions                 = ["AU"]
    include_unknown_countries_and_regions = false
  }
}

resource "azuread_named_location" "trusted_ips" {
  display_name = "Corporate - Trusted IP Ranges"
  ip {
    ip_ranges = var.trusted_ip_ranges
    trusted   = true
  }
}

#endregion

#region --- Policy 1: Require MFA for All Users ---

resource "azuread_conditional_access_policy" "require_mfa_all_users" {
  display_name = "CA001 - Require MFA for All Users"
  state        = var.policy_state

  conditions {
    users {
      included_users  = ["All"]
      excluded_users  = data.azuread_users.break_glass.object_ids
      excluded_groups = var.mfa_exclusion_group_ids
    }
    applications {
      included_applications = ["All"]
    }
    client_app_types = ["browser", "mobileAppsAndDesktopClients"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

#endregion

#region --- Policy 2: Require Phishing-Resistant MFA for Admins ---

resource "azuread_conditional_access_policy" "require_phishing_resistant_mfa_admins" {
  display_name = "CA002 - Require Phishing-Resistant MFA for Administrators"
  state        = var.policy_state

  conditions {
    users {
      included_roles = var.privileged_role_ids
      excluded_users = data.azuread_users.break_glass.object_ids
    }
    applications {
      included_applications = ["All"]
    }
    client_app_types = ["all"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
    # Authentication strength requiring FIDO2 or Windows Hello
    authentication_strength_policy_id = azuread_authentication_strength_policy.phishing_resistant.id
  }
}

resource "azuread_authentication_strength_policy" "phishing_resistant" {
  display_name         = "Phishing-Resistant MFA"
  description          = "Requires FIDO2 security key or Windows Hello for Business"
  allowed_combinations = ["fido2", "windowsHelloForBusiness"]
}

#endregion

#region --- Policy 3: Block Legacy Authentication ---

resource "azuread_conditional_access_policy" "block_legacy_auth" {
  display_name = "CA003 - Block Legacy Authentication Protocols"
  state        = var.policy_state

  conditions {
    users {
      included_users = ["All"]
      excluded_users = data.azuread_users.break_glass.object_ids
    }
    applications {
      included_applications = ["All"]
    }
    client_app_types = ["exchangeActiveSync", "other"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

#endregion

#region --- Policy 4: Require Compliant Device for Corporate Apps ---

resource "azuread_conditional_access_policy" "require_compliant_device" {
  display_name = "CA004 - Require Compliant or Hybrid Joined Device"
  state        = var.policy_state

  conditions {
    users {
      included_users  = ["All"]
      excluded_users  = data.azuread_users.break_glass.object_ids
      excluded_groups = var.byod_group_ids
    }
    applications {
      included_applications = var.sensitive_app_ids
    }
    client_app_types = ["browser", "mobileAppsAndDesktopClients"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["compliantDevice", "domainJoinedDevice"]
  }
}

#endregion

#region --- Policy 5: Block High Risk Sign-ins ---

resource "azuread_conditional_access_policy" "block_high_risk_signin" {
  display_name = "CA005 - Block High Risk Sign-ins"
  state        = var.policy_state

  conditions {
    users {
      included_users = ["All"]
      excluded_users = data.azuread_users.break_glass.object_ids
    }
    applications {
      included_applications = ["All"]
    }
    client_app_types = ["all"]
    sign_in_risk_levels = ["high"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

#endregion

#region --- Policy 6: Require MFA for High Risk Users ---

resource "azuread_conditional_access_policy" "mfa_high_risk_users" {
  display_name = "CA006 - Require MFA and Password Change for High Risk Users"
  state        = var.policy_state

  conditions {
    users {
      included_users = ["All"]
      excluded_users = data.azuread_users.break_glass.object_ids
    }
    applications {
      included_applications = ["All"]
    }
    client_app_types = ["all"]
    user_risk_levels = ["high"]
  }

  grant_controls {
    operator          = "AND"
    built_in_controls = ["mfa", "passwordChange"]
  }
}

#endregion

#region --- Policy 7: Block Access from Non-Trusted Countries ---

resource "azuread_conditional_access_policy" "block_non_trusted_countries" {
  display_name = "CA007 - Block Access from Non-Trusted Countries"
  state        = var.policy_state

  conditions {
    users {
      included_users = ["All"]
      excluded_users = data.azuread_users.break_glass.object_ids
    }
    applications {
      included_applications = ["All"]
    }
    client_app_types = ["all"]
    locations {
      included_locations = ["All"]
      excluded_locations = [
        azuread_named_location.australia.id,
        "AllTrusted"
      ]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

#endregion

#region --- Policy 8: Require MFA for Azure Management ---

resource "azuread_conditional_access_policy" "require_mfa_azure_mgmt" {
  display_name = "CA008 - Require MFA for Azure Management"
  state        = var.policy_state

  conditions {
    users {
      included_users = ["All"]
      excluded_users = data.azuread_users.break_glass.object_ids
    }
    applications {
      # Azure Management application ID
      included_applications = ["797f4846-ba00-4fd7-ba43-dac1f8f63013"]
    }
    client_app_types = ["all"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

#endregion
