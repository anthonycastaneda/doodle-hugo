---
author: "Anthony Castañeda"
title: "Entra ID"
date: "2025-03-23"
description: "ChatGPT creates documentation"
tags: ["blog","chatgpt"]
---

## Entra PowerShell

To work with Enterprise Applications in Azure using PowerShell, particularly for Entra ID (previously Azure AD), you'll typically use the **AzureAD** or **Microsoft.Graph** module for interacting with these resources. Below is an example of a PowerShell script that demonstrates how to interact with an **Enterprise Application** in Entra ID using the **Microsoft.Graph** module.

### Prerequisites

1. **Microsoft.Graph PowerShell Module**: If you don't have it installed, use the following to install it:

   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```

2. **Login**: You'll need to authenticate with your Azure tenant. If you're using multi-tenant authentication, you may need admin consent for specific actions.

---

### Example Script for Managing Enterprise Applications

This script will cover basic tasks, such as:

1. Logging in to Azure.
2. Fetching a list of Enterprise Applications.
3. Assigning roles or permissions to the app.

```PowerShell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All"

# Get all Enterprise Applications
$enterpriseApps = Get-MgServicePrincipal

# Display list of Enterprise Applications (Service Principals)
$enterpriseApps | Select DisplayName, AppId, Id

# Example: Get details of a specific Enterprise Application by AppId
$appId = "your-app-id-here"  # Replace with your Enterprise Application's AppId
$enterpriseApp = Get-MgServicePrincipal -ServicePrincipalId $appId

# Display details of the specific Enterprise Application
$enterpriseApp | Format-List DisplayName, AppId, Id, Description, AppRoleAssignedTo

# Example: Assign a role to the Enterprise Application
# First, find the role you want to assign
$roles = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $enterpriseApp.Id

# Display available roles
$roles | Select AppRoleId, PrincipalDisplayName, ResourceDisplayName

# Assign role (if necessary)
# Example: You'd assign a role like this (adjust based on your needs):
$roleId = "role-id"  # Replace with actual role ID
$resourceId = "resource-id"  # Replace with resource (service) ID

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $enterpriseApp.Id -AppRoleId $roleId -ResourceId $resourceId

Write-Host "Role Assigned Successfully!"
```

---

### Key Concepts

- **Service Principal**: This represents the application's identity in Azure AD.
- **App Roles**: These are permissions or roles assigned to an application, and the `AppRoleAssignedTo` refers to which roles are assigned.
- **Get-MgServicePrincipal**: Retrieves a list of service principals (Enterprise Applications).
- **New-MgServicePrincipalAppRoleAssignment**: Assigns an app role to a service principal.

---

### More advanced operations you can perform

- **Assigning users to an Enterprise Application**: Use `Add-MgUserToGroup` or `Add-MgServicePrincipalOwner` if you're adding a user to the application or managing permissions.
- **Deleting an Enterprise Application**: Use `Remove-MgServicePrincipal`.

---
