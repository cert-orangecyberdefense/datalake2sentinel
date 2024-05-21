# Datalake to Microsoft Sentinel

Here we define the procedure to launch safely and efficiently the **Datalake2Sentinel** connector as an **Azure Function**.

## Installation

### Prerequisities

- An Azure Subscription
- A Microsoft Sentinel Instance

### Full Instructions

The full instructions can be found in [INSTALL.md](INSTALL.md)

### Summary

1. Create an app registration in the same Microsoft tenant where the Sentinel instance resides. The app requires Microsoft Sentinel Contributor assigned on the workspace.
2. Create a Keyvault in your Azure subscription
3. Add a new secret with the name "tenant" with the following value :

```json
{
  "clientId": "<CLIENT_ID>",
  "tenantId": "<TENANT_ID>",
  "clientCredential": "<CLIENT_CREDENTIAL>",
  "workspaceId": "<WORKSPACE_ID>"
}
```

4. Add a new secret with the name "datalake" and the value of your Datalake credentials as example

```json
{
  "dtlUsername": "<DATALAKE_USERNAME>",
  "dtlPassword": "<DATALAKE_PASSWORD>"
}
```

5. Iy you plan to use a certificate for Azure authentication. Generate a new certificate with the name "cert" and upload the public key in the app registration.
6. Create an Azure Function in your Azure subscription, this needs to be a Linux based Python 3.8+ function.
7. Modify config.py to your needs.
8. Upload the code to your Azure Function.

   - If you are using VSCode, this can be done by clicking the Azure Function folder and selecting "Deploy to Function App", provided you have the Azure Functions extension installed.
   - If using Powershell, you can upload the ZIP file using the following command: `Publish-AzWebapp -ResourceGroupName <resourcegroupname> -Name <functionappname> -ArchivePath <path to zip file> -Force`. If you want to make changes to the ZIP-file, simply send the contents of the `AzureFunction`-folder (minus any `.venv`-folder you might have created) to a ZIP-file and upload that.
   - If using AZ CLI, you can upload the ZIP file using the following command: `az functionapp deployment source config-zip --resource-group <resourcegroupname> --name <functionappname> --src <path to zip file>`.

9. Add a "New application setting" (env variable) to your Azure Function named `tenant`. Create a reference to the key vault previously created (`@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/tenant/)`).
10. Do the same for the `datalake` secret (`@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/datalake/)`)
11. Do the same for the `certificate` secret if needed (`@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/cert/)`)
12. Add a "New application setting" (env variable) `timerTriggerSchedule` and set it to run. The `timerTriggerSchedule` takes a cron expression. For more information, see [Timer trigger for Azure Functions](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer?tabs=python-v2%2Cin-process&pivots=programming-language-python).
