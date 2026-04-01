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
3. Store the required Azure credentials in Azure Key Vault and expose them to the Function App through Key Vault references:

```
CLIENT-ID=<CLIENT_ID>
TENANT-ID=<TENANT_ID>
CLIENT-CREDENTIAL=<CLIENT_CREDENTIAL>
WORKSPACE-ID=<WORKSPACE_ID>
```

4. Store the required Datalake settings in Azure Key Vault and expose them to the Function App through Key Vault references:

```
DATALAKE-TOKEN=<DATALAKE_LONGTERM_TOKEN>
DATALAKE-ENV=<prod|preprod>
```

If `DATALAKE_ENV` is not set, `prod` is the default value.


5. If you plan to use a certificate for Azure authentication. Generate a new certificate with the name "cert" and upload the public key in the app registration.
6. Create an Azure Function in your Azure subscription, this needs to be a Linux based Python 3.8+ function.
7. Upload the code to your Azure Function.

   - If you are using VSCode, this can be done by clicking the Azure Function folder and selecting "Deploy to Function App", provided you have the Azure Functions extension installed.
   - If using Powershell, you can upload the ZIP file using the following command: `Publish-AzWebapp -ResourceGroupName <resourcegroupname> -Name <functionappname> -ArchivePath <path to zip file> -Force`. If you want to make changes to the ZIP-file, simply send the contents of the `AzureFunction`-folder (minus any `.venv`-folder you might have created) to a ZIP-file and upload that.
   - If using AZ CLI, you can upload the ZIP file using the following command: `az functionapp deployment source config-zip --resource-group <resourcegroupname> --name <functionappname> --src <path to zip file>`.

8. Add the Azure credential application settings `CLIENT_ID`, `TENANT_ID`, `CLIENT_CREDENTIAL`, and `WORKSPACE_ID` in your Azure Function, each as a Key Vault reference (for example: `@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/CLIENT-ID/)`).
9. Do the same for the Datalake settings `DATALAKE_TOKEN` and `DATALAKE_ENV` (for example: `@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/DATALAKE-TOKEN/)`).
10. Do the same for the `CLIENT_CERTIFICATE` secret if needed (`@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/certificates/cert/)`)
11. Add a "New application setting" (env variable) `TIMER_TRIGGER_SCHEDULE` and set it to run. The `TIMER_TRIGGER_SCHEDULE` takes a cron expression. For more information, see [Timer trigger for Azure Functions](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer?tabs=python-v2%2Cin-process&pivots=programming-language-python).
12. Any variable from the [`.env.sample`] file can be added as an application setting in your Azure Function to override its default value (e.g. `LOG_FILE` set to `/tmp/datalake2sentinel.log`).
13. In some case you need to change the value of env variable `FUNCTIONS_EXTENSION_VERSION` from `~4` to `~3`.
