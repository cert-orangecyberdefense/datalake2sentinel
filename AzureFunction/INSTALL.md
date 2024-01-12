# Step-by-Step Azure Function Setup

This step-by-step instruction guides you through the process of setting up a complete Azure Function that will acquire Threat Intelligence indicators from Orange Cyberdefense's Datalake, sanitize it, then writes it to Microsoft Sentinel instance. 

The full setup consists of several Azure components:

1. **App Registration** - This app will get the permissions to write data to the **ThreatIntelligenceIndicator** table of Sentinel
2. **Keyvault** - contains the keys to automatically authenticate with the app registration
3. **Function** - contains the scripts to retrieve information from Datalake in interval, format it in *STIX format* and then push it in Sentinel through the app registration

## Prerequisities

- An Azure Subscription 
- A Microsoft Sentinel Instance
- [Threat Intelligence Solution installed](https://learn.microsoft.com/nb-no/azure/sentinel/connect-threat-intelligence-upload-api#enable-the-threat-intelligence-upload-indicators-api-data-connector-in-microsoft-sentinel) on the Microsoft Sentinel workspace

## App Registration

This is how to create and configure the app registration:

1. Open Azure via https://portal.azure.com
2. Go to the service App Registrations
3. Make a new registration
4. Give the new app a descriptive name, for instance: *datalake2sentinel*. Other settings can be left to default values.
5. Click after creating the app registration in the overview page under Client credentials on *add a certificate or secret*
6. Click under Client secrets on *New client secret*
7. Give a description, for instance *D2S Azure Function* and leave the recommended expiry value
8. Copy the value of the new Client Secret, which need to be stored in an Azure Key Vault
9. [Add the created app registration to the Microsoft Sentinel Contributor role](https://learn.microsoft.com/nb-no/azure/sentinel/connect-threat-intelligence-upload-api#assign-a-role-to-the-application) on the relevant workspace.


## Keyvault

This is how to create a Key Vault and store the secret value in it:

1. Go to the service *Key vaults*
2. Click *Create key vault*
3. Configure the Key vault as you wish, pay attention to the region in which it is stored, for instance "France Central"

### Formatting the Secret value

From above App Registration, 4 elements are required to store in Keyvault a value in the correct format to make the script able to properly make use of the app.

- **TENANT_ID** = the value stated at _Directory (tenant) ID_ in the App Registration overview
- **CLIENT_ID** = the value stated at _Application (client) ID_ in the App Registration overview
- **CLIENT_CREDENTIAL** = the value you copied in the last step in creating the App Registration
- **WORKSPACE_ID** = the workspace id of the Sentinel workspace you want to write to

The combined value that should be stored in the Keyvault, is as follows, where the variable names including the <> should be replaced by above 4 values.

```json
{"clientId":"<CLIENT_ID>", "tenantId":"<TENANT_ID>", "clientCredential":"<CLIENT_CREDENTIAL>",  "workspaceId":"<WORKSPACE_ID>"}
```



### Add secrets to the Key Vault

1. After creating the Key vault, under Objects click Keys and create a new key
2. Enter the values that were copied from App Registration Secrets above
- the name of the key **MUST** be `tenant`
- The *Secret Value* will be the formatted secret value you created above
- Other settings can be left to default values
3. Add a new secret `datalake` with the value the following value
```json
{
    "dtlUsername":"<DATALAKE_USERNAME>",
    "dtlPassword":"<DATALAKE_PASSWORD>"
}
```

## Function

This is how the create the Azure Function app.

### Create the Azure Function in the Azure Portal

1. Go to the service *Function App*
2. Click *Create* to generate a new Azure Function
- Give the function a descriptive name
- Choose at Publish for *Code*, and *Python* as the Runtime Stack. Again pay attention to the Region ("France Central")
- OS can remain Linux
- At plan type choose *App service plan*
- Other settings can be left to default values. Click *Review + Create*
3. Assign the correct RBAC to your Function so that it can access to secrets in Vault.

4. Go back to the Azure Function and click on *Configuration*
5. Add a new application setting with the name `tenant` and the Key Vault reference string `@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/tenant/)`
6. Add a new application setting with the name `datalake` and the Key Vault reference string `@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/datalake/)`
7. Add a new application setting with the name `timerTriggerSchedule`
   * The `timerTriggerSchedule` takes a cron expression. For more information, see [Timer trigger for Azure Functions](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer?tabs=python-v2%2Cin-process&pivots=programming-language-python).
   * For example to run once every two hours cron expression: `0 */2 * * *`

### Upload the Function Code with Visual Studio Code

1. Download and install [Visual Studio Code](https://code.visualstudio.com/)
2. Install the [Azure Functions extension](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azurefunctions)
3. Open Visual Studio Code and open the folder containing this repo
4. Right click on the folder called `Azure Function` and select *Deploy to Function App...*
5. Select the Azure Function you created in the previous steps and click *Deploy*


## Validation

Once all above steps are completed, the Azure Function will retrieve data at the time you have scheduled your function to run.

1. Go to the service *Microsoft Sentinel*
2. At the left-hand side click *Threat Intelligence*
3. You should now get a list of thousands threat indicators, with **Datalake - OrangeCyberdefense** as the source