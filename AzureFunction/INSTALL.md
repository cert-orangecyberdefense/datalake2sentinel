# Step-by-Step Azure Function Setup

This step-by-step instruction guides you through the process of setting up a complete Azure Function that will acquire Threat Intelligence indicators from Orange Cyberdefense's Datalake, sanitize it, then writes it to Microsoft Sentinel instance.

The full setup consists of several Azure components:

1. **App Registration** - This app will get the permissions to write data to the **ThreatIntelligenceIndicator** table of Sentinel
2. **Keyvault** - contains the keys to automatically authenticate with the app registration
3. **Function** - contains the scripts to retrieve information from Datalake in interval, format it in _STIX format_ and then push it in Sentinel through the app registration

## Prerequisities

- An Azure Subscription
- A Microsoft Sentinel Instance
- [Threat Intelligence Solution installed](https://learn.microsoft.com/nb-no/azure/sentinel/connect-threat-intelligence-upload-api#enable-the-threat-intelligence-upload-indicators-api-data-connector-in-microsoft-sentinel) on the Microsoft Sentinel workspace

## App Registration

This is how to create and configure the app registration:

1. Open Azure via https://portal.azure.com
2. Go to the service App Registrations
3. Make a new registration
4. Give the new app a descriptive name, for instance: _datalake2sentinel_. Other settings can be left to default values.
5. (Optional) If you plan to use a secret credential to authenticate to the app:
   1. Click after creating the app registration in the overview page under Client credentials on _add a certificate or secret_
   2. Click under Client secrets on _New client secret_
   3. Give a description, for instance _D2S Azure Function_ and leave the recommended expiry value
   4. Copy the value of the new Client Secret, which need to be stored in an Azure Key Vault
6. [Add the created app registration to the Microsoft Sentinel Contributor role](https://learn.microsoft.com/nb-no/azure/sentinel/connect-threat-intelligence-upload-api#assign-a-role-to-the-application) on the relevant workspace.

## Keyvault

This is how to create a Key Vault and store the secret values in it:

1. Go to the service _Key vaults_
2. Click _Create key vault_
3. Configure the Key vault as you wish, pay attention to the region in which it is stored, for instance "France Central"

### Required secrets in Key Vault

From the App Registration, the Azure values are:

- **TENANT_ID** = the value stated at _Directory (tenant) ID_ in the App Registration overview
- **CLIENT_ID** = the value stated at _Application (client) ID_ in the App Registration overview
- **CLIENT_CREDENTIAL** = the value of the generated Client Secret (only if using client secret authentication)
- **WORKSPACE_ID** = the workspace id of the Sentinel workspace you want to write to

1. After creating the Key vault, under Objects click Secrets and create the following secrets:

```
CLIENT-ID=<CLIENT_ID>
TENANT-ID=<TENANT_ID>
CLIENT-CREDENTIAL=<CLIENT_CREDENTIAL>
WORKSPACE-ID=<WORKSPACE_ID>
DATALAKE-TOKEN=<DATALAKE_LONGTERM_TOKEN>
DATALAKE-ENV=<prod|preprod> (optional, defaults to `prod`)
```

2. (Only if using a certificate) Generate a new certificate for app registration.
   1. Under Objects click Certificates and create a new certificate
      - Select the Generate method
      - Name it `cert`
      - Enter a subject, for example: `"CN=<your-tenant>.onmicrosoft.com"`
      - Select PEM as Content Type
      - Other settings can be configured as needed
   2. Click on generated certificate and click _Download in CER format_. Remove the `.txt` extension from the downloaded file
   3. Go back to the app registration previously created
   4. Click on _Client & Secrets_ and go to _Certificates_
   5. Click on _Upload certificate_ and select the CER file you downloaded

## Function

This is how to create the Azure Function app:

### Create the Azure Function in the Azure Portal

1. Go to the service _Function App_
2. Click _Create_ to generate a new Azure Function

- Give the function a descriptive name
- Choose at Publish for _Code_, and _Python_ as the Runtime Stack. Again pay attention to the Region ("France Central")
- OS can remain Linux
- At plan type choose _App service plan_
- Other settings can be left to default values. Click _Review + Create_

3. Assign the correct RBAC to your Function so that it can access to secrets in Vault.

4. Go back to the Azure Function and click on _Configuration_
5. Add the Azure credential application settings as Key Vault references:
   - `CLIENT_ID`: `@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/CLIENT-ID/)`
   - `TENANT_ID`: `@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/TENANT-ID/)`
   - `CLIENT_CREDENTIAL`: `@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/CLIENT-CREDENTIAL/)`
   - `WORKSPACE_ID`: `@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/WORKSPACE-ID/)`
6. Add the Datalake application settings as Key Vault references:
   - `DATALAKE_TOKEN`: `@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/DATALAKE-TOKEN/)`
   - `DATALAKE_ENV`: `@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/DATALAKE-ENV/)`
7. (Only if using a certificate) Add a new application setting with the name `CLIENT_CERTIFICATE` and the Key Vault reference string `@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/certificates/cert/)`
8. Add a new application setting with the name `TIMER_TRIGGER_SCHEDULE`
   - The `TIMER_TRIGGER_SCHEDULE` takes a cron expression. For more information, see [Timer trigger for Azure Functions](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer?tabs=python-v2%2Cin-process&pivots=programming-language-python).
   - For example to run once every two hours cron expression: `0 */2 * * *`
9. Any variable from the [`.env.sample`](../.env.sample) file can be added as an application setting to override its default value (e.g. `LOG_FILE` set to `/tmp/datalake2sentinel.log`).
10. In some case you need to change the value of env variable `FUNCTIONS_EXTENSION_VERSION` from `~4` to `~3`.

### Upload the Function Code with Visual Studio Code

1. Download and install [Visual Studio Code](https://code.visualstudio.com/)
2. Install the [Azure Functions extension](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azurefunctions)
3. Open Visual Studio Code and open the folder containing this repo
4. If not generated automatically, create the folder `.vscode` at the root of the repository folder and replace all its files with the one in [.vscode](../.vscode/).
5. Right click on the folder called `Azure Function` and select _Deploy to Function App..._
6. Select the Azure Function you created in the previous steps and click _Deploy_

## Validation

Once all above steps are completed, the Azure Function will retrieve data at the time you have scheduled your function to run.

1. Go to the service _Microsoft Sentinel_
2. At the left-hand side click _Threat Intelligence_
3. You should now get a list of thousands threat indicators, with **Datalake - OrangeCyberdefense** as the source
