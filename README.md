# Datalake to Microsoft Sentinel integration

## About The Project

The Datalake to Microsoft Sentinel integration allows you to push threat indicators from Orange Cyberdefense **Datalake** Platform to Microsoft **Sentinel** SIEM solution.

## Getting Started

### Prerequisites

First of all, you need to have a **Datalake account**. If so, follow the steps below if you want to run the **datalake2sentinel** connector in a dedicate server.

* Rename the file `config.py.default` to `config.py` and adapt the values according to your usage. This file is use to configure the **Datalake API requests** which will be executed and the **behavior** of the Datalake2Sentinel integration.
* Rename the file `.env.default` to `.env` and replace the environment variables with yours. This file is use to define all the credentials for **Datalake API** and **Azure**.

### Usage

It is important to note that the **datalake2sentinel** connector is divided in two parts:

1) The **job** part which is the core of the connector and which code is locate in the actual repository. It handle all the logic which include getting threats indicators from Datalake, formatting them to STIX format and sending them to Sentinel through the **Upload Indicator API**.
2) The **Data connector** part, which can be downloaded on the Azure Marketplace and handle the monitoring of the connector.    

You can launch the **datalake2sentinel** connector using two methods:

1) **Running on a dedicated server**: with this approach you can use one of the following command
    * Execute the command `make run` to install all the dependencies and launch the integration directly using **Python**.
    * Or execute only one of the commands `make run_docker` or `docker build . -t datalake2sentinel && docker run datalake2sentinel` to run the connector in a docker container.
2) **Using an Azure Function**: follow the documentation [AzureFunction](AzureFunction/README.md) to easily setup an Azure Function which will handle the execution of the connector. 