# Datalake to Microsoft Sentinel integration

## About The Project

The Datalake to Microsoft Sentinel integration allows you to upload indicators from OrangeCyberdefense Datalake's API to Microsoft Sentinel SIEM solution.

## Getting Started
TODO
### Prerequisites
* Rename the file `config.py.default` to `config.py` and adapt the values according to your usage. This file is use to configure the **Datalake API requests** which will be execute and the **behaviour** of the Datalake2Sentinel integration.
* Rename the file `.env.default` to `.env` and replace the environment variables with yours. This file is use to define all the credentials for **Datalake API** and **Azure**.

### Usage
After the prerequisites are all setup, you can launch **datalake2sentinel** connector using two methods:

* Execute the command `make run` to install all the dependencies and launch the integration directly using **Python**.
* Or execute only one of the commands `make run_docker` or `docker build . -t datalake2sentinel && docker run datalake2sentinel` to run the connector in a docker container.