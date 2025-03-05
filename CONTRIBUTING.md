# Installation for local development

You will need Python >=3.6 in order to execute the scripts. 

# Tests
You can run automatic tests using the command `make test_dev` or you can also run :
```shell script
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make test
deactivate
```

**N.B:** Make sure to be in the main **datalake2sentinel/** folder within your terminal.
# Files in common for Docker/Local instance and AzureFunction instance:
- The files below are common to all instances:
    - Datalake2Sentinel.constants.py
    - Datalake2Sentinel.logger.py
    - Datalake2Sentinel.launch.py
    - Datalake2Sentinel.Datalake2Sentinel.py
- The files below are specific to a Docker/Local instance:
    - core.py
    - .env
    - config.py
- The files below are specific to an AzureFunction instance:
    - Datalake2Sentinel.core.py
    - Datalake2Sentinel.config.py