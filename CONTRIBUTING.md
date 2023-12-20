# Installation for local development

You will need Python 3.6+ in order to execute the scripts. 

# Tests
You can run automatic tests using the command `make test_dev` or you can also run :
```shell script
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make test_dev
```

**N.B:** Make sure to be in the **Integration/** folder withing your terminal.