init:
	python3 -m venv .venv
	. .venv/bin/activate
	pip install -r AzureFunction/requirements.txt

lint:
	black .

clean:
	find . -type d -name __pycache__  -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	rm -rf .venv

run: init
	python3 AzureFunction/Datalake2Sentinel/run_local.py

run_docker:
	docker build  -t datalake2sentinel .
	docker run datalake2sentinel

test: init lint
	@pytest