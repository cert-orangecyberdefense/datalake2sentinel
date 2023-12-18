init:
	pip install -r requirements.txt

lint:
	black .

clean:
	rm -rf __pycache__

run:
	python core.py
	rm -rf .venv

test_dev:
	( \
		python3 -m venv .venv; \
		. .venv/bin/activate; \
		pip install -r requirements.txt; \
		pytest; \
		deactivate \
	)

test: lint
	@pytest

start_env:
	python3 -m venv .venv
	. .venv/bin/activate
	pip install -r requirements.txt