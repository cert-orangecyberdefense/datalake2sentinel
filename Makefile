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
		pytest $$path; \
		deactivate \
	)

test: lint
	@pytest $$path

start_env:
	python3 -m venv .venv
	. .venv/bin/activate
	pip install -r requirements.txt