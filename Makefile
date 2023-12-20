init:
	pip install -r requirements.txt

lint:
	black .

clean:
	find . -type d -name __pycache__  -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	rm -rf .venv

run: init
	python3 core.py

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