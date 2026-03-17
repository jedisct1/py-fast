.PHONY: all install test lint format check clean dist

all: check test

install:
	uv sync

test:
	uv run python -m pytest tests/ -v

lint:
	uv run ruff check src/ tests/

format:
	uv run ruff format src/ tests/
	uv run ruff check --fix src/ tests/

check: lint
	uv run ruff format --check src/ tests/

clean:
	rm -rf dist/ build/ __pycache__ .pytest_cache
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -type d -exec rm -rf {} +

dist: clean
	uv build
