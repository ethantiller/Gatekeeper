.PHONY: start-env status-env stop-env

start-env:
	uv run python -m gatekeeper.sandbox.environment up

status-env:
	uv run python -m gatekeeper.sandbox.environment status

stop-env:
	uv run python -m gatekeeper.sandbox.environment down

