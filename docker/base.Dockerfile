FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git curl ca-certificates python3 python3-pip python3-venv strace build-essential \
    && rm -rf /var/lib/apt/lists/*

# uv so repo images can run `uv sync`; corepack for pnpm and yarn.
COPY --from=ghcr.io/astral-sh/uv:0.11.8 /uv /uvx /usr/local/bin/
RUN corepack enable

# The node image already has uid 1000 as "node": rename it instead of adding a second user.
RUN groupmod -n sandbox node \
    && usermod -l sandbox -d /home/sandbox -m node \
    && mkdir -p /workspace \
    && chown sandbox:sandbox /workspace

# Tripwire files are NOT baked in: values are per session and planted at run time.
WORKDIR /workspace
USER sandbox
CMD ["sleep", "infinity"]
