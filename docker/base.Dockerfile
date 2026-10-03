FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git curl ca-certificates python3 python3-pip python3-venv strace build-essential \
    && rm -rf /var/lib/apt/lists/*

# uv so repo images can run `uv sync`; corepack for pnpm and yarn.
COPY --from=ghcr.io/astral-sh/uv:0.11.8 /uv /uvx /usr/local/bin/

# Enable Corepack, then rename the default non-root user to sandbox_user.
# Then set /home/sandbox as the home directory for the new user.
RUN corepack enable \
    && groupmod -n sandbox_user node \
    && usermod -l sandbox_user -d /home/sandbox -m node \
    && mkdir -p /workspace \
    && chown sandbox_user:sandbox_user /workspace

# Tripwire files are NOT baked in: values are per session and planted at run time.
WORKDIR /workspace
USER sandbox_user
CMD ["sleep", "infinity"]
