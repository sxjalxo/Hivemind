# The FastAPI service, packaged so the whole product comes up with compose
# rather than through the three-step developer install.
#
# Two things this image carries that a plain Python image does not:
#
#   * the `docker` CLI. `container.py` is the only place that talks to Docker
#     and it shells out to the binary, behind an allowlist of exec / inspect /
#     kill. Copied from the official CLI image rather than installed from
#     Debian's `docker.io`, which drags in the whole engine to get one binary.
#
#     It is present but INERT by default: docker-compose.yml deliberately does
#     not mount the daemon socket, so evaluation runs refuse to start and the
#     analysis half carries on untouched. The binary stays so that mounting
#     the socket back is a one-line compose change and not a rebuild. See the
#     comment on the `backend` service for what that trade actually costs.
#   * `nmap`, for the service-scan probe. Without it that probe reports
#     `unknown` -- honestly, but the scan establishes nothing.
#
# Not installed: Ollama. It stays on the host for GPU access (an 8 GB card
# holds llama3.1:8b only at num_ctx 8192, and a container would not see the
# GPU on Windows anyway), so the container reaches it via host.docker.internal.
FROM python:3.12-slim

COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies are installed BEFORE the source is copied, against a stub
# `app` package, so editing code reuses the cached install layer -- only a
# change to pyproject.toml re-downloads anything. Until 2026-10-15 the source
# came first, so every edit re-fetched every package from PyPI, and a slow
# PyPI then failed the build (twice that week, as a misleading
# `ResolutionImpossible`). This needs neither a lock file nor a dependency
# list copied out of pyproject.toml, which would drift from it silently.
#
# It works because the install is editable: `-e` records WHERE `app` lives
# (/app/app), not its contents, so the real source copied over the stub is
# what imports. `scripts` is not installed at all; it is imported from the
# working directory, as on a dev machine (`python -m scripts.preflight`).
#
# `-e` also matches the documented dev install exactly. pyproject.toml
# declares no build-system or package discovery, so a non-editable
# `pip install .` would be relying on setuptools auto-discovery to pick `app`
# out of a tree that also holds `tests` and `scripts`.
COPY pyproject.toml alembic.ini ./
RUN mkdir app && touch app/__init__.py && pip install --no-cache-dir -e .
COPY app ./app
COPY scripts ./scripts

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Every default here points at a compose service name. `evaluation_target_host`
# already defaults to `cowrie` in app/config.py and is correct from inside the
# compose network -- it is the HOST-run backend that has to override it to
# 127.0.0.1, which is the opposite of what the README's note might suggest.
ENV PG_DSN=postgresql+asyncpg://hivemind:hivemind@postgres:5432/hivemind \
    ES_URL=http://elasticsearch:9200 \
    OLLAMA_HOST=http://host.docker.internal:11434

EXPOSE 8000
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
