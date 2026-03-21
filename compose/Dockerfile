FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

FROM python:3.13-slim

RUN groupadd -r camazotz && useradd -r -g camazotz -d /workspace camazotz

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY --from=builder /build/.venv /workspace/.venv
COPY --from=builder /build/pyproject.toml /build/uv.lock /workspace/

WORKDIR /workspace
COPY brain_gateway/ brain_gateway/
COPY camazotz_modules/ camazotz_modules/
COPY contracts/ contracts/

RUN chown -R camazotz:camazotz /workspace
USER camazotz

EXPOSE 8080
CMD ["uv", "run", "uvicorn", "brain_gateway.app.main:app", "--host", "0.0.0.0", "--port", "8080"]
