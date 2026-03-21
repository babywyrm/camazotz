FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /workspace
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY brain_gateway/ brain_gateway/
COPY camazotz_modules/ camazotz_modules/
COPY contracts/ contracts/

FROM python:3.13-slim

RUN groupadd -r camazotz && useradd -r -g camazotz -d /workspace camazotz

WORKDIR /workspace
COPY --from=builder /workspace/.venv .venv/
COPY --from=builder /workspace/brain_gateway brain_gateway/
COPY --from=builder /workspace/camazotz_modules camazotz_modules/
COPY --from=builder /workspace/contracts contracts/

RUN chown -R camazotz:camazotz /workspace
USER camazotz

ENV PATH="/workspace/.venv/bin:$PATH"

EXPOSE 8080
CMD ["uvicorn", "brain_gateway.app.main:app", "--host", "0.0.0.0", "--port", "8080"]
