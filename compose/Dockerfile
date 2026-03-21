FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /workspace
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY brain_gateway/ brain_gateway/
COPY camazotz_modules/ camazotz_modules/
COPY contracts/ contracts/

EXPOSE 8080
CMD ["uv", "run", "uvicorn", "brain_gateway.app.main:app", "--host", "0.0.0.0", "--port", "8080"]
