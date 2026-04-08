FROM python:3.13-slim AS builder
WORKDIR /build
COPY frontend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
RUN groupadd -r camazotz && useradd -r -g camazotz -d /app camazotz
COPY --from=builder /install /usr/local
WORKDIR /app
COPY frontend/app.py .
COPY frontend/threat_map.py .
COPY frontend/templates/ ./templates/
COPY scripts/qa_runner/ ./qa_runner/
USER camazotz
EXPOSE 3000
CMD ["gunicorn", "-b", "0.0.0.0:3000", "-w", "2", "--timeout", "300", "app:app"]
