FROM python:3.13-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
RUN groupadd -r camazotz && useradd -r -g camazotz -d /app camazotz
COPY --from=builder /install /usr/local
WORKDIR /app
COPY app.py .
COPY templates/ ./templates/
USER camazotz
EXPOSE 3000
CMD ["gunicorn", "-b", "0.0.0.0:3000", "-w", "2", "--timeout", "30", "app:app"]
