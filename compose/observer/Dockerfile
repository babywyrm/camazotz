FROM python:3.13-slim

RUN groupadd -r observer && useradd -r -g observer -d /app observer

WORKDIR /app
COPY main.py .

USER observer
CMD ["python3", "main.py"]
