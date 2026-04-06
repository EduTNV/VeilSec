FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y gcc libpq-dev curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m -u 1001 veilsec
USER veilsec
CMD ["celery", "-A", "apps.worker_dast.worker", "worker", "--loglevel=info", "--queues=dast"]
