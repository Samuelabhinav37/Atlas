FROM python:3.12-slim

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY apps/ ./apps/
COPY policies/ ./policies/
COPY taxonomy/ ./taxonomy/

RUN pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["python", "-m", "atlas.cli", "serve", "--host", "0.0.0.0", "--port", "8000"]
