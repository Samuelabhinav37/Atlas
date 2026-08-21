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

# Run as a non-root user -- this is a security gateway that parses untrusted,
# adversarial input (SQL/shell/path payloads) by design, so it should not
# also hold root inside its own container if one of those parsers is ever
# defeated.
RUN useradd --create-home --uid 10001 atlas \
    && chown -R atlas:atlas /app
USER atlas

EXPOSE 8000

CMD ["python", "-m", "atlas.cli", "serve", "--host", "0.0.0.0", "--port", "8000"]
