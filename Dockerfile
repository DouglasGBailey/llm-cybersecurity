# LLM Cybersecurity Agent Platform -- REST API image.
#
# 0.0.0.0 as the bind address below is correct/standard for a container --
# exposure is controlled by `docker run -p` port publishing at the host
# level, not by the in-container bind address (unlike running the API
# directly on a host, where src/api.py defaults to 127.0.0.1 -- see
# README's "REST API" section for that distinction).
#
# Real config/scope.yaml, config/alerts.yaml, config/llm_probes.yaml,
# data/, reports/, and logs/ are intentionally NOT baked into this image
# (user-specific, gitignored) -- mount them as volumes at run time.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap dnsutils whois \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY config/*.example.yaml config/

EXPOSE 8000

CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]
