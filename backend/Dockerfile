FROM python:3.12-slim

WORKDIR /app

# OPA binary — for optional WASM policy compilation at build time  
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    curl -sL -o /usr/local/bin/opa \
      https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && \
    chmod +x /usr/local/bin/opa && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Compile base Rego policies to WASM bundle (used when OPA_URL points to gateway)
# Skips gracefully if OPA build fails — Python policy evaluation is the fallback
RUN opa build -t wasm -e 'data.codios.scope/allow' \
      policies/base/scope.rego policies/base/identity.rego \
      -o policies/bundle.tar.gz 2>/dev/null || \
    echo "OPA WASM build skipped — Python policy evaluation active"

EXPOSE 8080

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
