# Aegis Agent 本体镜像（编排层，不含安全工具；高危动作在 sandbox 镜像内执行）
FROM python:3.12-slim

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap tshark && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY roe.example.yaml ./roe.yaml
ENV PYTHONPATH=/app/src

ENTRYPOINT ["python", "-m", "secagent.main"]
