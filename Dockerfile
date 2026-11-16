# syntax=docker/dockerfile:1.7
# ---------- build giao diện ----------
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npx vite build

# ---------- backend + collector ----------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data STATIC_DIR=/app/static TZ=Asia/Ho_Chi_Minh
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping tzdata ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# GoFlow2 (NetFlow / IPFIX / sFlow collector, BSD-3) for "Network traffic" – IT Ops starts it itself when enabled.
# Pinned version + SHA-256 of the official release file (checked by Docker at build time).
ADD --chmod=755 --checksum=sha256:63d3bb6c4e458f56ae3268eac74979da1fee0cea5342362295e7d587784af14b \
    https://github.com/netsampler/goflow2/releases/download/v2.2.7/goflow2-2.2.7-linux-amd64 /usr/local/bin/goflow2
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY backend/migrations ./migrations
COPY backend/alembic.ini .
COPY --from=web /web/dist ./static
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT','8000'))" || exit 1
# PORT đọc từ .env (docker-compose dùng network_mode: host nên cổng app = cổng trên máy chủ)
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers"]
