FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl iputils-ping iproute2 util-linux \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app/ ./
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
