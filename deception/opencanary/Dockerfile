FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libssl-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir opencanary

RUN mkdir -p /var/log/opencanary /root

COPY opencanary.conf /root/.opencanary.conf

EXPOSE 8080 2121 3306

CMD ["opencanaryd", "--dev"]
