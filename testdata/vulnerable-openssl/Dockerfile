FROM debian:bookworm-slim

# Build and scan only inside this disposable fixture container.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc libc6-dev python3 python3-requests python3-pyelftools ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pin the historical Debian repository and OpenSSL packages. Do not upgrade
# these packages: their old versions are the positive vulnerability test case.
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20230501T000000Z/ bookworm main' \
        > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends --allow-downgrades \
        libssl3=3.0.8-1 libssl-dev=3.0.8-1 openssl=3.0.8-1 \
    && rm -rf /var/lib/apt/lists/*

COPY testdata/vulnerable-openssl/probe.c /fixture/probe.c
RUN gcc -Wall -Wextra -o /fixture/openssl-probe /fixture/probe.c -lcrypto \
    && /fixture/openssl-probe

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "src/binsentry.py"]
CMD ["scan", "/fixture/openssl-probe"]
