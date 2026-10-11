# Orkestratör + araçların tek imajı. Böylece Docker soketi mount etmeden,
# "native" runner ile paketlenmiş binary'leri kullanır.
# Çalıştırma:
#   docker run --rm -v "$PWD:/work" ghcr.io/m0corut/recon-orchestrator \
#     https://ornek.com --authorized

# nuclei binary'sini resmi imajdan al (sürüm tag ile sabitlenir)
FROM projectdiscovery/nuclei:latest AS nuclei

FROM python:3.12-slim

# nmap + DNS/openssl araçları + testssl bağımlılıkları
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap dnsutils bsdmainutils procps git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# nuclei
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei

# testssl.sh (bash script + bundled openssl)
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir ".[dns]"

# non-root
RUN useradd -m scanner
USER scanner
WORKDIR /work

ENTRYPOINT ["recon"]
CMD ["--help"]
