# Orkestratör + araçların tek imajı. Böylece Docker soketi mount etmeden,
# "native" runner ile paketlenmiş binary'leri kullanır.
# Çalıştırma:
#   docker run --rm -v "$PWD:/work" ghcr.io/m0corut/recon-orchestrator \
#     https://ornek.com --authorized

# nuclei binary'sini resmi imajdan al (sürüm tag ile sabitlenir;
# recon/runner.py içindeki TOOLS ile aynı tutun)
FROM projectdiscovery/nuclei:v3.11.1 AS nuclei
FROM projectdiscovery/subfinder:v2.17.0 AS subfinder
FROM projectdiscovery/katana:v1.8.0 AS katana

FROM python:3.12-slim

# nmap + DNS/openssl araçları + testssl bağımlılıkları.
# chromium: katana --crawl-headless (SPA endpoint keşfi) için; katana -sc bunu bulur.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap dnsutils bsdmainutils procps git ca-certificates \
        chromium musl \
    && rm -rf /var/lib/apt/lists/*
# katana's upstream binary is musl-linked (Alpine image); the musl package
# provides its loader so it runs on this glibc base.
ENV CHROME_PATH=/usr/bin/chromium

# nuclei
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=subfinder /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=katana /usr/local/bin/katana /usr/local/bin/katana

# testssl.sh (bash script + bundled openssl)
RUN git clone --depth 1 --branch v3.2.4 https://github.com/drwetter/testssl.sh.git /opt/testssl \
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
