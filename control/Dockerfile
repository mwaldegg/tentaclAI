# tentacontrol – web admin for tentaclai
FROM python:3.15-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DEBIAN_FRONTEND=noninteractive

# docker CLI + compose (to rebuild/recreate the tentaclai service), curl for vendoring
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin docker-buildx-plugin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY control/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Frontend libraries are vendored at build time – no CDN at runtime
RUN mkdir -p /app/vendor \
    && curl -fsSL -o /app/vendor/htmx.min.js https://cdn.jsdelivr.net/npm/htmx.org@2.0.4/dist/htmx.min.js \
    && curl -fsSL -o /app/vendor/xterm.js https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js \
    && curl -fsSL -o /app/vendor/xterm.css https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css \
    && curl -fsSL -o /app/vendor/addon-fit.js https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.js \
    && curl -fsSL -o /app/vendor/cytoscape.min.js https://cdn.jsdelivr.net/npm/cytoscape@3.30.2/dist/cytoscape.min.js

COPY lib/tclib.py lib/egress-default.txt /app/
COPY VERSION /app/VERSION
COPY control/app/ /app/app/
COPY control/passwd.py /usr/local/bin/tentacontrol-passwd
COPY control/sshcli.py /usr/local/bin/tentacontrol-ssh
RUN chmod 0755 /usr/local/bin/tentacontrol-passwd /usr/local/bin/tentacontrol-ssh

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*"]
