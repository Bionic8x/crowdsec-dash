FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static

# World map outlines (Natural Earth, public domain, packaged by world-atlas).
# Fetched at build time so the running container never needs a CDN, and checked
# against a pinned SHA-256 so a tampered download fails the build.
ARG WORLD_ATLAS_URL=https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json
ARG WORLD_ATLAS_SHA256=2516c915867c7baf18ddec727aec46c315541a07cfb3d79a6559b05d5e94eee8
RUN python -c "import hashlib, sys, urllib.request; \
d = urllib.request.urlopen('${WORLD_ATLAS_URL}', timeout=60).read(); \
h = hashlib.sha256(d).hexdigest(); \
sys.exit('countries-110m.json checksum mismatch: ' + h) if h != '${WORLD_ATLAS_SHA256}' else None; \
open('/app/static/vendor/countries-110m.json', 'wb').write(d)"

EXPOSE 8088/tcp 5514/udp
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8088/api/health', timeout=4)" || exit 1

# Starts as root, fixes /data ownership, then runs uvicorn as PUID:PGID (see app/entrypoint.py).
ENTRYPOINT ["python", "-m", "app.entrypoint"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8088", "--proxy-headers"]
