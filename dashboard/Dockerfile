FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static

# World map outlines (Natural Earth, public domain, packaged by world-atlas).
# Fetched at build time so the running container never needs a CDN.
ADD https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json /app/static/vendor/countries-110m.json

EXPOSE 8088/tcp 5514/udp
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8088/api/health', timeout=4)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8088", "--proxy-headers"]
