FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY bouncer.py .

# Standard library only. Runs as root but compose drops every capability except the
# few it needs (see docker-compose.yml), which also stops it reading NPM's processes.
CMD ["python", "/app/bouncer.py"]
