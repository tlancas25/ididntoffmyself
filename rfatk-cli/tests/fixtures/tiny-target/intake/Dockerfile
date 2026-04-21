FROM python:3.12-slim

# Note: we never add a non-root user. The container runs as root by default.
# Secondary planted bug for the container-infra specialist — MEDIUM severity:
# Dockerfile final stage should use a non-root USER.

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py db.py users.py ./

EXPOSE 8080
CMD ["python", "app.py"]
