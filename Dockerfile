# Small Python base image
FROM python:3.12-slim

# Make Python friendlier in containers
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Workdir inside the container
WORKDIR /app

# Install deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || true

# Copy the rest of the project
COPY . .

# Default entrypoint: run the tool; pass args at "docker run"
ENTRYPOINT ["python", "file_integrity_monitor.py"]
CMD ["--help"]
