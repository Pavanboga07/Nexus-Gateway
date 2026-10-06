FROM python:3.12-slim

WORKDIR /app

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install production dependencies only (tests live in requirements-dev.txt)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY relay/ ./relay/
COPY run.py .

EXPOSE 9000

CMD ["python", "run.py"]
