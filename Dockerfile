# Build stage
FROM python:3.13-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    python3-dev \
    file-dev \
    curl

# Create and activate virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir --force-reinstall yt-dlp==2025.5.22

# Final stage
FROM python:3.13-alpine

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install runtime dependencies
RUN apk add --no-cache \
    ffmpeg \
    file-dev

# Create non-root user and application directories
RUN adduser -D -u 1000 botuser && \
    mkdir -p /app/sessions /app/downloads && \
    chown -R botuser:botuser /app

# Set up application directory
WORKDIR /app

# Copy application code
COPY --chown=botuser:botuser . .

# Ensure sessions directory has correct permissions
RUN chmod 755 /app/sessions && \
    chown -R botuser:botuser /app/sessions

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
USER botuser

CMD ["python", "bot.py"] 