# syntax=docker/dockerfile:1
FROM python:3.12-alpine

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    DATA_DIR=/data

# tzdata so TZ in compose.override.yml means something.
RUN apk add --no-cache tzdata \
 && addgroup -g 1000 app \
 && adduser -D -u 1000 -G app -h /app app

WORKDIR /app
COPY app ./app
COPY tools/cli.py /usr/local/bin/spam-assassin
RUN chmod 0755 /usr/local/bin/spam-assassin \
 && mkdir -p /data \
 && chown -R app:app /app /data

USER app
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
    CMD ["python", "-m", "app.healthcheck"]

CMD ["python", "-m", "app.main"]
