FROM python:3.13-slim
WORKDIR /app
COPY central/ /app/
COPY central/ui.html /app/ui.html
RUN useradd -r -u 10001 watch && mkdir /data && chown watch:watch /data
USER watch
ENV DB_PATH=/data/watch.sqlite3 WATCH_CONFIG=/app/config/targets.json AGENTS_FILE=/app/config/agents.json PORT=8080
CMD ["python", "-u", "/app/server.py"]
