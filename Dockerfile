FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=18765

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tests ./tests
COPY desktop.py .

EXPOSE 18765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS -X POST http://127.0.0.1:18765/api/system/self-test | grep -q '"all_passed":true' || exit 1

CMD ["uvicorn", "app.server:app", "--host", "0.0.0.0", "--port", "18765"]
