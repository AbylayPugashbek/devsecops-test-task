FROM python:3.11-slim

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel jaraco.context \
    && pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN chown -R app:app /app
USER app

# Vuln: Debug mode in production, binding to 0.0.0.0
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
