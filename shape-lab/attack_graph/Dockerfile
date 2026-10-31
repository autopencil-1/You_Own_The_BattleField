FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app.py db.py importer.py threat_model.py reconcile_paths.py /app/

USER 10001:10001
EXPOSE 8791
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8791"]
