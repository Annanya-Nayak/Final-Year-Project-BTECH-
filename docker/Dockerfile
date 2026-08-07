FROM python:3.11-slim-bullseye
 
RUN apt-get update && apt-get install -y \
    cmake build-essential libssl-dev git curl \
    && rm -rf /var/lib/apt/lists/*
 
WORKDIR /app
 
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
 
RUN python -c "from transformers import pipeline; pipeline('sentiment-analysis', \
    model='distilbert-base-uncased-finetuned-sst-2-english', device=-1)"
 
EXPOSE 8000
 
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
