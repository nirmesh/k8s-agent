FROM python:3.12-slim

WORKDIR /app/backend

RUN apt-get update && apt-get install -y curl ca-certificates && \
    KUBECTL_VERSION=$(curl -L --fail -s https://dl.k8s.io/release/stable.txt | tr -d '\n') && \
    curl -LO --fail "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" && \
    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl && \
    rm kubectl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/backend

ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
