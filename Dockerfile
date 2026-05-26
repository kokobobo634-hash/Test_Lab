FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data /app/uploads

EXPOSE 5000

CMD ["python", "-c", "import app; app.init_db(); app.app.run(host='0.0.0.0', port=5000, debug=False)"]
