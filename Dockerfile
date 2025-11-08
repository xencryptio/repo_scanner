# Backend (Flask)
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies (git + build tools)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source files
COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
