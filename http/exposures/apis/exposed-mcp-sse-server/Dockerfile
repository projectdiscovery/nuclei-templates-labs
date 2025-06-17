FROM python:3.11-slim

WORKDIR /app

COPY . /app

# Install dependencies if you have a requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "main.py"]