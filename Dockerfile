FROM python:3.8-alpine3.11
RUN mkdir -p /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY .. /app
WORKDIR /app


CMD ["python", "app.py"]