FROM python:3.8-alpine3.11
RUN mkdir -p /app
COPY .. /app
WORKDIR /app

RUN pip install -r requirements.txt


CMD ["python", "app.py"]