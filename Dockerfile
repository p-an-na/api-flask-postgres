FROM python:3-slim
RUN mkdir -p /app
COPY ./ /app
WORKDIR /app

RUN pip install -r requirements.txt


CMD ["python", "app.py"]