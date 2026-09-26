FROM python:3.12-slim 

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt #to keep the image size small

COPY app/app.py . 

# Set environment variables it can be changed during runtime if needed
ENV FLASK_APP=app.py \    
    PORT=5000 \
    DB_PATH=/app/users.db

EXPOSE 5000
CMD ["python", "app.py"]