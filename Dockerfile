# Python    (DS223j   )
FROM python:3.9-slim

#    
WORKDIR /app

#   
COPY requirements.txt .

#   
RUN pip install --no-cache-dir -r requirements.txt

#    
COPY . .

# Waitress    (Port 8000)
CMD ["waitress-serve", "--host=0.0.0.0", "--port=8000", "app:app"]