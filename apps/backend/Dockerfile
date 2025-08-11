FROM python:3.11-slim

WORKDIR /app

# Create a non-root user
RUN addgroup --system app && adduser --system --group app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Switch to non-root user
USER app

# Expose port and run the application
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
