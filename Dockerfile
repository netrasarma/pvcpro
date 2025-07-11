# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Copy the entire subdirectory from your repository into the /app directory in the container
COPY pvc-pro-final/ /app/

# Set the working directory to where the files are now located
WORKDIR /app

# Now that we are in the correct directory, install the requirements
RUN pip install --no-cache-dir -r requirements.txt

# The CMD command can now find app.py because we are in the /app directory
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
