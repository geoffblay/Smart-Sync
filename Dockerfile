# # Use an official Python runtime as the base image
# FROM python:3.10-slim

# # Set the working directory in the container
# WORKDIR /app

# ENV FLASK_DEBUG=development \
#     PYTHONUNBUFFERED=0

# # Copy the requirements file and install dependencies
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

# # Copy the application code
# COPY . .

# # Expose the port your app runs on
# EXPOSE 5000

# # Define the command to run your app
# CMD ["python", "app.py"]

FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy your application code to the container
COPY . /app

# Install dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 5000 for the app
EXPOSE 5000

# Run the app
CMD ["python", "app.py"]

