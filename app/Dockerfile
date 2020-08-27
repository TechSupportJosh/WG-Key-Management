#https://testdriven.io/blog/dockerizing-flask-with-postgres-gunicorn-and-nginx/

# pull official base image
FROM python:3.8.1-slim-buster

# set work directory
WORKDIR /usr/src/app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
RUN pip install --upgrade pip
COPY ./requirements.txt /usr/src/app/requirements.txt
RUN pip install -r requirements.txt

# expose port
EXPOSE 5000

# copy project
COPY . /usr/src/app/