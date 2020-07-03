FROM python:3.7-alpine

COPY requirements.txt /tmp

RUN pip install -r /requirements.txt
COPY . /tmp/nucypher-service
RUN pip install /tmp/nucypher-service

WORKDIR /tmp/nucypher-service

CMD flask run