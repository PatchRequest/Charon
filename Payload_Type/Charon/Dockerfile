FROM ubuntu:22.04

ARG CA_CERTIFICATE
ARG NPM_REGISTRY
ARG PYPI_INDEX
ARG PYPI_INDEX_URL
ARG DOCKER_REGISTRY_MIRROR
ARG HTTP_PROXY
ARG HTTPS_PROXY

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      python3 python3-pip \
      mono-devel && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /
RUN pip3 install -r /requirements.txt

WORKDIR /Mythic/
CMD ["python3", "main.py"]
