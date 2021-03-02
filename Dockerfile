FROM alpine:3.13.2

WORKDIR /app
RUN apk update
RUN apk add --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing yara
RUN apk add --no-cache python2 python3 python3-dev build-base linux-headers
RUN python3 -m ensurepip && pip3 install --upgrade pip wheel
RUN pip3 install unipacker

ENTRYPOINT [ "unipacker" ]
