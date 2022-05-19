FROM --platform=$TARGETPLATFORM python:3.10-alpine as builder
RUN apk update && apk add --update cargo gcc rust make musl-dev python3-dev libffi-dev openssl-dev

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY ./requirements.txt .
RUN python3 -m pip install --no-cache-dir wheel
RUN python3 -m pip install --no-cache-dir -r requirements.txt

FROM --platform=$TARGETPLATFORM python:3.10-alpine
COPY --from=builder	/opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR mhddos_proxy
COPY . .
ENTRYPOINT ["python3", "./runner.py"]
