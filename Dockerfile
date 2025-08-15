ARG UBUNTU_VERSION

FROM ubuntu:${UBUNTU_VERSION}

WORKDIR /root
RUN apt-get update && \
    apt-get install -y libthrift-0.16.0 thrift-compiler g++ \
    libboost-dev libthrift-dev libsodium-dev make

COPY . .

RUN make all

ENV PATH="${WORKDIR}:${PATH}"

CMD ["server"]
