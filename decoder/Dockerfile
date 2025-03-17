# Dockerfile for the 2025 eCTF
# Make any changes here to set up your build environment (e.g., installing crypto
# libraries, dependencies, the compiler for a different language)

FROM ubuntu:24.04

LABEL version="0.2"
LABEL description="Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Requisite Packages
# do this first because it takes the longest
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
    gdb-multiarch \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    python3.10 \
    git \
    wget \
    libtool \
    texinfo \
    unzip \
    python3

# Install MSDK
RUN apt-get install -y unzip && \
    wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

ENV MAXIM_PATH=/root/msdk-2024_02

WORKDIR /decoder
ENTRYPOINT ["bash", "-c", "python3 ./tools/gen_secret_h.py ../global.secrets && make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]

# Sample run command:
# docker run --rm -v ./build_out:/out -v ./:/decoder -v ./secrets:/secrets -e DECODER_ID=0xdeadbeef decoder
# docker run --rm -v ./build_out:/out -v ./:/decoder -v ./../global.secrets:/global.secrets -e DECODER_ID=1234 decoder
