FROM phusion/baseimage:latest
MAINTAINER plusls <plusls@qq.com>

RUN dpkg --add-architecture i386 && \
    apt-get -y update && \
    apt install -y \
    libc6:i386 \
    libc6-dbg:i386 \
    libc6-dbg \
    lib32stdc++6 \
    g++-multilib \
    cmake \
    net-tools \
    libffi-dev \
    libssl-dev \
    python3-pip \
    python-pip \
    python-capstone \
    ruby2.3 \
    tmux \
    strace \
    ltrace \
    nasm \
    wget \
    radare2 \
    gdb \
    netcat \
    git \
    libtool-bin \
    automake \
    libglib2.0-dev \
    socat --fix-missing && \
    rm -rf /var/lib/apt/list/*

RUN pip3 install --no-cache-dir \
    ropper \
    unicorn \
    keystone-engine \
    capstone
    
RUN pip install --no-cache-dir \
    ropgadget \
    pwntools \
    zio \
    angr && \
    pip install --upgrade pip && \
    pip install --upgrade pwntools

RUN gem install \
    one_gadget && \
    rm -rf /var/lib/gems/2.3.*/cache/*

RUN git clone https://github.com/mirrorer/afl && \
    cd afl && \
    make && \
    cd qemu_mode && \
    CPU_TARGET=i386 ./build_qemu_support.sh

WORKDIR /ctf/work/

ENTRYPOINT ["/bin/bash"]
