FROM phusion/baseimage:latest
MAINTAINER plusls <plusls@qq.com>

COPY sources.list /etc/apt/.

RUN dpkg --add-architecture i386 && \
    apt-get -y update && \
    apt install -y \
    libc6:i386 \
    libc6-dbg:i386 \
    libc6-dbg \
    bison \
    build-essential \
    debian-archive-keyring \
    debootstrap \
    lib32stdc++6 \
    g++-multilib \
    cmake \
    autoconf \
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
    capstone \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/
    
RUN pip install --no-cache-dir \
    ropgadget \
    pwntools \
    zio \
    angr \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/ && \
    pip install --upgrade pip \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/ && \
    pip install --upgrade pwntools \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/

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
