FROM ubuntu:20.04

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONIOENCODING=utf8 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8

# Install package
RUN apt-get update && \
    apt-get install -y \
    python3 python3-dev python3-pip \
    libboost-all-dev \
    cmake ninja-build \
    git curl wget clang llvm \
    build-essential golang \
    nano pkg-config libtinfo5\
    opam libclang-cpp12-dev libgmp-dev \
    libclang-12-dev llvm-12-dev libmpfr-dev \
    make autoconf automake libtool bison flex \
    --no-install-recommends

# Install pip
RUN pip3 install --upgrade pip && \
    pip3 install networkx==2.5 pydot pydotplus wllvm


# Install LLVM-10
RUN mkdir /llvm && \
    cd /llvm && \
    wget https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz && \
    tar -xf clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz && \
    rm clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz && \
    mv clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04 /llvm/llvm10

ENV LLVM_DIR=/llvm/llvm10
ENV PATH=$LLVM_DIR/bin:$PATH
ENV LLVM_COMPILER=clang


# Install smake
#RUN git clone https://github.com/prosyslab/smake.git /smake && \
#    cd /smake && \
#    git checkout 4820d08fc1e43555c2be842984d9a7043d42d07b



# Install sparrow
#ENV OPAMYES=1
#RUN git clone https://github.com/prosyslab/sparrow.git /sparrow && \
#    cd /sparrow && \
#    git checkout dafl && \
#    sed -i '/^opam init/ s/$/ --disable-sandboxing/' build.sh && \
    #sed -i '/^opam pin add cil/ s/$/ -n/' build.sh && \
#    ./build.sh

# Setup OPAM and install OCaml packages
#RUN opam init --disable-sandboxing -a && \
#    . /root/.opam/opam-init/init.sh > /dev/null 2>&1 && \
#    opam update && \
#    opam install -y \
#        ppx_compare yojson ocamlgraph memtrace lymp clangml \
#        conf-libclang.12 batteries apron conf-mpfr cil linenoise claml

# Build Sparrow
#RUN . /root/.opam/opam-init/init.sh > /dev/null 2>&1 && \
#    cd /sparrow && \
#    make clean && make

RUN mkdir -p /fuzzer







