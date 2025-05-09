ARG PREFIX
FROM $PREFIX/base

WORKDIR /fuzzer

COPY fuzzer_base/windranger/windranger.tar.gz /fuzzer/

RUN tar -xzf windranger.tar.gz && \
    rm windranger.tar.gz && \
    mv windranger windRanger

# wllvm 설치
RUN pip3 install --upgrade pip==9.0.3 && \
    pip3 install wllvm && \
    export LLVM_COMPILER=clang

# Install gclang
RUN mkdir -p /root/go && \
    export GOPATH=/root/go && \
    export PATH=$GOPATH/bin:$PATH && \
    go install github.com/SRI-CSL/gllvm/cmd/...@v1.3.0

