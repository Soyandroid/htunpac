FROM fedora:31

LABEL description="Build environment for htunpac"

RUN yum -y install \
    git \
    make \
    zip \
    clang \
    mingw64-gcc.x86_64 \
    mingw32-gcc.x86_64

RUN mkdir /htunpac
WORKDIR /htunpac

COPY dist dist
COPY kernal32 kernal32
COPY pedumper pedumper
COPY pre-dump pre-dump
COPY util util
COPY GNUmakefile GNUmakefile
COPY Module.mk Module.mk

# Building
RUN make