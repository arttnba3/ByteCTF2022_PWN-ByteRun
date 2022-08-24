FROM ubuntu:22.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt update && apt-get -y dist-upgrade && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y lib32z1 xinetd git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev

RUN apt install -y xinetd

RUN groupadd -r ctf && useradd -r -g ctf ctf

COPY ./src/ctf /ctf
COPY ./src/ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /start.sh

RUN chown -R ctf:ctf /ctf && \
    chmod 555 /start.sh && \
    chmod 555 /ctf/run.sh && \
    chmod 444 /etc/xinetd.d/ctf

CMD ["/bin/sh", "/start.sh"]
