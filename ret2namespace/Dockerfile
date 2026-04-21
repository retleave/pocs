FROM ubuntu:25.04 AS app
FROM pwn.red/jail

COPY --from=app / /srv
COPY dist/ret2namespace /srv/app/run
COPY dist/libc.so.6 /srv/app/libc.so.6
COPY dist/ld-linux-x86-64.so.2 /srv/app/ld-linux-x86-64.so.2
COPY ./flag.txt /srv/app/flag.txt

RUN chmod +x /srv/app/run

ENV JAIL_PORT=1448 JAIL_MEM=128M JAIL_ENV_NUM=5 JAIL_PID=20 JAIL_TIME=600
