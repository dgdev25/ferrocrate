FROM alpine:3.20
COPY d /d
RUN test -L /d/bin/link && [ "$(readlink /d/bin/link)" = "../real.txt" ] && ls -laR /d
