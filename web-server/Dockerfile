FROM openjdk:8-alpine as builder

ADD payloads payloads
WORKDIR /payloads
RUN for f in *.java ; do javac "$f" ; done

FROM nginx
COPY --from=builder /payloads/*.class /tmp/

EXPOSE 80