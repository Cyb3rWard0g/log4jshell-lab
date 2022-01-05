FROM maven as builder

RUN git clone https://github.com/mbechler/marshalsec \
    && mkdir /usr/src/app \
    && cp -avr marshalsec/src /usr/src/app/src \
    && cp -av marshalsec/pom.xml /usr/src/app \
    ##### Compile marshal app #####
    && mvn -f /usr/src/app/pom.xml clean package -DskipTests

FROM openjdk:8-alpine
COPY --from=builder /usr/src/app/target/marshalsec-0.0.3-SNAPSHOT-all.jar /usr/app/marshalsec-0.0.3-SNAPSHOT-all.jar

EXPOSE 1389

ENTRYPOINT ["java", "-cp", "/usr/app/marshalsec-0.0.3-SNAPSHOT-all.jar", "marshalsec.jndi.LDAPRefServer", "http://127.0.0.1:8888/#Run"]