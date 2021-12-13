# CVE-2021-44228 Log4Shell Research Lab 🚧

A basic lab environment to test some of the public proof of concepts to trigger and learn more about [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) and expedite the time it takes to deploy multiple scenarios.

## Docker Deployment

### Clone Repo

```
git clone https://github.com/Cyb3rWard0g/log4jshell-lab
```
### Run Docker Compose File

```
cd log4jshell-lab
docker-compose -f docker-compose.yml up --build -d
```

### Check Docker Containers

```
docker ps

docker logs --follow ldap-server
docker logs --follow web-server
```

## Run Vulnerable Apps

* [Serve Netcat Server](#netcat-server)
* [BasicJar](#basicjar)

## Netcat Server

```
nc -lvnp 443
```

## BasicJar
### Compile

**Dockerized**
```
cd vulnApps
docker run -it --rm -v "$(pwd)":/opt/maven -w /opt/maven maven mvn clean install
```

**Locally**
```
cd vulnApps
mvn -f pom.xml clean package -DskipTests
```

### Run Application

```
java -cp target/Log4jLabProject-1.0-SNAPSHOT-all.jar  com.log4jshell.App
```

![](resources/images/log4jshell-trigger-rce-basicjar-reverseshell.png)

## References
* https://www.smarthomebeginner.com/traefik-docker-security-best-practices/#9_Use_a_Docker_Socket_Proxy