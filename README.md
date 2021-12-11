# CVE-2021-44228 Log4j RCE (Log4Shell) Research Lab

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

## Run Vulnerable App

### Compile

```
cd vulnApp
mvn -f pom.xml clean package -DskipTests
```

## Run

```
java -cp target/Log4jLabProject-1.0-SNAPSHOT-all.jar  com.log4jshell.App
```

## References
* https://www.smarthomebeginner.com/traefik-docker-security-best-practices/#9_Use_a_Docker_Socket_Proxy