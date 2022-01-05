# Basic JAR Application

```
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);
    public static void main(String[] args) {
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true");
        String command = args[0];
        logger.error("Execute: " + command);
    }
}
```

## Clone Repo

```
git clone https://github.com/Cyb3rWard0g/log4jshell-lab
```

## Install Docker

```bash
wget https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/bash/Install-Docker.sh
chmod +x Install-Docker.sh

./Install-Docker.sh
```

## Compile Vulnerable Application

### Docker

```
cd log4jshell-lab/victim/vuln-apps/others/basicJar

docker run -it --rm -v "$(pwd)":/opt/maven -w /opt/maven maven mvn clean install
```

### Manually
```
cd log4jshell-lab/victim/vuln-apps/others/basicJar
mvn -f pom.xml clean package -DskipTests
```

## Run Application

```
java -cp target/Log4jLabProject-1.0-SNAPSHOT-all.jar com.log4jshell.App "Command"
```

```
06:29:08.316 [main] ERROR com.log4jshell.App - Execute: Command
```



