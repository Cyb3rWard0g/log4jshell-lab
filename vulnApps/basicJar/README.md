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

## Compile

### Docker

```
cd log4jshell-lab/vulnApps/basicJar
docker run -it --rm -v "$(pwd)":/opt/maven -w /opt/maven maven mvn clean install
```

### Manually
```
cd log4jshell-lab/vulnApps/basicJar
mvn -f pom.xml clean package -DskipTests
```

## Run Application

```
cd log4jshell-lab/vulnApps/basicJar
java -cp target/Log4jLabProject-1.0-SNAPSHOT-all.jar com.log4jshell.App "Command"
```

```
06:29:08.316 [main] ERROR com.log4jshell.App - Execute: Command
```



