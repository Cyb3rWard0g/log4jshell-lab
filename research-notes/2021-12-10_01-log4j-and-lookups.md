# What is Log4j?

> Almost every large application includes its own logging or tracing API. In conformance with this rule, the E.U. SEMPER project decided to write its own tracing API. This was in early 1996. After countless enhancements, several incarnations and much work that API has evolved to become **log4j**, a popular logging package for Java.

* Log4j is an open-source java-based logging library used by several applications and maintained as an [Apache Logging Services Project](https://logging.apache.org/).
* There is Log4j 1.x and 2.x. Log4j 1.x [became end of life](https://blogs.apache.org/foundation/entry/apache_logging_services_project_announces) in August 2015.
* Log4j 2 is a completely new framework and compared with the original log4j 1.X release, log4j 2 [addresses issues](https://logging.apache.org/log4j/2.x/manual/index.html) with the previous release and offers a **plugin architecture** for users.
* Log4j 2 uses a new [Plugin System](https://logging.apache.org/log4j/2.x/manual/plugins.html) to [extend its logging framework](https://logging.apache.org/log4j/2.x/manual/extending.html) by adding [Appenders](https://logging.apache.org/log4j/2.x/manual/appenders.html), [Filters](https://logging.apache.org/log4j/2.x/manual/filters.html), [Layouts](https://logging.apache.org/log4j/2.x/manual/layouts.html), [Lookups](https://logging.apache.org/log4j/2.x/manual/lookups.html), and Pattern Converters without requiring any changes to Log4j.

`For the purposes of this research, I will refer to Log4j 2 simply as Log4j.` 

## Plugin Categories

Of course the `Lookups` feature to extend Log4j got my attention 😎. Apparently, Log4j plugins are categorized the following way:
* **Core**: Plugins represented by an element in the configuration file such as an Appender, Layout, Logger or Filter.
* **Converters**: Plugins used by the [PatternLayout class](https://logging.apache.org/log4j/2.x/log4j-core/apidocs/org/apache/logging/log4j/core/layout/PatternLayout.html) to render the elements identified by the conversion pattern defined to format log messages.
* **KeyProviders**: Some components within Log4j may provide the ability to perform data encryption. These components require a secret key to perform the encryption.
* **Lookups: Plugins that implement the [StrLookup](https://logging.apache.org/log4j/2.x/log4j-core/apidocs/org/apache/logging/log4j/core/lookup/StrLookup.html) interface to look up a string key to a string value.**
* **TypeConverters**: Plugins used for converting strings into other types in a plugin factory method parameter.

## What else about Lookups?

* Lookups are part of the "[Property Substitution](https://logging.apache.org/log4j/2.x/manual/configuration.html#PropertySubstitution)" process that allows Log4j to specify references in its configuration to properties that are defined elsewhere.
* According to Log4j documentation, some of these properties are resolved when the configuration file is interpreted while others may be passed to components where they will be evaluated at runtime.
* `Property substitution` uses variations of two specific classes:
  * [StrSubstitutor](https://logging.apache.org/log4j/2.x/log4j-core/apidocs/org/apache/logging/log4j/core/lookup/StrSubstitutor.html): This class takes a piece of text and substitutes all the variables within it. The default definition of a variable is `${variableName}`. For example: `${java.version}` or `${os.name}`.
  * [StrLookup](https://logging.apache.org/log4j/2.x/log4j-core/apidocs/org/apache/logging/log4j/core/lookup/StrLookup.html): This class looks up a `String` key to a `String` value. As mentioned before, this class interface is implemented by "**Lookup Plugins**" and can be used to create references using the syntax `${prefix:name}` where the prefix tells Log4j that the variable `name` should be evaluated in a specific `context`.

## How are Lookups defined?

> A Lookup must be declared using a **Plugin annotation** with a type of `Lookup`. The name specified on the Plugin annotation will be used to match the prefix. Unlike other Plugins, Lookups do not use a `PluginFactory`. Instead, they are required to provide a constructor that accepts no arguments.

The example below shows a `Lookup` that will return the value of a `System Property`.

```
@Plugin(name = "sys", category = "Lookup")
public class SystemPropertiesLookup implements StrLookup {
 
    /**
     * Lookup the value for the key.
     * @param key  the key to be looked up, may be null
     * @return The value for the key.
     */
    public String lookup(String key) {
        return System.getProperty(key);
    }
 
    /**
     * Lookup the value for the key using the data in the LogEvent.
     * @param event The current LogEvent.
     * @param key  the key to be looked up, may be null
     * @return The value associated with the key.
     */
    public String lookup(LogEvent event, String key) {
        return System.getProperty(key);
    }
}
```

As mentioned before, `Lookups` can be referenced with the syntax `${name:key}` where name is the `name` specified in the `Plugin annotation` and `key` is the name of the item to locate. The logic inside of the constructor varies depending on the lookup being defined.

## Any Log4j Built-in Lookups? Yes!

The [System Properties lookup](https://logging.apache.org/log4j/2.x/manual/lookups.html#SystemPropertiesLookup) is actually built into Log4j. System property values are usually defined outside of the application, so it make sense they should be accessible via a Lookup.

The following table has information from [Log4j Lookups official documentation](https://logging.apache.org/log4j/2.x/manual/lookups.html) and [Log4j GitHub repo](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/UpperLookup.java). I added links to the constructors and classes backing up some of the lookups below:

| Prefix | Code | Context|
| --- | --- | --- |
| base64 | [Base64StrLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/Base64StrLookup.java) | Base64 encoded data. The format is `${base64:Base64_encoded_data}`. For example: `${base64:SGVsbG8gV29ybGQhCg==}` yields Hello World!. |
| bundle | [ResourceBundleLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/ResourceBundleLookup.java) | Resource bundle. The format is `${bundle:BundleName:BundleKey}`. The bundle name follows package naming conventions, for example: `${bundle:com.domain.Messages:MyKey}`. |
| [ctx](https://logging.apache.org/log4j/2.x/manual/lookups.html#ContextMapLookup) | [ContextMapLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/ContextMapLookup.java) | Thread Context Map (MDC) |
| [date](https://logging.apache.org/log4j/2.x/manual/lookups.html#DateLookup) | [DateLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/DateLookup.java) | Inserts the current date and/or time using the specified format |
| [env](https://logging.apache.org/log4j/2.x/manual/lookups.html#EnvironmentLookup) | [EnvironmentLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/EnvironmentLookup.java) |  System environment variables. The formats are `${env:ENV_NAME}` and `${env:ENV_NAME:-default_value}`. |
| [java](https://logging.apache.org/log4j/2.x/manual/lookups.html#JavaLookup) | [JavaLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JavaLookup.java) | Looks up keys related to Java: Java version, JRE version, VM version, and so on. Example: `${java:os}` -> `Linux 5.4.0-1064-azure unknown, architecture: amd64-64` |
| [jndi](https://logging.apache.org/log4j/2.x/manual/lookups.html#JndiLookup) | [JndiLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java) | Looks up keys from JNDI resources. As of Log4j 2.17.0 JNDI operations require that log4j2.enableJndiLookup=true be set as a system property or the corresponding environment variable for this lookup to function. The pattern: `${jndi:logging/context-name}`  |
| [jvmrunargs](https://logging.apache.org/log4j/2.x/manual/lookups.html#JmxRuntimeInputArgumentsLookup) | [JmxRuntimeInputArgumentsLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JmxRuntimeInputArgumentsLookup.java) | A JVM input argument accessed through JMX, but not a main argument; see RuntimeMXBean.getInputArguments(). Not available on Android. |
| [k8s](https://logging.apache.org/log4j/2.x/manual/lookups.html#KubernetesLookup) | [KubernetesLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-kubernetes/src/main/java/org/apache/logging/log4j/kubernetes/KubernetesLookup.java) | Retrieve various Kubernetes attributes. Supported keys are: accountName, containerId, containerName, clusterName, host, hostIp, labels, labels.app, labels.podTemplateHash, masterUrl, namespaceId, namespaceName, podId, podIp, podName, imageId, imageName. |
| [log4j](https://logging.apache.org/log4j/2.x/manual/lookups.html#Log4jConfigLookup)	| [Log4jLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/Log4jLookup.java) | Log4j configuration properties. The expressions `${log4j:configLocation}` and `${log4j:configParentLocation}` respectively provide the absolute path to the log4j configuration file and its parent folder. |
| [lower](https://logging.apache.org/log4j/2.x/manual/lookups.html#LowerLookup) | [LowerLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/LowerLookup.java) | Converts values to lower case. The passed in `key` should be the value of another lookup. Example: `'${upper:ROBERTO}'` -> roberto|
| [main](https://logging.apache.org/log4j/2.x/manual/lookups.html#AppMainArgsLookup) | [MainMapLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/MainMapLookup.java) | A value set with MapLookup.setMainArguments(String[]) |
| [map](https://logging.apache.org/log4j/2.x/manual/lookups.html#MapLookup) | [MapLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/MapLookup.java) | A value from a MapMessage |
| [sd](https://logging.apache.org/log4j/2.x/manual/lookups.html#StructuredDataLookup) | [StructuredDataLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/StructuredDataLookup.java) | A value from a StructuredDataMessage. The key `id` will return the name of the StructuredDataId without the enterprise number. The key `type` will return the message type. Other keys will retrieve individual elements from the Map. |
| [sys](https://logging.apache.org/log4j/2.x/manual/lookups.html#SystemPropertiesLookup) | [SystemPropertiesLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/SystemPropertiesLookup.java) | System properties. The formats are `${sys:some.property}` and `${sys:some.property:-default_value}`. |
| [upper](https://logging.apache.org/log4j/2.x/manual/lookups.html#UpperLookup) | [UpperLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/UpperLookup.java) | Converts values to upper case. The passed in `key` should be the value of another lookup. Example: `'${upper:roberto}'` -> ROBERTO |

## Where Can I Reference Lookups?

Initially, the documentation was not clear and I assumed `Lookups` were only used to define properties in Log4j configurations. However, `Lookups` can also be used in `messages` processed by `Log4j`.

### Lookups in a Configuration

The Log4j (.xml) configuration below shows a few examples of a basic property substitution with `logdir` and `layout` declared as properties and then referenced in the `Appenders` section. However, there is also this string `${sys:catalina.base}` being used while defining the `logdir` property variable. 

```
<?xml version="1.0" encoding="utf-8"?>
<Configuration status="WARN">
  <Properties>
    <Property name="logdir">${sys:catalina.base}/logs</Property>
    <Property name="layout">%d{HH:mm:ss} [%t] %-5level %logger{36} - %msg%n</Property>
  </Properties>
  <Appenders>
    <RollingFile name="JavaAppLogs" fileName="${logdir}/javaapp.log" filePattern="${logdir}/javaapp.%d{yyyy-MM-dd}-%i.log">
      <PatternLayout pattern="${layout}"/>
      <Policies>
        <TimeBasedTriggeringPolicy />
        <SizeBasedTriggeringPolicy size="1 MB" />
      </Policies>
      <DefaultRolloverStrategy max="10" />
    </RollingFile>
  </Appenders>
  <Loggers>
    <Root level="error">
      <AppenderRef ref="JavaAppLogs"/>
    </Root>
  </Loggers>
</Configuration>
```

The `${sys:catalina.base}` string represents a [System Property Lookup](https://logging.apache.org/log4j/2.x/manual/lookups.html#SystemPropertiesLookup) which uses the `sys` prefix to let Log4j know how to process the `catalina.base` string (Catalina is [Tomcat](https://tomcat.apache.org/)'s servlet container. In this example, Log4j takes the `catalina.base` string and processes it with the [SystemPropertiesLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/SystemPropertiesLookup.java) class. The result could be something similar to `/opt/tomcat` or `/usr/share/tomcat`.

### Lookups in Messages

The code below is a basic Java application using Log4J to process a `message` with an `argument` provided while running the application.

```
package com.log4jsample;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);
    public static void main(String[] args) {
        String command = args[0];
        logger.info("Results: " + command);
    }
}
```

After compiling the application, I can run the application the following way: 

```
java -cp target/Log4jSample-1.0-SNAPSHOT-all.jar com.log4jsample.App '${java:os}'
```

and get the following output: `Results: Linux 5.4.0-1064-azure unknown, architecture: amd64-64`.

This is because the `${java:os}` represents a [Java Lookup](https://logging.apache.org/log4j/2.x/manual/lookups.html#JavaLookup) which uses the [JavaLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JavaLookup.java) class to process the string after the `java` prefix.


## Are "Message Lookups" Enabled by Default?

* Message lookups were enabled by default from version `2.0-beta9 to 2.14.1`
* On `2016-10-02`, [Log4j 2.7](https://logging.apache.org/log4j/2.x/changes-report.html#a2.7) added the ability to disable message lookups. The following sring `%msg{nolookup}` needed to be added to the layout message format pattern in the Log4j configuration. **Message lookups were still enabled by default**.
* On `2017-11-18`, [Log4j 2.10](https://logging.apache.org/log4j/2.x/changes-report.html#a2.10.0) added the property `log4j.formatMsgNoLookups` to disable message pattern converter lookups globally. **Message lookups were still enabled by default**.
* On `2021-12-10`, [Log4j 2.15](https://logging.apache.org/log4j/2.x/changes-report.html#a2.15.0) removed the `log4j2.formatMsgNoLookups` property and `nolookups` message pattern converted option. However, **Message lookups are now disabled by default**. Lookups can be enabled on a per-pattern basis using `%m{lookups}`.
* On `2021-12-10`, [Log4j 2.16](https://logging.apache.org/log4j/2.x/changes-report.html#a2.16.0) completely removed support for Message Lookups.

## JNDI Lookups -> Message -> 💣

"`Message Lookups`" was the initial feature that `Log4Shell` ([CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228)) abused to pass a [JNDI Lookup](https://logging.apache.org/log4j/2.x/manual/lookups.html#JndiLookup) string for Log4j to process and connect to a attacker's controlled remote server.

# References

* https://logging.apache.org/log4j/2.x/manual/configuration.html#AutomaticConfiguration
* https://logging.apache.org/log4j/2.x/manual/configuration.html#PropertySubstitution
* https://logging.apache.org/log4j/2.x/manual/configuration.html#SystemProperties
* https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/
* https://logging.apache.org/log4j/2.x/manual/appenders.html#JMSAppender
* https://logging.apache.org/
* https://logging.apache.org/log4j/2.x/manual/extending.html#Lookups