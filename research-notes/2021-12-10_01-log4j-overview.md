# What is Log4j?

> Almost every large application includes its own logging or tracing API. In conformance with this rule, the E.U. SEMPER project decided to write its own tracing API. This was in early 1996. After countless enhancements, several incarnations and much work that API has evolved to become **log4j**, a popular logging package for Java.

* Log4j is an open-source java-based logging library used by several applications and maintained as an [Apache Logging Services Project](https://logging.apache.org/).
* There is Log4j 1.x and 2.x. Log4j 1.x [became end of life](https://blogs.apache.org/foundation/entry/apache_logging_services_project_announces) in August 2015.
* Log4j 2 is a completely new framework and compared with the original log4j 1.X release, log4j 2 [addresses issues](https://logging.apache.org/log4j/2.x/manual/index.html) with the previous release and offers a **plugin architecture** for users.
* Log4j 2 uses the new "[Plugin System](https://logging.apache.org/log4j/2.x/manual/plugins.html)" to [extend its logging framework](https://logging.apache.org/log4j/2.x/manual/extending.html) by adding [Appenders](https://logging.apache.org/log4j/2.x/manual/appenders.html), [Filters](https://logging.apache.org/log4j/2.x/manual/filters.html), [Layouts](https://logging.apache.org/log4j/2.x/manual/layouts.html), [Lookups](https://logging.apache.org/log4j/2.x/manual/lookups.html), and Pattern Converters without requiring any changes to Log4j.

`For the purposes of this research, I will refer to Log4j 2 simply as Log4j.` 

## Plugin Categories

Of course the `Lookups` feature to extend Log4j got my attention 😎. Apparently, Log4j plugins are categorized the following way:
* **Core**: Plugins represented by an element in the configuration file such as an Appender, Layout, Logger or Filter.
* **Converters**: Plugins used by the [PatternLayout class](https://logging.apache.org/log4j/2.x/log4j-core/apidocs/org/apache/logging/log4j/core/layout/PatternLayout.html) to render the elements identified by the conversion pattern defined to format log messages.
* **KeyProviders**: Some components within Log4j may provide the ability to perform data encryption. These components require a secret key to perform the encryption.
* **Lookups: Plugins that implement the [StrLookup](https://logging.apache.org/log4j/2.x/log4j-core/apidocs/org/apache/logging/log4j/core/lookup/StrLookup.html) interface to look up a string key to a string value.**
* **TypeConverters**: Plugins used for converting strings into other types in a plugin factory method parameter.

## What else about Lookups?

* Lookups is part of the "[Property Substitution](https://logging.apache.org/log4j/2.x/manual/configuration.html#PropertySubstitution)" process that allows Log4j to specify references in its configuration to properties that are defined elsewhere.
* According to the documentation, some of these properties will be resolved when the configuration file is interpreted while others may be passed to components where they will be evaluated at runtime.
* `Property substitution` uses variations of two specific classes:
  * [StrSubstitutor](https://logging.apache.org/log4j/2.x/log4j-core/apidocs/org/apache/logging/log4j/core/lookup/StrSubstitutor.html): This class takes a piece of text and substitutes all the variables within it. The default definition of a variable is `${variableName}`. For example: `${java.version}` or `${os.name}`.
  * [StrLookup](https://logging.apache.org/log4j/2.x/log4j-core/apidocs/org/apache/logging/log4j/core/lookup/StrLookup.html): Looks up a `String` key to a `String` value. As mentioned before, this interface is implemented by lookups can be used to create references using the syntax `${prefix:name}` where the prefix tells Log4j that the variable `name` should be evaluated in a specific `context`.

## How are Lookups defined?

> A Lookup must be declared using a Plugin annotation with a type of "Lookup". The name specified on the Plugin annotation will be used to match the prefix. Unlike other Plugins, Lookups do not use a PluginFactory. Instead, they are required to provide a constructor that accepts no arguments.

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

## Any Other Built-in Lookups? Yes!

The `System Properties` lookup is actually built in to Log4j. Lookups such as `${sys:logPath}` make sense now 👍. System property values are usually defined outside of the application, so it make sense they should be accessible via a Lookup.

The following table has informati from the [official documentation](https://logging.apache.org/log4j/2.x/manual/lookups.html) and its [GitHub repo](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/UpperLookup.java). I added links to the constructors and classes wbacking up some of the lookups:

| Prefix | Code | Context|
| --- | --- | --- |
| base64 | [Base64StrLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/Base64StrLookup.java) | Base64 encoded data. The format is `${base64:Base64_encoded_data}`. For example: `${base64:SGVsbG8gV29ybGQhCg==}` yields Hello World!. |
| bundle | [ResourceBundleLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/ResourceBundleLookup.java) | Resource bundle. The format is `${bundle:BundleName:BundleKey}`. The bundle name follows package naming conventions, for example: `${bundle:com.domain.Messages:MyKey}`. |
| [ctx](https://logging.apache.org/log4j/2.x/manual/lookups.html#ContextMapLookup) | [ContextMapLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/ContextMapLookup.java) | Thread Context Map (MDC) |
| [date](https://logging.apache.org/log4j/2.x/manual/lookups.html#DateLookup) | [DateLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/DateLookup.java) | Inserts the current date and/or time using the specified format |
| [env](https://logging.apache.org/log4j/2.x/manual/lookups.html#EnvironmentLookup) | [EnvironmentLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/EnvironmentLookup.java) |  System environment variables. The formats are `${env:ENV_NAME}` and `${env:ENV_NAME:-default_value}`. |
| [java](https://logging.apache.org/log4j/2.x/manual/lookups.html#JavaLookup) | [JavaLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JavaLookup.java) | Looks up keys related to Java: Java version, JRE version, VM version, and so on. Example: `${jada:os}` -> `Linux 5.4.0-1064-azure unknown, architecture: amd64-64` |
| [jndi](https://logging.apache.org/log4j/2.x/manual/lookups.html#JndiLookup) | [JndiLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java) | Looks up keys from JNDI resources. As of Log4j 2.17.0 JNDI operations require that log4j2.enableJndiLookup=true be set as a system property or the corresponding environment variable for this lookup to function. The pattern: `${jndi:logging/context-name}`  |
| [jvmrunargs](https://logging.apache.org/log4j/2.x/manual/lookups.html#JmxRuntimeInputArgumentsLookup) | [JmxRuntimeInputArgumentsLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JmxRuntimeInputArgumentsLookup.java) |  A JVM input argument accessed through JMX, but not a main argument; see RuntimeMXBean.getInputArguments(). Not available on Android. |
| [log4j](https://logging.apache.org/log4j/2.x/manual/lookups.html#Log4jConfigLookup)	| [Log4jLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/Log4jLookup.java) | Log4j configuration properties. The expressions `${log4j:configLocation}` and `${log4j:configParentLocation}` respectively provide the absolute path to the log4j configuration file and its parent folder. |
| [lower](https://logging.apache.org/log4j/2.x/manual/lookups.html#LowerLookup) | [LowerLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/LowerLookup.java) | Converts values to lower case. The passed in `key` should be the value of another lookup. Example: `'${upper:ROBERTO}'` -> roberto|
| [main](https://logging.apache.org/log4j/2.x/manual/lookups.html#AppMainArgsLookup) | [MainMapLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/MainMapLookup.java) | A value set with MapLookup.setMainArguments(String[]) |
| [map](https://logging.apache.org/log4j/2.x/manual/lookups.html#MapLookup) | [MapLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/MapLookup.java) | A value from a MapMessage |
| [sd](https://logging.apache.org/log4j/2.x/manual/lookups.html#StructuredDataLookup) | [StructuredDataLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/StructuredDataLookup.java) | A value from a StructuredDataMessage. The key `id` will return the name of the StructuredDataId without the enterprise number. The key `type` will return the message type. Other keys will retrieve individual elements from the Map. |
| [sys](https://logging.apache.org/log4j/2.x/manual/lookups.html#SystemPropertiesLookup) | [SystemPropertiesLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/SystemPropertiesLookup.java) | System properties. The formats are `${sys:some.property}` and `${sys:some.property:-default_value}`. |
| [upper](https://logging.apache.org/log4j/2.x/manual/lookups.html#UpperLookup) | [UpperLookup](https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/UpperLookup.java) | Converts values to upper case. The passed in `key` should be the value of another lookup. Example: `'${upper:roberto}'` -> ROBERTO |

## JNDI Lookup 🎯

Things are starting to make more sense now 😂

> The Java Naming and Directory Interface (JNDI) is a Java API for a directory service that allows Java software clients to discover and look up data and resources (in the form of Java objects) via a name. Additionally, it specifies a service provider interface (SPI) that allows directory service implementations to be plugged into the framework.

![](../resources/images/log4j-jndi-architecture.png)

### JNDI Service Provider Interfaces

* Lightweight Directory Access Protocol (LDAP)
* Common Object Request Broker Architecture (CORBA) Common Object Services (COS) name service
* Java Remote Method Invocation (RMI) Registry
* Domain Name Service (DNS)

This is it for this section. I finished my notes by introducing the concepts of JNDI which will be covered in the next document.

# References

* https://logging.apache.org/log4j/2.x/manual/configuration.html#AutomaticConfiguration
* https://logging.apache.org/log4j/2.x/manual/configuration.html#PropertySubstitution
* https://logging.apache.org/log4j/2.x/manual/configuration.html#SystemProperties
* https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/
* https://logging.apache.org/log4j/2.x/manual/lookups.html#JndiLookup
* https://logging.apache.org/log4j/2.x/manual/appenders.html#JMSAppender
* https://logging.apache.org/
* https://logging.apache.org/log4j/2.x/manual/extending.html#Lookups
* https://en.wikipedia.org/wiki/Java_Naming_and_Directory_Interface
* https://docs.oracle.com/javase/tutorial/jndi/overview/index.html