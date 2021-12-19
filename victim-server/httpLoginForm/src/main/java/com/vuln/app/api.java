package com.vuln.app;

import java.io.*;
import javax.servlet.ServletException;
import javax.servlet.http.*;
import javax.servlet.annotation.*;
import java.util.Enumeration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

@WebServlet(name = "api", urlPatterns = {"/api/*"})
public class api extends HttpServlet {

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String requestUrl = request.getRequestURI();
		String name = requestUrl.substring(requestUrl.lastIndexOf('/') + 1);

    Logger logger = LogManager.getLogger(api.class);
    PrintWriter out = response.getWriter();

    out.println("Log4j System Properties:");
    out.println("=======================");
    out.println("com.sun.jndi.ldap.object.trustURLCodebase: " + System.getProperty("com.sun.jndi.ldap.object.trustURLCodebase"));
    out.println("log4j2.formatMsgNoLookups: " + System.getProperty("log4j2.formatMsgNoLookups"));
    out.println("log4j2.disableThreadContext: " + System.getProperty("log4j2.disableThreadContext"));
    out.println("log4j2.enableJndi: " + System.getProperty("log4j2.enableJndi"));
    
    String output;

    if (name.equals("msglookup") || name.equals("threadcontext")){
      String ua = request.getHeader("user-agent");
      if(name.equals("msglookup")){
        output = "Message Lookup: " + ua;
      }
      else {
        ThreadContext.put("apiversion", ua);
        output = "No Message Lookup! Thread Context instead!";
      }
      out.println("\nExecution context:");
      out.println("===================");
      out.println(name + " variation with user-agent " + ua);
      logger.error(output);
    }
    else {
      output = "You need to use either: /api/msglookup or /api/threadcontext";
      out.println(output);
    }
  }
}