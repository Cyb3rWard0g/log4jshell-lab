package com.vuln.app;

import java.io.*;
import javax.servlet.ServletException;
import javax.servlet.http.*;
import javax.servlet.annotation.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

@WebServlet(name = "api", urlPatterns = {"/api"})
public class api extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Enable JNDI
    System.setProperty("log4j2.enableJndi", "true");

    // Enforce default JNDI allowedLdapHosts property
    System.setProperty("log4j2.allowedLdapHosts","localhost");
  
    // Initialize Log4j
    Logger logger = LogManager.getLogger(api.class);

    PrintWriter out = response.getWriter();
    out.println("\nLog4j2 version:");
    out.println("===============");
    out.println(logger.getClass().getPackage().getImplementationVersion());

    out.println("\nSystem Properties:");
    out.println("==================");
    out.println("Java version: " + System.getProperty("java.version"));
    out.println("com.sun.jndi.ldap.object.trustURLCodebase: " + System.getProperty("com.sun.jndi.ldap.object.trustURLCodebase"));
    out.println("sun.net.spi.nameservice.nameservers: " + System.getProperty("sun.net.spi.nameservice.nameservers"));
    out.println("sun.net.spi.nameservice.provider.1: " + System.getProperty("sun.net.spi.nameservice.provider.1"));
    out.println("log4j2.enableJndi: " + System.getProperty("log4j2.enableJndi"));
    out.println("log4j2.allowedLdapHosts: " + System.getProperty("log4j2.allowedLdapHosts"));

    out.println("\nExecution context:");
    out.println("==================");
    String ua = request.getHeader("user-agent");
    out.println("Thread Context lookup! Input: " + ua + "\n");

    // Thread Context - Log4j
    ThreadContext.put("trigger", ua);
    logger.error("Thread Context Lookup!");
  }
}