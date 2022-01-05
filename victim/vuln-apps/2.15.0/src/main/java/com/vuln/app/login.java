package com.vuln.app;

import java.io.*;
import javax.servlet.ServletException;
import javax.servlet.http.*;
import javax.servlet.annotation.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

@WebServlet(name = "login", urlPatterns = {"/login"})
public class login extends HttpServlet {
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    // Enforce default JNDI allowedLdapHosts property
    System.setProperty("log4j2.allowedLdapHosts","localhost");

    // Initialize Log4j
    Logger logger = LogManager.getLogger(login.class);

    PrintWriter out = response.getWriter();
    
    String email = request.getParameter("email");
    out.println("Welcome " + email + "!!");
    
    out.println("\nLog4j2 version:");
    out.println("===============");
    out.println(logger.getClass().getPackage().getImplementationVersion());

    out.println("\nSystem Properties:");
    out.println("==================");
    out.println("Java version: " + System.getProperty("java.version"));
    out.println("com.sun.jndi.ldap.object.trustURLCodebase: " + System.getProperty("com.sun.jndi.ldap.object.trustURLCodebase"));
    out.println("sun.net.spi.nameservice.nameservers: " + System.getProperty("sun.net.spi.nameservice.nameservers"));
    out.println("sun.net.spi.nameservice.provider.1: " + System.getProperty("sun.net.spi.nameservice.provider.1"));
    out.println("log4j2.allowedLdapHosts: " + System.getProperty("log4j2.allowedLdapHosts"));

    out.println("\nExecution context:");
    out.println("==================");
    out.println("Thread Context lookup! Input: " + email + "\n");

    // Thread Context - Log4j
    ThreadContext.put("trigger", email);
    logger.error("Thread Context Lookup!");
  }
}