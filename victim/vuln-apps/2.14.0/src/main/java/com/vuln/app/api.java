package com.vuln.app;

import java.io.*;
import javax.servlet.ServletException;
import javax.servlet.http.*;
import javax.servlet.annotation.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@WebServlet(name = "api", urlPatterns = {"/api"})
public class api extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
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

    out.println("\nExecution context:");
    out.println("==================");
    String ua = request.getHeader("user-agent");
    out.println("Message lookup! Input: " + ua + "\n");

    // Message Lookup - Log4j
    logger.error("Message Lookup: " + ua);
  }
}