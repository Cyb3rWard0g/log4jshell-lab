package com.vuln.app;

import java.io.*;
import javax.servlet.ServletException;
import javax.servlet.http.*;
import javax.servlet.annotation.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@WebServlet(name = "login", urlPatterns = {"/login"})
public class login extends HttpServlet {
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    // Initialized Log4j
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

    out.println("\nExecution context:");
    out.println("==================");
    out.println("Message lookup! Input: " + email + "\n");

    // Message Lookup - Log4j
    logger.error("Message Lookup: " + email);
  }
}