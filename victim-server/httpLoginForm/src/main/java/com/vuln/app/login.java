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
    String email = request.getParameter("email");
    String password = request.getParameter("password");
    String output;
    Logger logger = LogManager.getLogger(login.class);

    PrintWriter out = response.getWriter();
    response.setContentType("text/html;charset=UTF-8");
    out.println("Welcome " + email + "!!");
    out.println("Password: " + password);

    if(email.startsWith("msglookup@")){
      out.println("Mode: Message Lookup");
      output = "Message Lookup: " + password;
    }
    else if(email.startsWith("threadcontext@")){
      ThreadContext.put("apiversion", password);
      out.println("Mode: Thread Context");
      output = "No Message Lookup! Thread Context instead!";
    }
    else {
      out.println("Mode: Message Lookup (default)");
      output = "Message Lookup (default): " + password;
    }
    logger.error(output);
  }
}