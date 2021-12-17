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
    String email = request.getParameter("email");
    String password = request.getParameter("password");

    PrintWriter out = response.getWriter();
    response.setContentType("text/html;charset=UTF-8");
    out.println("Welcome " + email + "!!");

    // Log4jShell CVE-2021-44228
    Logger logger = LogManager.getLogger(login.class);
    logger.error(password);

    out.println("Password executed: " + password);
  }
}
