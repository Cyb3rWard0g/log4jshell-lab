# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: MIT

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Git Clone Log4hShell project
write-Host "  [*] Cloning log4shell-lab project.."
git clone https://github.com/Cyb3rWard0g/log4jshell-lab C:\ProgramData\log4shell-lab

# Compile Vulnerable App (LoginForm and API)
write-Host "  [*] Compiling vulnerable java application.."
Set-Location C:\ProgramData\log4shell-lab\victim-server\httpLoginForm
mvn clean install

# Copy WAR file for Tomcat
write-Host "  [*] Copying .wat file to Tomcat webapps folder.."
Copy-Item target\VulnWebApp-1.0-SNAPSHOT.war C:\ProgramData\Tomcat9\webapps\

# Copy setenv.bat file to Tomcat bin folder
write-Host "  [*] Copying setenv.bat file to Tomcat bin folder.."
Set-Location C:\ProgramData\log4shell-lab
Copy-Item victim-server\setenv.bat $env:CATALINA_HOME\bin\setenv.bat

# Restart service
Restart-Service -Name tomcat9 -Force

write-Host "  [*] Verifying if tomcat is running.."
$s = Get-Service -Name tomcat9
while ($s.Status -ne 'Running') { Start-Service tomcat9; Start-Sleep 3 }
Start-Sleep 5
write-Host "  [*] tomcat9 is running.."