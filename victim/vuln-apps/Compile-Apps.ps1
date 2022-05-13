# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: MIT

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$WorkDir = 'C:\ProgramData'
$log4shellDir = "$WorkDir\log4jshell-lab"

# Git Clone Log4hShell project
write-Host "  [*] Cloning log4shell-lab project.."
[string]$PathToGit = "C:\Program Files\Git\bin\git.exe"
[Array]$Arguments = "clone", "https://github.com/Cyb3rWard0g/log4jshell-lab", "$log4shellDir"
& $PathToGit $Arguments

write-host "  [*] Compiling applications.."
Set-Location "$log4shellDir\victim\vuln-apps"
[System.Environment]::SetEnvironmentVariable("JAVA_HOME", "C:\Program Files\Java\jdk1.8.0_211\")
Get-ChildItem */* | where {$_.name -eq "pom.xml"} | foreach { cd $_.DirectoryName; C:\ProgramData\chocolatey\lib\maven\apache-maven-3.8.4\bin\mvn.cmd clean install; cd ..}

# Copy WAR file for Tomcat
write-Host "  [*] Copying .war files to Tomcat webapps folder.."
Get-ChildItem */* | where {$_.name -eq "pom.xml"} | foreach { cd $_.DirectoryName; Copy-Item target\*.war C:\ProgramData\Tomcat9\webapps\; cd ..}

# Copy setenv.bat file to Tomcat bin folder
write-Host "  [*] Copying setenv.bat file to Tomcat bin folder.."
Set-Location "$log4shellDir\victim"
[system.Environment]:;::SetEnvironmentVariable("CATALINA_HOME", "C:\ProgramData\chocolatey\lib\Tomcat\tools\apache-tomcat-9.0.62")
Copy-Item setenv.bat $env:CATALINA_HOME\bin\setenv.bat

# Restart service
Restart-Service -Name tomcat9 -Force

write-Host "  [*] Verifying if tomcat is running.."
$s = Get-Service -Name tomcat9
while ($s.Status -ne 'Running') { Start-Service tomcat9; Start-Sleep 3 }
Start-Sleep 5
write-Host "  [*] tomcat9 is running.."