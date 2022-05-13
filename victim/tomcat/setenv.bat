@rem *******************************************
@rem Collaboration: Open Threat Research (OTR)
@rem Author: Roberto Rodriguez (@Cyb3rWard0g)
@rem License: MIT
@rem *******************************************
@echo off
:: set java options
set JAVA_OPTS=%JAVA_OPTS% -Dcom.sun.jndi.ldap.object.trustURLCodebase=true

GOTO finish

:finish