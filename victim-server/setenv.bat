@rem *******************************************
@rem Collaboration: Open Threat Research (OTR)
@rem Author: Roberto Rodriguez (@Cyb3rWard0g)
@rem License: MIT
@rem *******************************************
@echo off
:: set java options
set JAVA_OPTS=%JAVA_OPTS% -Dcom.sun.jndi.ldap.object.trustURLCodebase=true
set JAVA_OPTS=%JAVA_OPTS% -Dlog4j2.formatMsgNoLookups=false
set JAVA_OPTS=%JAVA_OPTS% -Dlog4j2.disableThreadContext=false
set JAVA_OPTS=%JAVA_OPTS% -Dlog4j2.enableJndiLookup=true
GOTO finish

:finish