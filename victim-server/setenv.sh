#!/bin/sh

# Collaboration: Open Threat Research (OTR)
# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: MIT

##### JAVA OPTIONS ####
export JAVA_OPTS="$JAVA_OPTS -Dcom.sun.jndi.ldap.object.trustURLCodebase=true"
export JAVA_OPTS="$JAVA_OPTS -Dlog4j2.formatMsgNoLookups=false"
export JAVA_OPTS="$JAVA_OPTS -Dlog4j2.disableThreadContext=false"

# Log4j 2.15
# Fixes:
# https://issues.apache.org/jira/browse/LOG4J2-3201 - Limit the protocols JNDI can use by default. Limit the servers and classes that can be accessed via LDAP.


# Log4j 2.16
#export JAVA_OPTS="$JAVA_OPTS -Dlog4j2.enableJndi=true"

# Log4k 2.17 -
# Limit JNDI to the java protocol only. JNDI will remain disabled by default. Rename JNDI enablement property from 'log4j2.enableJndi' to 'log4j2.enableJndiLookup', 'log4j2.enableJndiJms', and 'log4j2.enableJndiContextSelector'. 
export JAVA_OPTS="$JAVA_OPTS -Dlog4j2.enableJndiLookup"

#### Environment Variables ####
# export LOG4J_FORMAT_MSG_NO_LOOKUPS="true"