#!/bin/sh

for dir in 2.*; do
  docker run --rm -v "$(pwd)/$dir":/opt/maven -w /opt/maven maven mvn clean install
  cp "$(pwd)/$dir/target/Log4j-$dir-SNAPSHOT.war" /opt/tomcat/webapps/
done