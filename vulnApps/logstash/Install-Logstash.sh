#!/bin/sh

# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: MIT

apt install -y openjdk-8-jre-headless apt-transport-https
wget -qO – https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add –
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list

apt-get update -y && apt-get install logstash -y

systemctl start logstash.service
systemctl enable logstash.service