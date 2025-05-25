#!/bin/bash

echo "Ulgam täzelenýär..."
sudo apt-get update && sudo apt-get upgrade -y

echo "Zerur paketler gurnalýar..."
sudo apt install -y curl socat git

echo "Marzban Node repozitoriýasy göçürilýär..."
git clone https://github.com/Gozargah/Marzban-node
cd Marzban-node

echo "Docker gurnalýar..."
curl -fsSL https://get.docker.com | sudo sh

echo "Docker Compose barlanýar..."
if ! command -v docker-compose &> /dev/null; then
    sudo apt install -y docker-compose
fi

echo "SSL bukjasy döredilýär..."
sudo mkdir -p /var/lib/marzban-node/

echo "docker-compose.yml faýly ýazylýar..."
cat <<EOF | sudo tee docker-compose.yml > /dev/null
services:
  marzban-node:
    image: gozargah/marzban-node:latest
    restart: always
    network_mode: host

    volumes:
      - /var/lib/marzban-node:/var/lib/marzban-node

    environment:
      SSL_CLIENT_CERT_FILE: "/var/lib/marzban-node/ssl_client_cert.pem"
      SERVICE_PROTOCOL: rest
EOF

echo "Docker servery işe girizilýär..."
sudo docker compose up -d

echo ""
echo "Gurnama tamamlandy Created by : #m !"
echo "Soňky ädim hökmünde SSL sertifikaty goşuň:"
echo "  sudo nano /var/lib/marzban-node/ssl_client_cert.pem"
echo ""
echo "Sertifikaty goýuň, CTRL+O bilen ýazdyryň we CTRL+X bilen çykyň."
echo "Soňra servery täzeden başlatmak üçin:"
echo "  sudo docker restart marzban-node"