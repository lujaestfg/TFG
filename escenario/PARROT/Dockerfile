# Dockerfile
FROM parrotsec/security:latest

RUN apt update && apt install -y \
    hping3 \
    mariadb-server \
    nmap \
    && apt clean && rm -rf /var/lib/apt/lists/*

CMD [ "bash" ]
