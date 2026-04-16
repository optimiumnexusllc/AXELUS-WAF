# AXELUS-WAF Admin Frontend
# Serves the English dashboard, proxies API to axelus-mgt
FROM nginx:alpine
COPY nginx/default.conf /etc/nginx/conf.d/default.conf
COPY web/index.html /usr/share/nginx/html/index.html
LABEL org.opencontainers.image.title="axelus-admin" \
      org.opencontainers.image.vendor="OPTIMIUM NEXUS LLC" \
      org.opencontainers.image.url="https://www.optimiumnexus.com"
EXPOSE 80
