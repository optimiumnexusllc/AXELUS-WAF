# AXELUS-WAF — axelus-chaos Image
# Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
FROM optimiumnexusllc/axelus-chaos:latest
ARG BUILD_DATE
ARG GIT_COMMIT
ARG VERSION=latest
LABEL org.opencontainers.image.title="axelus-chaos" \
      org.opencontainers.image.description="AXELUS-WAF component: axelus-chaos" \
      org.opencontainers.image.vendor="OPTIMIUM NEXUS LLC" \
      org.opencontainers.image.url="https://www.optimiumnexus.com" \
      org.opencontainers.image.source="https://github.com/optimiumnexusllc/AXELUS-WAF" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      com.axelus.component="chaos" \
      com.axelus.publisher="OPTIMIUM NEXUS LLC" \
      com.axelus.contact="contact@optimiumnexus.com"
ENV HISTFILE=/dev/null HISTSIZE=0
