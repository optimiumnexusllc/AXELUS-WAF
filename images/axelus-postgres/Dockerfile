# AXELUS-WAF — axelus-postgres Image
# Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
FROM optimiumnexusllc/axelus-postgres:15.2
ARG BUILD_DATE
ARG GIT_COMMIT
ARG VERSION=15.2
LABEL org.opencontainers.image.title="axelus-postgres" \
      org.opencontainers.image.description="AXELUS-WAF component: axelus-postgres" \
      org.opencontainers.image.vendor="OPTIMIUM NEXUS LLC" \
      org.opencontainers.image.url="https://www.optimiumnexus.com" \
      org.opencontainers.image.source="https://github.com/optimiumnexusllc/AXELUS-WAF" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      com.axelus.component="postgres" \
      com.axelus.publisher="OPTIMIUM NEXUS LLC" \
      com.axelus.contact="contact@optimiumnexus.com"
ENV HISTFILE=/dev/null HISTSIZE=0
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=10 \
  CMD pg_isready -U axelus -d axelus || exit 1
