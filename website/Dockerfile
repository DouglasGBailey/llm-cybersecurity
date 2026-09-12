# Static marketing site — served by nginx inside the container on port 8080.
# This host's nginx (whatever fronts this container — a host-level
# nginx-in-Docker reverse proxy, Traefik, Caddy, etc.) is expected to
# terminate TLS; see nginx.conf for the header set this container sends.
# Add HSTS/SSL only at whichever layer actually terminates HTTPS.
#
# Uses the nginxinc/nginx-unprivileged image (not the official nginx image)
# because it's built to run as a non-root user out of the box — cache/pid
# dirs are already owned by uid 101 and it listens on 8080, not 80, so
# nothing needs `USER root` tricks or a writable /var/cache/nginx bind-mount.
FROM nginxinc/nginx-unprivileged:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1
