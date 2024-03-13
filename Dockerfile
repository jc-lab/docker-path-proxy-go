FROM alpine:18

RUN mkdir -p /app
WORKDIR "/app"

ADD "dist/docker-path-proxy_linux-amd64.exe" "/app/docker-path-proxy.exe"

CMD ["/app/docker-path-proxy.exe"]

EXPOSE 8000