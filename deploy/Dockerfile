# ncc-registry 镜像：多阶段构建成单二进制 + 最小运行层。
#
# 构建（在 ncc-registry/ 目录下）：
#   docker build -f deploy/Dockerfile -t ncc-registry:dev ..
# 或在 deploy/ 下直接 docker compose up -d --build。
FROM golang:1.24-alpine AS build
WORKDIR /src
# 先只拷 go.mod/go.sum，让依赖层可缓存
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO 关掉：驱动是纯 Go（glebarez/sqlite），静态二进制可直接跑在 alpine 上
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ncc-registry ./cmd/ncc-registry

FROM alpine:3.20
# 时区与证书：节点名/心跳时间按本地时区显示，出网拉取（如未来接对象存储）需要根证书
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 ncc
WORKDIR /app
COPY --from=build /out/ncc-registry /usr/local/bin/ncc-registry

# 数据目录（库 + blobs + node-id + jwt-secret）挂在这里，备份 = 打包这个目录
ENV NCCR_DATA_DIR=/data \
    NCCR_PORT=8282 \
    NCCR_PUBLIC_URL=http://localhost:8282
VOLUME ["/data"]
EXPOSE 8282
USER ncc
ENTRYPOINT ["ncc-registry"]
