FROM golang:1.12-alpine AS builder
ADD go.mod go.sum /app/
WORKDIR /app/
RUN apk --no-cache add git
RUN go mod download
ADD . /app/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o /kube-trivy .

FROM alpine:3.9
RUN apk --no-cache add ca-certificates git
COPY --from=builder /kube-trivy /usr/local/bin/kube-trivy
RUN chmod +x /usr/local/bin/kube-trivy

ENTRYPOINT ["kube-trivy"]
