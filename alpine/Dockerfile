FROM golang:1-alpine as builder

RUN apk update

RUN apk --no-cache --no-progress add git ca-certificates tzdata make

#RUN apk --no-cache --no-progress add update-ca-certificates

RUN rm -rf /var/cache/apk/*

WORKDIR /go/who

# Download go modules
COPY go.mod .
COPY go.sum .
RUN GO111MODULE=on GOPROXY=https://proxy.golang.org go mod download

COPY . .
RUN ls -al

RUN make build

# Create a minimal container to run a Golang static binary
#FROM scratch

FROM alpine

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/who/who .
COPY --from=builder /go/who/data .

RUN ls -al

ENTRYPOINT ["/who"]
EXPOSE 80 8080
