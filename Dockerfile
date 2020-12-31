FROM golang:1.15
WORKDIR /go/src/hbs-decipher
COPY go.mod main.go decipher.go evb.go ./
RUN go build -o app/hbsdec

FROM alpine:latest  
RUN apk --no-cache add ca-certificates libc6-compat
WORKDIR /root/
COPY --from=0 /go/src/hbs-decipher/app/hbsdec .
ENTRYPOINT ["./hbsdec"]
