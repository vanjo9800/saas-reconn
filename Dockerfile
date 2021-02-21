FROM golang:alpine
RUN apk --no-cache add chromium
COPY ./*  /saasreconn/
WORKDIR /saasreconn/
ENTRYPOINT ["go run"]
