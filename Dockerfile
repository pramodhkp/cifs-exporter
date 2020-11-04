# Build
FROM golang:latest AS build
WORKDIR /go/src/cifs-exporter
COPY . .
RUN go get -d -v ./...
RUN go install -v ./...

# Release
FROM scratch AS release
COPY --from=build /go/src/cifs-exporter /usr/local/bin/cifs-exporter
USER 9999:9999
EXPOSE 9695
ENTRYPOINT ["/usr/local/bin/cifs-exporter"]
