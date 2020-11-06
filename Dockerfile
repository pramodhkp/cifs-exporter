FROM golang:latest
WORKDIR /go/src/cifs-exporter
COPY . .
RUN go get -d -v ./...
RUN go build

RUN cp cifs-exporter /usr/local/bin/cifs-exporter
EXPOSE 9965
ENTRYPOINT ["/usr/local/bin/cifs-exporter"]
