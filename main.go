package main

import (
	"flag"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shibumi/cifs-exporter/cifs"
	"github.com/shibumi/cifs-exporter/collector"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

var version, commit, date string

func main() {
	listenAddr := flag.String("web.listen-address", ":9965", "Address to listen on for web interface and telemetry.")
	metricsPath := flag.String("web.telemetry-path", "/metrics", "A path under which to expose metrics.")
	appVersion := flag.Bool("version", false, "Display version information")
	flag.Parse()
	if *appVersion {
		println(filepath.Base(os.Args[0]), version, commit, date)
		os.Exit(0)
	}
	registry := prometheus.NewRegistry()

	stats, _ := cifs.NewClientStats()
	log.Println(stats)
	http.Handle(*metricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`<html>
			<head><title>CIFS Exporter</title></head>
			<body>
			<h1>CIFS Exporter</h1>
			<p><a href='` + *metricsPath + `'>Metrics</a></p>
			</body>
			</html>`))
		if err != nil {
			log.Println(err)
		}
	})

	registry.MustRegister(collector.NewCIFSCollector())

	srv := &http.Server{}
	listener, err := net.Listen("tcp4", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Providing metrics at %s%s", *listenAddr, *metricsPath)
	log.Fatal(srv.Serve(listener))
}
