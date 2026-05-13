package server

import (
	"log"
	"net/http"
	"time"

	"github.com/bsv9/fsa-mock/internal/config"
)

func Run(cfg *config.Config) error {
	mux := http.NewServeMux()
	mux.Handle("/jsonrpc", newHandler(cfg))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("fsa-mock listening on %s (plain HTTP — terminate TLS in front)", cfg.Addr)
	return srv.ListenAndServe()
}
