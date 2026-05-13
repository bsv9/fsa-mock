package main

import (
	"flag"
	"log"
	"os"

	"github.com/bsv9/fsa-mock/internal/config"
	"github.com/bsv9/fsa-mock/internal/server"
)

func main() {
	envFile := flag.String("env-file", "", "path to .env file (defaults to $FSA_ENV_FILE or ./.env if it exists)")
	flag.Parse()

	path := *envFile
	if path == "" {
		path = os.Getenv("FSA_ENV_FILE")
	}
	if path == "" {
		path = ".env"
	}
	if err := config.LoadDotEnv(path); err != nil {
		log.Fatalf("env file %s: %v", path, err)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := server.Run(cfg); err != nil {
		log.Fatalf("server: %v", err)
	}
}
