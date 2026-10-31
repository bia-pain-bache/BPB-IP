package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bpb-ip/internal/app"
)

func main() {
	configPath := flag.String("config", "config.json", "path to the JSON configuration file")
	listPath := flag.String("list", "list.txt", "path to the local endpoint list")
	outputPath := flag.String("output", "results/ips.json", "path for the scan results")
	dryRun := flag.Bool("dry-run", false, "scan endpoints without changing Cloudflare DNS")
	configureCloudflare := flag.Bool("configure-cloudflare", false, "read zone ID, hostname, and API token from stdin and save them in config")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags)
	if *configureCloudflare {
		if err := app.ConfigureCloudflare(*configPath, os.Stdin); err != nil {
			logger.Printf("error: %v", err)
			os.Exit(1)
		}
		return
	}
	config, err := app.LoadConfig(*configPath)
	if err != nil {
		logger.Printf("error: %v", err)
		os.Exit(1)
	}
	interval, err := config.ScanIntervalDuration()
	if err != nil {
		logger.Printf("error: %v", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	options := app.Options{
		Context:    ctx,
		ConfigPath: *configPath,
		ListPath:   *listPath,
		OutputPath: *outputPath,
		DryRun:     *dryRun,
		Logger:     logger,
	}
	for {
		if err := app.Run(options); err != nil {
			logger.Printf("error: %v", err)
		}
		config, err := app.LoadConfig(*configPath)
		if err != nil {
			logger.Printf("error reloading config for scan interval; keeping previous interval %s: %v", interval, err)
		} else if updatedInterval, err := config.ScanIntervalDuration(); err != nil {
			logger.Printf("error reloading scan interval; keeping previous interval %s: %v", interval, err)
		} else {
			interval = updatedInterval
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
