package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"testing_Watcher/watcher"
)

func main() {
	// Initialize the file watcher
	fw, err := watcher.NewFileWatcher(`C:\Users\Raj\`)
	if err != nil {
		log.Fatal("Error initializing watcher:", err)
	}
	defer fw.Close()

	// Wait for interrupt signal (CTRL+C)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
}
