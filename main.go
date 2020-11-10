package main

import (
	"crypto/elliptic"
	"errors"
	flag "github.com/juju/gnuflag"
	log "github.com/sirupsen/logrus"
	"keygen/key"
	"os"
)

var filepath = "./"

func main() {
	if len(os.Args) == 1 {
		handleError(errors.New("command not found"))
	}

	output := flag.Bool("o", false, "output path")

	flag.Parse(true)

	if *output {
		defer func() {
			if err := recover(); err != nil {
				handleError(errors.New("invalid path"))
			}
		}()
		filepath = os.Args[3]
	}

	switch os.Args[1] {
	case "rsa":
		key := key.NewRSAKey(2048)

		log.Info("Generating Keys")
		if err := key.Generate(); err != nil {
			handleError(err)
		}

		log.Info("Exporting Keys")
		if err := key.Export(filepath); err != nil {
			handleError(err)
		}

	case "ecdsa":
		key := key.NewECDSAKey(elliptic.P256())

		log.Info("Generating Keys")
		if err := key.Generate(); err != nil {
			handleError(err)
		}

		log.Info("Exporting Keys")
		if err := key.Export(filepath); err != nil {
			handleError(err)
		}
	}
}

func handleError(err error) {
	log.Error(err.Error())
	os.Exit(1)
}
