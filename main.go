package main

import (
	"crypto/elliptic"
	"errors"
	flag "github.com/juju/gnuflag"
	log "github.com/sirupsen/logrus"
	"keygen/key"
	"os"
	"strconv"
)

var filepath = "./"

func main() {
	parseCommand()

	switch os.Args[1] {
	case "rsa":
		bits, err := strconv.Atoi(os.Args[2])
		if err != nil {
			handleError(errors.New("invalid key size"))
		}

		key := key.NewRSAKey(bits)

		if err := key.Generate(); err != nil {
			handleError(err)
		}

		if err := key.Export(filepath); err != nil {
			handleError(err)
		}

	case "ecdsa":
		var curve elliptic.Curve

		if os.Args[2] == "p224" {
			curve = elliptic.P224()
		} else if os.Args[2] == "p256" {
			curve = elliptic.P256()
		} else if os.Args[2] == "p384" {
			curve = elliptic.P384()
		} else if os.Args[2] == "p521" {
			curve = elliptic.P521()
		} else {
			handleError(errors.New("unsupported ecdsa curve"))
		}

		key := key.NewECDSAKey(curve)

		if err := key.Generate(); err != nil {
			handleError(err)
		}

		if err := key.Export(filepath); err != nil {
			handleError(err)
		}
	}
}

func parseCommand() {
	if len(os.Args) <= 1 {
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
		filepath = os.Args[4]
	}

	if len(os.Args) != 3 {
		if len(os.Args) != 5 {
			handleError(errors.New("insufficient arguments"))
		}
	}
}

func handleError(err error) {
	log.Error(err.Error())
	os.Exit(0)
}
