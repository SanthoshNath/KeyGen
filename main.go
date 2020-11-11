package main

import (
	"crypto/elliptic"
	"errors"
	flag "github.com/juju/gnuflag"
	log "github.com/sirupsen/logrus"
	"keygen/key"
	"os"
	"strconv"
	"strings"
)

var filepath = "./"

func main() {
	parseKeygenCommand()

	switch os.Args[1] {
	case "rsa":
		defer func() {
			if err := recover(); err != nil {
				handleError(errors.New("command not found"))
			}
		}()

		bits, err := strconv.Atoi(os.Args[2])
		if err != nil {
			handleError(errors.New("invalid key size"))
		}

		keys := key.NewRSAKey(bits)

		if err := keys.Generate(); err != nil {
			handleError(err)
		}

		if err := keys.Export(filepath); err != nil {
			handleError(err)
		}

	case "ecdsa":
		defer func() {
			if err := recover(); err != nil {
				handleError(errors.New("command not found"))
			}
		}()

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

		keys := key.NewECDSAKey(curve)

		if err := keys.Generate(); err != nil {
			handleError(err)
		}

		if err := keys.Export(filepath); err != nil {
			handleError(err)
		}

	case "ed25519":
		if len(os.Args) == 3 || len(os.Args) == 4 && os.Args[2] != "-o" || len(os.Args) > 4 {
			handleError(errors.New("too many arguments"))
		}

		keys := key.NewED25519Key()

		if err := keys.Generate(); err != nil {
			handleError(err)
		}

		if err := keys.Export(filepath); err != nil {
			handleError(err)
		}

	default:
		handleError(errors.New("command not found"))
	}
}

func parseKeygenCommand() {
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

		var index int
		for index = range os.Args {
			if os.Args[index] == "-o" {
				break
			}
		}

		filepath = os.Args[index+1]
	}

	if len(os.Args) > 5 {
		handleError(errors.New("too many arguments"))
	}
}

func handleError(err error) {
	errorString := strings.SplitAfter(err.Error(), ": ")
	if len(errorString) == 1 {
		log.Error(errorString[0])
	} else {
		log.Error(errorString[1])
	}

	os.Exit(0)
}
