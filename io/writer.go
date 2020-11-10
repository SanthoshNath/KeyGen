package io

import (
	"io"
	"os"
	"path"
)

func Write(filepath string, data string) error {
	file, err := os.OpenFile(path.Clean(filepath), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	_, err = io.WriteString(file, data)
	if err != nil {
		return err
	}

	return file.Sync()
}
