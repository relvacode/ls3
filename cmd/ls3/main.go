package main

import (
	"errors"
	"fmt"
	"github.com/jessevdk/go-flags"
	"ls3"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func RandStringRunes(n int, controlSet []rune) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = controlSet[rand.Intn(len(controlSet))]
	}
	return string(b)
}

type Command struct {
	ListenAddr string `long:"listen-addr" default:"127.0.0.1:9000" description:"HTTP listen address"`
	PathStyle  bool   `long:"path-style" env:"PATH_STYLE" description:"Use path-style addressing"`

	AccessKeyId     string `long:"access-key-id" env:"ACCESS_KEY_ID" description:"Set the access key id. Generated if not provided."`
	SecretAccessKey string `long:"secret-access-key" env:"SECRET_ACCESS_KEY" description:"Set the secret access key. Generated if not provided. If provided, access key id must also be provided"`
	Region          string `long:"region" env:"REGION" default:"us-east-1" description:"The signing region"`

	Positional struct {
		Path string `required:"true" description:"The root directory to serve"`
	} `positional-args:"true"`
}

func Main() error {
	var cmd Command
	p := flags.NewParser(&cmd, flags.HelpFlag)

	_, err := p.Parse()
	if err != nil {
		return err
	}

	var signer = ls3.Signer{
		AccessKeyID:     cmd.AccessKeyId,
		SecretAccessKey: cmd.SecretAccessKey,
		Region:          cmd.Region,
	}

	if (signer.AccessKeyID == "") != (signer.SecretAccessKey == "") {
		return errors.New("both access key id and secret access key must be provided, or neither")
	}

	if signer.AccessKeyID == "" {
		signer.AccessKeyID = RandStringRunes(20, []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
		signer.SecretAccessKey = RandStringRunes(40, []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
	}

	absPath, err := filepath.Abs(cmd.Positional.Path)
	if err != nil {
		return err
	}

	fmt.Println("[ls3 Object Storage Server]")
	fmt.Printf("Directory\t%s\n", absPath)
	fmt.Printf("Address\thttp://%s pathStyle=%t\n", cmd.ListenAddr, cmd.PathStyle)
	fmt.Printf("Access Key ID\t%s\n", signer.AccessKeyID)
	fmt.Printf("Secret Access Key\t%s\n", signer.SecretAccessKey)

	s := ls3.NewServer(signer, os.DirFS(absPath), cmd.PathStyle)

	return http.ListenAndServe(cmd.ListenAddr, s)
}

func main() {
	err := Main()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
