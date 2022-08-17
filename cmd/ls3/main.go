package main

import (
	"context"
	"errors"
	"github.com/jessevdk/go-flags"
	"github.com/relvacode/interrupt"
	"github.com/relvacode/ls3"
	"go.uber.org/zap"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"text/template"
	"time"
)

const ls3StartupTemplate = `
[Lightweight Object Storage Server]
Version           {{ .Version }}
Directory         {{ .AbsPath }}{{ if .MultiBucket }}/[*]{{ end }}
Endpoint          http://{{if .Domain }}{{ .Domain }}{{ else }}{{ .Host }}{{ end }}:{{ .Port }}
Access Key ID     {{ .AccessKeyID }}
Secret Access Key {{ .SecretAccessKey }}
`

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
	ListenAddr      string `long:"listen-addr" env:"LISTEN_ADDRESS" default:"127.0.0.1:9000" description:"HTTP listen address"`
	Domain          string `long:"domain" env:"DOMAIN" description:"Host style addressing on this domain"`
	MultiBucket     bool   `long:"multi-bucket" env:"MULTI_BUCKET" description:"Treat each requested bucket as a subdirectory of the base filesystem"`
	AccessKeyId     string `long:"access-key-id" env:"ACCESS_KEY_ID" description:"Set the access key id. Generated if not provided."`
	SecretAccessKey string `long:"secret-access-key" env:"SECRET_ACCESS_KEY" description:"Set the secret access key. Generated if not provided. If provided, access key id must also be provided"`

	Positional struct {
		Path string `required:"true" description:"The root directory to serve"`
	} `positional-args:"true"`
}

func getBuildVersion(info *debug.BuildInfo) (version string) {
	version = "unknown"
	if info == nil {
		return
	}

	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}

	return
}

func Main(log *zap.Logger) error {
	var cmd Command
	p := flags.NewParser(&cmd, flags.HelpFlag)

	_, err := p.Parse()
	if err != nil {
		return err
	}

	if (cmd.AccessKeyId == "") != (cmd.SecretAccessKey == "") {
		return errors.New("both access key id and secret access key must be provided, or neither")
	}

	if cmd.AccessKeyId == "" {
		log.Warn("ACCESS_KEY_ID not provided. Credentials will be generated automatically but will change next time the server starts!")
		cmd.AccessKeyId = RandStringRunes(20, []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
		cmd.SecretAccessKey = RandStringRunes(40, []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
	}

	keyring := ls3.Keyring{
		cmd.AccessKeyId: &ls3.Identity{
			AccessKeyID:     cmd.AccessKeyId,
			SecretAccessKey: cmd.SecretAccessKey,
			ACL: []*ls3.Policy{
				{
					Action:   []ls3.Action{"*"},
					Resource: []ls3.Resource{"*"},
				},
			},
		},
	}

	absPath, err := filepath.Abs(cmd.Positional.Path)
	if err != nil {
		return err
	}

	info, _ := debug.ReadBuildInfo()

	host, port, _ := net.SplitHostPort(cmd.ListenAddr)

	t := template.Must(template.New("startup").Parse(ls3StartupTemplate))
	_ = t.Execute(os.Stderr, map[string]interface{}{
		"Version":         getBuildVersion(info),
		"AbsPath":         absPath,
		"Host":            host,
		"Port":            port,
		"Domain":          cmd.Domain,
		"MultiBucket":     cmd.MultiBucket,
		"AccessKeyID":     cmd.AccessKeyId,
		"SecretAccessKey": cmd.SecretAccessKey,
	})

	fileSystem := os.DirFS(absPath)

	var buckets ls3.BucketFilesystemProvider
	if cmd.MultiBucket {
		buckets = &ls3.SubdirBucketFilesystem{FS: fileSystem}
	} else {
		buckets = &ls3.SingleBucketFilesystem{FS: fileSystem}
	}

	var (
		ctx     = interrupt.Context(context.Background())
		exit    = make(chan error, 1)
		handler = ls3.NewServer(log, ls3.SignAWSV4{}, keyring, buckets, cmd.Domain)
		server  = &http.Server{
			Addr:    cmd.ListenAddr,
			Handler: handler,
		}
	)

	go func() {
		<-ctx.Done()

		timeout, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		_ = server.Shutdown(timeout)
	}()

	go func() {
		log.Info("Start HTTP server")
		exit <- server.ListenAndServe()
	}()

	err = <-exit
	if err == http.ErrServerClosed {
		err = nil
	}

	return err
}

func main() {
	cfg := zap.NewDevelopmentConfig()
	log, _ := cfg.Build()

	err := Main(log)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
}
