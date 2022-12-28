package main

import (
	"context"
	cryto_rand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/relvacode/interrupt"
	"github.com/relvacode/ls3"
	"go.uber.org/zap"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync/atomic"
	"text/template"
	"time"
)

const ls3StartupTemplate = `
[Lightweight Object Storage Server]
Version           {{ .Version }}
Directory         {{ .AbsPath }}{{ .Sep }}[*]
Endpoint          http://{{if .Domain }}{{ .Domain }}{{ else }}{{ .Host }}{{ end }}:{{ .Port }}
Public Access     {{ .PublicAccess }}
Access Key ID     {{ .AccessKeyId }}
Secret Access Key {{ .SecretAccessKey }}

! The default credentials have full access to this system and its data
! unless a global policy explicitly denies access.
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

func SecureRandStringBase64(n int) string {
	rawSecret := make([]byte, n)
	_, err := io.ReadFull(cryto_rand.Reader, rawSecret)
	if err != nil {
		panic(err)
	}

	return base64.URLEncoding.WithPadding('+').EncodeToString(rawSecret)
}

func readPolicyFromFile(f string) ([]*ls3.PolicyStatement, error) {
	r, err := os.Open(f)
	if err != nil {
		return nil, err
	}

	defer r.Close()

	var acl []*ls3.PolicyStatement
	err = json.NewDecoder(r).Decode(&acl)
	if err != nil {
		return nil, err
	}

	return acl, nil
}

func NewServerPool(ctx context.Context, log *zap.Logger) *ServerPool {
	ctx, cancel := context.WithCancel(ctx)
	return &ServerPool{
		ctx:                ctx,
		cancel:             cancel,
		log:                log,
		serversAllInactive: make(chan struct{}),
	}
}

type ServerPool struct {
	ctx                context.Context
	cancel             context.CancelFunc
	log                *zap.Logger
	serversActive      int32
	serversAllInactive chan struct{}
}

// Start a new HTTP server in the pool
func (p *ServerPool) Start(server *http.Server) {
	atomic.AddInt32(&p.serversActive, 1)
	go func() {
		defer func() {
			p.cancel()

			if atomic.AddInt32(&p.serversActive, -1) == 0 {
				close(p.serversAllInactive)
			}
		}()

		p.log.Info(fmt.Sprintf("Start HTTP server on %s", server.Addr))

		err := server.ListenAndServe()
		if err != nil {
			p.log.Error("HTTP server stopped", zap.Error(err))
		}
	}()
	go func() {
		<-p.ctx.Done()

		timeout, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		_ = server.Shutdown(timeout)
	}()
}

// Wait for all active servers to shut down
func (p *ServerPool) Wait() {
	<-p.serversAllInactive
	p.log.Info("All servers stopped")
}

type Command struct {
	ListenAddr        string `long:"listen-addr" env:"LISTEN_ADDRESS" default:"127.0.0.1:9000" description:"HTTP listen address"`
	MetricsListenAddr string `long:"metrics-listen-addr" env:"METRICS_LISTEN_ADDRESS" default:"127.0.0.1:9001" description:"HTTP listen address for the metrics server"`
	Domain            string `long:"domain" env:"DOMAIN" description:"Host style addressing on this domain"`
	AccessKeyId       string `long:"access-key-id" env:"ACCESS_KEY_ID" description:"Set the access key id. Generated if not provided."`
	SecretAccessKey   string `long:"secret-access-key" env:"SECRET_ACCESS_KEY" description:"Set the secret access key. Generated if not provided. If provided, access key id must also be provided"`
	GlobalPolicyFile  string `long:"global-policy" env:"GLOBAL_POLICY_FILE" description:"Read the global server access policy from this file."`
	CredentialsFile   string `long:"credentials" env:"CREDENTIALS_FILE" description:"Read credentials from this file."`
	PublicAccess      bool   `long:"public-access" env:"PUBLIC_ACCESS" description:"Enable public access to all resources provided by this server. When enabled, adds UNAUTHENTICATED to the default policy. The behaviour of the UNAUTHENTICATED identity can still be managed through a custom identity or the global policy"`

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

	var globalPolicy []*ls3.PolicyStatement

	// Read global policy from file (if defined)
	if cmd.GlobalPolicyFile != "" {
		globalPolicy, err = readPolicyFromFile(cmd.GlobalPolicyFile)
		if err != nil {
			return err
		}
	} else {
		// Otherwise, the global policy is allow all.
		// This has the effect of using identity specific policies only.
		globalPolicy = []*ls3.PolicyStatement{
			{
				Resource: []ls3.Resource{"*"},
				Action:   []ls3.Action{"*"},
			},
		}
	}

	if (cmd.AccessKeyId == "") != (cmd.SecretAccessKey == "") {
		return errors.New("both access key id and secret access key must be provided, or neither")
	}

	if cmd.AccessKeyId == "" {
		log.Warn("ACCESS_KEY_ID not provided. Credentials will be generated automatically but will change next time the server starts!")
		cmd.AccessKeyId = RandStringRunes(20, []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
		cmd.SecretAccessKey = SecureRandStringBase64(36)
	}

	defaultKeyring := ls3.Keyring{
		// The default identity root (provided directly on the command line or generated automatically)
		// always has full access to the system unless otherwise denied by a global policy.
		cmd.AccessKeyId: &ls3.Identity{
			Name:            "root",
			AccessKeyId:     cmd.AccessKeyId,
			SecretAccessKey: cmd.SecretAccessKey,
			Policy: []*ls3.PolicyStatement{
				{
					Action:   []ls3.Action{"*"},
					Resource: []ls3.Resource{"*"},
				},
			},
		},
		ls3.IdentityUnauthenticatedPublic: &ls3.Identity{
			Name:        "public",
			AccessKeyId: ls3.IdentityUnauthenticatedPublic,
			Policy: []*ls3.PolicyStatement{
				{
					Deny:     !cmd.PublicAccess,
					Action:   []ls3.Action{"*"},
					Resource: []ls3.Resource{"*"},
				},
			},
		},
	}

	var identityProvider ls3.IdentityProvider = defaultKeyring

	if cmd.CredentialsFile != "" {
		fromFile, err := ls3.NewFileIdentityProvider(log, cmd.CredentialsFile, time.Minute*5)
		if err != nil {
			return err
		}

		// Setup a MultiIdentityProvider to read from file then the defaultKeyring.
		identityProvider = ls3.MultiIdentityProvider{fromFile, defaultKeyring}
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
		"Sep":             string(os.PathSeparator),
		"Host":            host,
		"Port":            port,
		"PublicAccess":    cmd.PublicAccess,
		"Domain":          cmd.Domain,
		"AccessKeyId":     cmd.AccessKeyId,
		"SecretAccessKey": cmd.SecretAccessKey,
	})

	var (
		ctx           = interrupt.Context(context.Background())
		serverPool    = NewServerPool(ctx, log)
		serverOptions = &ls3.ServerOptions{
			Log:          log,
			Signer:       ls3.SignAWSV4{},
			Identity:     identityProvider,
			Domain:       cmd.Domain,
			GlobalPolicy: globalPolicy,
			Filesystem: &ls3.SubdirBucketFilesystem{
				FS: os.DirFS(absPath),
			},
		}
	)

	serverPool.Start(&http.Server{
		Addr:    cmd.ListenAddr,
		Handler: ls3.NewServer(serverOptions),
	})

	if cmd.MetricsListenAddr != "" {
		serverPool.Start(&http.Server{
			Addr:    cmd.MetricsListenAddr,
			Handler: promhttp.HandlerFor(ls3.StatRegistry, promhttp.HandlerOpts{}),
		})
	}

	serverPool.Wait()

	return nil
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
