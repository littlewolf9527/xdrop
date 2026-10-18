package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/api"
	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/config"
	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/secret"
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"github.com/littlewolf9527/xdrop/controller/core/webui"
	"golang.org/x/term"
)

type manager interface {
	api.Nodes
	rules.ChangeSink
	Start(*rules.Service)
	Stop()
}
type server interface {
	Serve(net.Listener) error
	ListenAndServe() error
	Shutdown(context.Context) error
}
type assembly struct {
	static  http.Handler
	hub     interface{ Close() }
	open    func(string) (*store.DB, error)
	prepare func(*store.DB) (rules.Report, error)
	manager func([]nc.NodeSpec, orch.Options) manager
	service func(*store.DB, rules.ChangeSink, ...func() []rules.DeliveryNode) *rules.Service
	api     func(*rules.Service, api.Nodes, *auth.Service) http.Handler
	server  func(string, http.Handler) server
	close   func(*store.DB) error
}

var readMaster = secret.Load
var readNodes = store.Nodes

func defaults() assembly {
	return assembly{
		static: webui.Handler(),
		open:   store.Open, prepare: rules.Prepare,
		manager: func(specs []nc.NodeSpec, opts orch.Options) manager { return orch.New(specs, opts) },
		service: rules.New,
		server:  func(addr string, h http.Handler) server { return &http.Server{Addr: addr, Handler: h} },
		close:   func(db *store.DB) error { return db.Close() },
	}
}
func run(ctx context.Context, cfg config.Config, listener net.Listener) error {
	return assemble(ctx, cfg, listener, defaults())
}
func assemble(ctx context.Context, cfg config.Config, listener net.Listener, a assembly) (result error) {
	db, err := a.open(cfg.Database)
	if err != nil {
		return err
	}
	defer func() {
		if e := a.close(db); e != nil {
			log.Printf("database close: %v", e)
			result = errors.Join(result, e)
		}
	}()
	report, err := a.prepare(db)
	if err != nil {
		return err
	}
	if len(report.Violations) > 0 {
		for _, v := range report.Violations {
			log.Printf("prepare violation: %+v", v)
		}
		return fmt.Errorf("prepare rejected %d violations", len(report.Violations))
	}
	key, err := readMaster(cfg.SecretKeyFile)
	if err != nil {
		return err
	}
	rows, err := readNodes(db.Reader())
	if err != nil {
		return errors.New("cannot read nodes")
	}
	specs := []nc.NodeSpec{}
	for _, row := range rows {
		plain, err := key.Open(row.Name, row.KeyNonce, row.KeyCipher)
		if err != nil {
			continue
		}
		specs = append(specs, nc.NodeSpec{Name: row.Name, BaseURL: row.BaseURL, Key: nc.Secret(plain)})
	}
	settings, err := store.ReadSettings(db.Reader())
	if err != nil {
		return err
	}
	m := a.manager(specs, orch.Options{History: db, ReconcileInterval: time.Duration(settings.ReconcileIntervalMinutes) * time.Minute})
	s := a.service(db, m, api.DeliveryStatus(m))
	acc := auth.New(db)
	acc.OnSettings = func(settings store.Settings) {
		if setter, ok := m.(interface{ SetReconcileInterval(time.Duration) }); ok {
			setter.SetReconcileInterval(time.Duration(settings.ReconcileIntervalMinutes) * time.Minute)
		}
	}
	if s != nil {
		s.Prime(report)
		if limits, ok := m.(interface{ Limits() rules.Limits }); ok {
			s.UseLimits(limits.Limits)
		}
	}
	m.Start(s)
	defer m.Stop()
	var h http.Handler
	if a.api != nil {
		h = a.api(s, m, acc)
	} else {
		h, a.hub = api.NewWithHub(s, m, api.AccountAuthenticator(acc), log.Default(), api.Options{Database: cfg.Database, StartedAt: time.Now(), Accounts: acc, NodeStore: api.NewNodeService(db, key)})
	}
	srv := a.server(cfg.Listen, combineHandlers(h, a.static))
	done := make(chan error, 1)
	go func() {
		if listener == nil {
			done <- srv.ListenAndServe()
		} else {
			done <- srv.Serve(listener)
		}
	}()
	select {
	case <-ctx.Done():
	case err = <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			result = err
		}
	}
	drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if a.hub != nil {
		a.hub.Close()
	}
	if err := srv.Shutdown(drain); err != nil {
		log.Printf("HTTP shutdown: %v", err)
		result = errors.Join(result, err)
	}
	return result
}
func combineHandlers(api, static http.Handler) http.Handler {
	if static == nil {
		static = webui.Handler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			api.ServeHTTP(w, r)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.Method != "GET" && r.Method != "HEAD" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		static.ServeHTTP(w, r)
	})
}
func main() {
	path := flag.String("config", "", "configuration file")
	flag.Parse()
	if code := nodeCommand(flag.Args(), *path, os.Stdin, os.Stderr); code >= 0 {
		os.Exit(code)
	}
	if code := accountCommand(flag.Args(), *path, os.Stdin, os.Stderr); code >= 0 {
		os.Exit(code)
	}
	cfg, err := config.Load(*path)
	if err == nil {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err = run(ctx, cfg, nil)
		stop()
	}
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func accountCommand(args []string, path string, in *os.File, out io.Writer) int {
	if len(args) == 0 {
		return -1
	}
	if len(args) != 3 || args[0] != "user" || (args[1] != "add" && args[1] != "passwd") {
		fmt.Fprintln(out, "usage: xdrop-controller -config <file> user {add|passwd} <name>")
		return 2
	}
	fail := func(message string) int { fmt.Fprintln(out, message); return 1 }
	cfg, err := config.Load(path)
	if err != nil {
		return fail("cannot load configuration")
	}
	db, err := store.Open(cfg.Database)
	if err != nil {
		return fail("cannot open account database")
	}
	defer db.Close()
	password, err := readPassword(in, out)
	if err != nil {
		return fail("cannot read matching password")
	}
	acc := auth.New(db)
	var e *rules.Error
	if args[1] == "add" {
		e = acc.CreateUser(rules.Actor{Kind: rules.System, Name: "cli"}, args[2], password, "admin")
	} else {
		e = acc.SetPassword(rules.Actor{Kind: rules.System, Name: "cli"}, args[2], password)
	}
	if e != nil {
		return fail(e.Code)
	}
	return 0
}
func readPassword(in *os.File, out io.Writer) (string, error) {
	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && !(err == io.EOF && len(line) > 0) {
			return "", errors.New("password input failed")
		}
		return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
	}
	fmt.Fprint(out, "Password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(out)
	if err != nil {
		return "", errors.New("password input failed")
	}
	fmt.Fprint(out, "Repeat password: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(out)
	if err != nil || string(first) != string(second) {
		return "", errors.New("password input mismatch")
	}
	return string(first), nil
}

func nodeCommand(args []string, path string, in *os.File, out io.Writer) int {
	if len(args) == 0 || args[0] != "node" && args[0] != "secret-key" {
		return -1
	}
	fail := func(message string, code int) int { fmt.Fprintln(out, message); return code }
	initKey := args[0] == "secret-key"
	operation := ""
	patch := api.NodePatch{}
	keyStdin := false
	if initKey {
		if len(args) != 2 || args[1] != "init" {
			return fail("usage: secret-key init", 2)
		}
	} else {
		if len(args) < 3 {
			return fail("usage: node {add|update|delete} <name> [--url U] [--key-stdin]", 2)
		}
		operation = map[string]string{"add": "create", "update": "update", "delete": "delete"}[args[1]]
		if operation == "" {
			return fail("invalid node operation", 2)
		}
		flags := flag.NewFlagSet("node", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		url := flags.String("url", "", "node URL")
		flags.BoolVar(&keyStdin, "key-stdin", false, "read node key")
		if flags.Parse(args[3:]) != nil || flags.NArg() != 0 {
			return fail("invalid node arguments", 2)
		}
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "url" {
				patch.BaseURL = url
			}
		})
		if operation == "delete" && (patch.BaseURL != nil || keyStdin) {
			return fail("delete takes no node fields", 2)
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return fail(err.Error(), 1)
	}
	if initKey {
		if err = secret.Init(cfg.SecretKeyFile); err != nil {
			return fail(err.Error(), 1)
		}
		return 0
	}
	key, err := readMaster(cfg.SecretKeyFile)
	if err != nil {
		return fail(err.Error(), 1)
	}
	db, err := store.Open(cfg.Database)
	if err != nil {
		return fail("cannot open node database", 1)
	}
	defer db.Close()
	if keyStdin {
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && !(err == io.EOF && len(line) > 0) {
			return fail("cannot read node key", 1)
		}
		plain := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		patch.APIKey = &plain
	}
	_, failure := api.NewNodeService(db, key).Change(rules.Actor{Kind: rules.System, Name: "cli"}, operation, args[2], patch)
	if failure != nil {
		return fail(failure.Code+": "+failure.Message, 1)
	}
	return 0
}
