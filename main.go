package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ulog"
)

const progname = "tcpsplice"
const version = "1.4.0"

var (
	config  *uconfig.UConfig
	logger  *ulog.ULog
	started time.Time
	unbind  bool
)

func main() {
	var err error

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <configuration file>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	if config, err = uconfig.New(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "configuration file syntax error: %s - aborting\n", err)
		os.Exit(2)
	}

	logger = ulog.New(config.GetString(progname+".log", "console(output=stdout)"))
	logger.Info(map[string]interface{}{"scope": "main", "event": "start", "version": version, "config": os.Args[1], "pid": os.Getpid(),
		"services": len(config.GetPaths(progname + ".service"))})
	started = time.Now()

	go service_run()
	go monitor_run()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGUSR1)
	for {
		signal := <-signals
		switch {
		case signal == syscall.SIGHUP:
			if _, err = uconfig.New(os.Args[1]); err == nil {
				config.Load(os.Args[1])
				logger.Load(config.GetString(progname+".log", "console(output=stdout)"))
				logger.Info(map[string]interface{}{"scope": "main", "event": "reload", "version": version, "config": os.Args[1], "pid": os.Getpid(),
					"services": len(config.GetPaths(progname + ".service"))})
			} else {
				logger.Warn(map[string]interface{}{"scope": "main", "event": "reload", "config": os.Args[1], "error": fmt.Sprintf("%v", err)})
			}

		case signal == syscall.SIGUSR1:
			unbind = !unbind
			if unbind {
				logger.Info(map[string]interface{}{"scope": "main", "event": "unbind", "services": len(config.GetPaths(progname + ".service"))})
			} else {
				logger.Info(map[string]interface{}{"scope": "main", "event": "rebind", "services": len(config.GetPaths(progname + ".service"))})
			}
		}
	}
}
