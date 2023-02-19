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

const PROGNAME = "tcpsplice"
const VERSION = "1.4.1"

var (
	Config  *uconfig.UConfig
	Logger  *ulog.ULog
	Started time.Time
	Unbind  bool
)

func main() {
	var err error

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <configuration file>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	if Config, err = uconfig.New(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "configuration file syntax error: %s - aborting\n", err)
		os.Exit(2)
	}

	Logger = ulog.New(Config.GetString(PROGNAME+".log", "console(output=stdout)"))
	Logger.Info(map[string]any{
		"scope": "main", "event": "start", "version": VERSION, "config": os.Args[1],
		"pid": os.Getpid(), "services": len(Config.GetPaths(PROGNAME + ".service")),
	})
	Started = time.Now()

	go ServiceRun()
	go MonitorRun()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGUSR1)
	for {
		signal := <-signals
		switch {
		case signal == syscall.SIGHUP:
			if _, err = uconfig.New(os.Args[1]); err == nil {
				Config.Load(os.Args[1])
				Logger.Load(Config.GetString(PROGNAME+".log", "console(output=stdout)"))
				Logger.Info(map[string]any{
					"scope": "main", "event": "reload", "version": VERSION, "config": os.Args[1],
					"pid": os.Getpid(), "services": len(Config.GetPaths(PROGNAME + ".service")),
				})
			} else {
				Logger.Warn(map[string]any{
					"scope": "main", "event": "reload", "config": os.Args[1], "error": fmt.Sprintf("%v", err),
				})
			}

		case signal == syscall.SIGUSR1:
			Unbind = !Unbind
			if Unbind {
				Logger.Info(map[string]any{
					"scope": "main", "event": "unbind", "services": len(Config.GetPaths(PROGNAME + ".service")),
				})
			} else {
				Logger.Info(map[string]any{
					"scope": "main", "event": "rebind", "services": len(Config.GetPaths(PROGNAME + ".service")),
				})
			}
		}
	}
}
