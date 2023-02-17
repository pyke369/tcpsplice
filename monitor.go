package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/acl"
	"github.com/pyke369/golang-support/dynacert"
)

var (
	MonitorUpdate   = make(chan *SESSION, 128)
	monitorSessions = map[string]*SESSION{}
	monitorLock     sync.RWMutex
)

func monitorHandle(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Server", PROGNAME+"/"+VERSION)
	response.Header().Set("Access-Control-Allow-Origin", "*")

	if request.Method == "OPTIONS" {
		return
	}
	if request.Method != "GET" {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	credentials, noauth := "", len(Config.GetPaths(PROGNAME+".monitor.noauth")) > 0 && acl.CIDRConfig(request.RemoteAddr, Config, PROGNAME+".monitor.noauth")
	if username, password, ok := request.BasicAuth(); ok {
		credentials = username + ":" + password
	}
	if !noauth && len(Config.GetPaths(PROGNAME+".monitor.auth")) > 0 && !acl.PasswordConfig(credentials, Config, PROGNAME+".monitor.auth") {
		response.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", PROGNAME))
		response.WriteHeader(http.StatusUnauthorized)
		return
	}

	switch {
	case request.URL.Path == "/sessions.json":
		output := map[string]any{
			"server": map[string]any{
				"version": VERSION,
				"uptime":  time.Since(Started) / time.Second,
			},
		}
		services := map[string]any{}
		for _, name := range Config.GetPaths(PROGNAME + ".service") {
			name = strings.TrimPrefix(name, PROGNAME+".service.")
			entries := map[string]any{}
			monitorLock.RLock()
			for id, session := range monitorSessions {
				if session.name == name {
					entries[id] = map[string]any{
						"started":  session.started.Unix(),
						"duration": time.Since(session.started) / time.Second,
						"source":   session.source,
						"local":    session.local,
						"target":   session.target,
						"bytes":    [2]int64{session.smetrics.read, session.tmetrics.read},
						"mean":     [2]float64{session.smetrics.mean, session.tmetrics.mean},
						"last":     [2]float64{session.smetrics.last, session.tmetrics.last},
						"opaque":   session.opaque,
						"done":     session.done,
						"spliced":  session.spliced,
						"secure":   session.secure,
						"multi":    session.multi,
					}
				}
			}
			monitorLock.RUnlock()
			services[name] = entries
		}
		output["services"] = services
		response.Header().Set("Content-Type", "application/json")
		if json, err := json.Marshal(output); err == nil {
			response.Write(json)
		}

	case strings.HasPrefix(request.URL.Path, "/abort/"):
		monitorLock.RLock()
		for id, session := range monitorSessions {
			if id == request.URL.Path[7:] && !session.done {
				session.done = true
				session.abort <- true
				Logger.Warn(map[string]any{
					"scope": "monitor", "event": "abort", "id": id, "name": session.name,
					"source": session.source, "local": session.local, "target": session.target,
				})
				break
			}
		}
		monitorLock.RUnlock()
	}
}

func MonitorRun() {
	handler := http.NewServeMux()
	handler.HandleFunc("/sessions.json", monitorHandle)
	handler.HandleFunc("/abort/", monitorHandle)
	handler.Handle("/", http.StripPrefix("/", ResourcesHandler(6*time.Hour)))

	go func() {
		var server *http.Server

		key := ""
		for {
			time.Sleep(time.Second)
			if Unbind {
				if server != nil {
					Logger.Info(map[string]any{
						"scope": "monitor", "event": "close", "listen": strings.Split(key, "@@")[0],
					})
					server.Shutdown(context.Background())
					key, server = "", nil
				}
				continue
			}
			if parts := strings.Split(Config.GetStringMatch(PROGNAME+".monitor.listen", "_", `^.*?(:\d+)?((,[^,]+){2})?$`), ","); parts[0] != "_" {
				if value := strings.Join(parts, "@@"); value != key {
					if server != nil {
						Logger.Info(map[string]any{
							"scope": "monitor", "event": "close", "listen": strings.Split(key, "@@")[0],
						})
						server.Shutdown(context.Background())
					}
					key, server = value, &http.Server{
						Addr:         strings.TrimLeft(parts[0], "*"),
						Handler:      handler,
						ErrorLog:     log.New(io.Discard, "", 0),
						ReadTimeout:  10 * time.Second,
						WriteTimeout: 10 * time.Second,
						IdleTimeout:  30 * time.Second,
						TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
					}
					if len(parts) > 1 {
						certificate := &dynacert.DYNACERT{}
						certificate.Add("*", parts[1], parts[2])
						server.TLSConfig = dynacert.IntermediateTLSConfig(certificate.GetCertificate)
						go func(server *http.Server, parts []string) {
							Logger.Info(map[string]any{
								"scope": "monitor", "event": "listen", "listen": parts[0], "certificate": strings.Join(parts[1:], ","),
							})
							server.ListenAndServeTLS("", "")
							key = ""
						}(server, parts)
					} else {
						go func(server *http.Server, parts []string) {
							Logger.Info(map[string]any{
								"scope": "monitor", "event": "listen", "listen": parts[0],
							})
							server.ListenAndServe()
							key = ""
						}(server, parts)
					}
				}
			}
		}
	}()

	go func() {
		for range time.Tick(time.Second) {
			count := 0
			monitorLock.Lock()
			for id, session := range monitorSessions {
				if time.Since(session.update) >= 3*time.Second {
					delete(monitorSessions, id)
					count++
				}
			}
			monitorLock.Unlock()
			if count > 0 {
				Logger.Info(map[string]any{
					"scope": "monitor", "event": "clean", "sessions": count,
				})
			}
		}
	}()

	for {
		session := <-MonitorUpdate
		id := session.id
		monitorLock.Lock()
		if monitorSessions[id] == nil {
			monitorSessions[id] = &SESSION{
				name:    session.name,
				source:  session.source,
				local:   session.local,
				target:  session.target,
				started: session.started,
				secure:  session.secure,
				multi:   session.multi,
				spliced: session.spliced,
				abort:   session.abort,
			}
		}
		duration := math.Max(float64(time.Since(session.started))/float64(time.Second), 0.001)
		session.smetrics.mean = math.Floor(float64(session.tmetrics.write*8)/(duration*1000)) / 1000
		session.tmetrics.mean = math.Floor(float64(session.smetrics.write*8)/(duration*1000)) / 1000
		if !session.update.IsZero() && !monitorSessions[id].update.IsZero() {
			duration = math.Max(float64(session.update.Sub(monitorSessions[id].update))/float64(time.Second), 0.001)
			session.smetrics.last = math.Floor(float64((session.tmetrics.write-monitorSessions[id].tmetrics.write)*8)/(duration*1000)) / 1000
			session.tmetrics.last = math.Floor(float64((session.smetrics.write-monitorSessions[id].smetrics.write)*8)/(duration*1000)) / 1000
		} else {
			session.smetrics.last = session.smetrics.mean
			session.tmetrics.last = session.tmetrics.mean
		}
		monitorSessions[id].opaque = session.opaque
		monitorSessions[id].update = session.update
		monitorSessions[id].done = session.done
		monitorSessions[id].smetrics.read = session.smetrics.read
		monitorSessions[id].smetrics.write = session.smetrics.write
		monitorSessions[id].smetrics.mean = session.smetrics.mean
		monitorSessions[id].smetrics.last = session.smetrics.last
		monitorSessions[id].tmetrics.read = session.tmetrics.read
		monitorSessions[id].tmetrics.write = session.tmetrics.write
		monitorSessions[id].tmetrics.mean = session.tmetrics.mean
		monitorSessions[id].tmetrics.last = session.tmetrics.last
		monitorLock.Unlock()
	}
}
