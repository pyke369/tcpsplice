package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/dynacert"
)

var (
	update   = make(chan *SESSION, 128)
	sessions = map[string]*SESSION{}
	lock     sync.RWMutex
)

func monitor_handle(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Server", progname+"/"+version)
	response.Header().Set("Access-Control-Allow-Origin", "*")

	if request.Method == "OPTIONS" {
		return
	}
	if request.Method != "GET" {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	noauth := false
	if remote, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		if remote := net.ParseIP(remote); remote != nil {
			for _, entry := range config.GetPaths(progname + ".monitor.noauth") {
				entry = config.GetString(entry, "")
				if _, network, err := net.ParseCIDR(entry); err == nil {
					if remote != nil && network.Contains(remote) {
						noauth = true
						break
					}
				}
			}
		}
	}
	if !noauth && len(config.GetPaths(progname+".monitor.auth")) != 0 {
		credentials, matched := "", false
		if username, password, ok := request.BasicAuth(); ok {
			credentials = username + ":" + password
		}
		for _, auth := range config.GetPaths(progname + ".monitor.auth") {
			if config.GetString(auth, "") == credentials {
				matched = true
				break
			}
		}
		if !matched {
			response.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", progname))
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	switch {
	case request.URL.Path == "/sessions.json":
		output := map[string]interface{}{
			"server": map[string]interface{}{
				"version": version,
				"uptime":  time.Now().Sub(started) / time.Second,
			},
		}
		services := map[string]interface{}{}
		for _, name := range config.GetPaths(progname + ".service") {
			name = strings.TrimPrefix(name, progname+".service.")
			entries := map[string]interface{}{}
			lock.RLock()
			for id, session := range sessions {
				if session.name == name {
					entries[id] = map[string]interface{}{
						"started":  session.started.Unix(),
						"duration": time.Now().Sub(session.started) / time.Second,
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
			lock.RUnlock()
			services[name] = entries
		}
		output["services"] = services
		response.Header().Set("Content-Type", "application/json")
		if json, err := json.Marshal(output); err == nil {
			response.Write(json)
		}

	case strings.HasPrefix(request.URL.Path, "/abort/"):
		lock.RLock()
		for id, session := range sessions {
			if id == request.URL.Path[7:] && !session.done {
				session.done = true
				session.abort <- true
				logger.Warn(map[string]interface{}{"scope": "monitor", "event": "abort", "id": id, "name": session.name,
					"source": session.source, "local": session.local, "target": session.target})
				break
			}
		}
		lock.RUnlock()
	}
}

func monitor_run() {
	handler := http.NewServeMux()
	handler.HandleFunc("/sessions.json", monitor_handle)
	handler.HandleFunc("/abort/", monitor_handle)
	handler.Handle("/", http.StripPrefix("/", Resources(6*time.Hour)))

	go func() {
		var server *http.Server

		key := ""
		for {
			time.Sleep(time.Second)
			if unbind {
				if server != nil {
					logger.Info(map[string]interface{}{"scope": "monitor", "event": "close", "listen": strings.Split(key, "@@")[0]})
					server.Shutdown(context.Background())
					key, server = "", nil
				}
				continue
			}
			if parts := strings.Split(config.GetStringMatch(progname+".monitor.listen", "_", `^.*?(:\d+)?((,[^,]+){2})?$`), ","); parts[0] != "_" {
				if value := strings.Join(parts, "@@"); value != key {
					if server != nil {
						logger.Info(map[string]interface{}{"scope": "monitor", "event": "close", "listen": strings.Split(key, "@@")[0]})
						server.Shutdown(context.Background())
					}
					key, server = value, &http.Server{
						Addr:         strings.TrimLeft(parts[0], "*"),
						Handler:      handler,
						ErrorLog:     log.New(ioutil.Discard, "", 0),
						ReadTimeout:  10 * time.Second,
						WriteTimeout: 10 * time.Second,
						IdleTimeout:  30 * time.Second,
						TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
					}
					if len(parts) > 1 {
						certificate := &dynacert.DYNACERT{Public: parts[1], Key: parts[2]}
						server.TLSConfig = dynacert.IntermediateTLSConfig(certificate.GetCertificate)
						go func(server *http.Server, parts []string) {
							logger.Info(map[string]interface{}{"scope": "monitor", "event": "listen", "listen": parts[0], "certificate": strings.Join(parts[1:], ",")})
							server.ListenAndServeTLS("", "")
							key = ""
						}(server, parts)
					} else {
						go func(server *http.Server, parts []string) {
							logger.Info(map[string]interface{}{"scope": "monitor", "event": "listen", "listen": parts[0]})
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
			lock.Lock()
			for id, session := range sessions {
				if time.Now().Sub(session.update) >= 3*time.Second {
					delete(sessions, id)
					count++
				}
			}
			lock.Unlock()
			if count > 0 {
				logger.Info(map[string]interface{}{"scope": "monitor", "event": "clean", "sessions": count})
			}
		}
	}()

	for {
		session := <-update
		id := session.id
		lock.Lock()
		if sessions[id] == nil {
			sessions[id] = &SESSION{
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
		duration := math.Max(float64(time.Now().Sub(session.started))/float64(time.Second), 0.001)
		session.smetrics.mean = math.Floor(float64(session.tmetrics.write*8)/(duration*1000)) / 1000
		session.tmetrics.mean = math.Floor(float64(session.smetrics.write*8)/(duration*1000)) / 1000
		if !session.update.IsZero() && !sessions[id].update.IsZero() {
			duration = math.Max(float64(session.update.Sub(sessions[id].update))/float64(time.Second), 0.001)
			session.smetrics.last = math.Floor(float64((session.tmetrics.write-sessions[id].tmetrics.write)*8)/(duration*1000)) / 1000
			session.tmetrics.last = math.Floor(float64((session.smetrics.write-sessions[id].smetrics.write)*8)/(duration*1000)) / 1000
		} else {
			session.smetrics.last = session.smetrics.mean
			session.tmetrics.last = session.tmetrics.mean
		}
		sessions[id].opaque = session.opaque
		sessions[id].update = session.update
		sessions[id].done = session.done
		sessions[id].smetrics.read = session.smetrics.read
		sessions[id].smetrics.write = session.smetrics.write
		sessions[id].smetrics.mean = session.smetrics.mean
		sessions[id].smetrics.last = session.smetrics.last
		sessions[id].tmetrics.read = session.tmetrics.read
		sessions[id].tmetrics.write = session.tmetrics.write
		sessions[id].tmetrics.mean = session.tmetrics.mean
		sessions[id].tmetrics.last = session.tmetrics.last
		lock.Unlock()
	}
}
