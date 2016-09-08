package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ulog"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const progname = "tcpsplice"
const version = "1.0.1"

type Session struct {
	id, service, source, target                          string
	started, active, last                                time.Time
	sourceRead, targetWritten, targetRead, sourceWritten int64
	sourceMeanThroughput, targetMeanThroughput           float64
	sourceLastThroughput, targetLastThroughput           float64
	loggued, done                                        bool
	closer                                               chan bool
}

var (
	config       *uconfig.UConfig
	logger       *ulog.ULog
	start        time.Time
	statistics   chan *Session
	sessions     map[string]*Session
	sessionsLock sync.RWMutex
)

func serviceHandler(service string, listener *net.TCPListener) {
	for {
		if source, err := listener.AcceptTCP(); err == nil {
			remotes := config.GetPaths(fmt.Sprintf("services.%s.remote", service))
			if len(remotes) > 0 {
				go func() {
					remote := config.GetString(remotes[rand.Int31n(int32(len(remotes)))], "")
					if target, err := net.DialTimeout("tcp", remote,
						time.Second*time.Duration(config.GetDurationBounds(fmt.Sprintf("services.%s.connect_timeout", service), 10, 2, 60))); err == nil {
						incomingSize := config.GetSizeBounds(fmt.Sprintf("services.%s.incoming_buffer_size", service), 64*1024, 4*1024, 512*1024)
						outgoingSize := config.GetSizeBounds(fmt.Sprintf("services.%s.outgoing_buffer_size", service), 64*1024, 4*1024, 512*1024)
						logMinimumSize := config.GetSizeBounds(fmt.Sprintf("services.%s.log_minimum_size", service), 1024, 0, math.MaxInt64)
						sessionMinimumSize := config.GetSizeBounds(fmt.Sprintf("services.%s.session_minimum_size", service), 1024, 0, math.MaxInt64)
						writeTimeout := time.Second * time.Duration(config.GetDurationBounds(fmt.Sprintf("services.%s.write_timeout", service), 10, 2, 60))
						idleTimeout := time.Second * time.Duration(config.GetDurationBounds(fmt.Sprintf("services.%s.idle_timeout", service), 60, 0, 300))
						source.SetReadBuffer(int(incomingSize))
						source.SetWriteBuffer(int(incomingSize))
						target.(*net.TCPConn).SetReadBuffer(int(outgoingSize))
						target.(*net.TCPConn).SetWriteBuffer(int(outgoingSize))
						session := &Session{
							id:      fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s%s", source.RemoteAddr(), target.RemoteAddr())))),
							service: service,
							source:  fmt.Sprintf("%s", source.RemoteAddr()),
							target:  fmt.Sprintf("%s", target.RemoteAddr()),
							started: time.Now(),
							active:  time.Now(),
							last:    time.Time{},
							closer:  make(chan bool, 1),
						}
						if logMinimumSize == 0 {
							session.loggued = true
							logger.Info(map[string]interface{}{"type": "splice", "id": session.id, "service": service, "source": session.source, "target": session.target})
						}
						if sessionMinimumSize == 0 {
							statistics <- session
						}
						go func() {
							data := make([]byte, incomingSize)
							for {
								read, err := source.Read(data)
								if read > 0 {
									session.sourceRead += int64(read)
									session.active = time.Now()
									target.SetWriteDeadline(time.Now().Add(writeTimeout))
									written, err := target.Write(data[0:read])
									if written > 0 {
										session.targetWritten += int64(written)
									}
									if err != nil {
										logger.Warn(map[string]interface{}{"type": "error", "id": session.id, "service": service, "source": session.source, "target": session.target, "error": "target write timeout"})
										break
									}
								}
								if err != nil {
									break
								}
							}
							source.Close()
							target.Close()
						}()
						data := make([]byte, outgoingSize)
						close := false
						for !close {
							target.SetReadDeadline(time.Now().Add(time.Second))
							read, err := target.Read(data)
							if read > 0 {
								session.targetRead += int64(read)
								session.active = time.Now()
								source.SetWriteDeadline(time.Now().Add(writeTimeout))
								written, err := source.Write(data[0:read])
								if written > 0 {
									session.sourceWritten += int64(written)
								}
								if err != nil {
									logger.Warn(map[string]interface{}{"type": "error", "id": session.id, "service": service, "source": session.source, "target": session.target, "error": "source write timeout"})
									break
								}
							}
							if err != nil {
								if err, ok := err.(net.Error); !ok || !err.Timeout() {
									break
								}
							}
							if !session.loggued && (session.targetWritten >= logMinimumSize || session.sourceWritten >= logMinimumSize) {
								session.loggued = true
								logger.Info(map[string]interface{}{"type": "splice", "id": session.id, "service": service, "source": session.source, "target": session.target})
							}
							if (session.targetWritten >= sessionMinimumSize || session.sourceWritten >= sessionMinimumSize) && time.Now().Sub(session.last) >= time.Second*2 {
								session.last = time.Now()
								statistics <- session
							}
							select {
							case close = <-session.closer:
							default:
							}
							if idleTimeout != 0 && time.Now().Sub(session.active) >= idleTimeout {
								logger.Warn(map[string]interface{}{"type": "error", "id": session.id, "service": service, "source": session.source, "target": session.target, "error": "idle timeout"})
								close = true
							}
						}
						source.Close()
						target.Close()
						if session.targetWritten >= logMinimumSize || session.sourceWritten >= logMinimumSize {
							duration := math.Max(float64(time.Now().Sub(session.started))/float64(time.Second), 0.001)
							logger.Info(map[string]interface{}{"type": "unsplice", "id": session.id, "service": service, "source": session.source, "target": session.target,
								"duration": math.Floor(duration*1000) / 1000, "bytes": [2]int64{session.targetWritten, session.sourceWritten},
								"throughput": [2]float64{math.Floor(float64(session.targetWritten*8)/(duration*1000)) / 1000,
									math.Floor(float64(session.sourceWritten*8)/(duration*1000)) / 1000}})
						}
						if session.targetWritten >= sessionMinimumSize || session.sourceWritten >= sessionMinimumSize {
							session.done = true
							session.last = time.Now()
							statistics <- session
						}
					} else {
						source.Close()
					}
				}()
			} else {
				source.Close()
			}
		}
	}
}

func monitorHandler(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Access-Control-Allow-Origin", "*")
	if request.URL.Path == "/sessions.json" {
		output := map[string]interface{}{
			"server": map[string]interface{}{
				"version": version,
				"uptime":  time.Now().Sub(start) / time.Second,
			},
		}
		services := map[string]interface{}{}
		for _, service := range config.GetPaths("services") {
			service = strings.TrimPrefix(service, "services.")
			s := map[string]interface{}{}
			sessionsLock.RLock()
			for id, session := range sessions {
				s[id] = map[string]interface{}{
					"started":  session.started.Unix(),
					"duration": time.Now().Sub(session.started) / time.Second,
					"source":   session.source,
					"target":   session.target,
					"bytes":    [2]int64{session.sourceRead, session.targetRead},
					"mean":     [2]float64{session.sourceMeanThroughput, session.targetMeanThroughput},
					"last":     [2]float64{session.sourceLastThroughput, session.targetLastThroughput},
					"done":     session.done,
				}
			}
			sessionsLock.RUnlock()
			services[service] = s
		}
		output["services"] = services
		response.Header().Set("Content-Type", "application/json")
		if json, err := json.Marshal(output); err == nil {
			response.Write(json)
		}
	} else if strings.Index(request.URL.Path, "/close/") == 0 {
		sessionsLock.RLock()
		for id, session := range sessions {
			if id == request.URL.Path[7:] && !session.done {
				session.done = true
				session.closer <- true
				logger.Warn(map[string]interface{}{"type": "close", "id": id, "service": session.service, "source": session.source, "target": session.target})
				break
			}
		}
		sessionsLock.RUnlock()
	} else {
		response.Header().Set("Content-Type", "text/html; charset=utf-8")
		response.Write(monitorContent)
	}
}

func baseHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Server", fmt.Sprintf("%s/%s", progname, version))
		if request.Method == "OPTIONS" {
			return
		}
		if request.Method != "HEAD" && request.Method != "GET" {
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		check := false
		if remote, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
			if remote := net.ParseIP(remote); remote != nil {
				for _, allow := range config.GetPaths("monitor.acl.allow") {
					check = true
					allow = config.GetString(allow, "")
					if strings.Index(allow, "/") < 0 {
						allow += "/32"
					}
					if _, network, err := net.ParseCIDR(allow); err == nil {
						if remote != nil && network.Contains(remote) {
							next.ServeHTTP(response, request)
							return
						}
					}
				}
			}
		}
		credentials := ""
		if username, password, ok := request.BasicAuth(); ok {
			credentials = fmt.Sprintf("%s:%s", username, password)
		}
		for _, auth := range config.GetPaths("monitor.acl.auth") {
			check = true
			if config.GetString(auth, "") == credentials {
				next.ServeHTTP(response, request)
				return
			}
		}
		if check {
			response.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", progname))
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(response, request)
	})
}

func main() {
	var err error

	rand.Seed(time.Now().UnixNano() + int64(os.Getpid()))
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <configuration file>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	if config, err = uconfig.New(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "configuration file syntax error: %s - aborting\n", err)
		os.Exit(2)
	}
	logger = ulog.New(config.GetString("server.log", "console()"))
	logger.Info(map[string]interface{}{"type": "start", "version": version, "config": os.Args[1], "services": len(config.GetPaths("services"))})
	start = time.Now()

	for _, service := range config.GetPaths("services") {
		for _, local := range config.GetPaths(fmt.Sprintf("%s.local", service)) {
			service = strings.TrimPrefix(service, "services.")
			local = config.GetString(local, "")
			if address, err := net.ResolveTCPAddr("tcp", strings.TrimLeft(local, "*")); err == nil {
				if listener, err := net.ListenTCP("tcp", address); err == nil {
					logger.Info(map[string]interface{}{"type": "service", "name": service, "listen": local})
					go serviceHandler(service, listener)
				} else {
					logger.Warn(map[string]interface{}{"type": "service", "name": service, "listen": local, "error": err})
				}
			} else {
				logger.Warn(map[string]interface{}{"type": "service", "name": service, "listen": local, "error": err})
			}
		}
	}

	http.Handle("/", baseHandler(http.HandlerFunc(monitorHandler)))
	if parts := strings.Split(config.GetStringMatch("monitor.listen", "_", "^(?:\\*|\\d+(?:\\.\\d+){3}|\\[[^\\]]+\\])(?::\\d+)?(?:(?:,[^,]+){2})?$"), ","); parts[0] != "_" {
		server := &http.Server{Addr: strings.TrimLeft(parts[0], "*")}
		if len(parts) > 1 {
			logger.Info(map[string]interface{}{"type": "monitor", "listen": parts[0], "cert": parts[1], "key": parts[2]})
			go server.ListenAndServeTLS(parts[1], parts[2])
		} else {
			logger.Info(map[string]interface{}{"type": "monitor", "listen": parts[0]})
			go server.ListenAndServe()
		}
	}

	statistics = make(chan *Session, 100)
	sessions = map[string]*Session{}
	cleaner := time.NewTicker(time.Second).C
	for {
		select {
		case session := <-statistics:
			sessionsLock.Lock()
			if sessions[session.id] == nil {
				sessions[session.id] = &Session{service: session.service, source: session.source, target: session.target, started: session.started, closer: session.closer}
			}
			sessionsLock.Unlock()
			duration := math.Max(float64(time.Now().Sub(session.started))/float64(time.Second), 0.001)
			session.sourceMeanThroughput = math.Floor(float64(session.targetWritten*8)/(duration*1000)) / 1000
			session.targetMeanThroughput = math.Floor(float64(session.sourceWritten*8)/(duration*1000)) / 1000
			if !session.last.IsZero() && !sessions[session.id].last.IsZero() {
				duration = math.Max(float64(session.last.Sub(sessions[session.id].last))/float64(time.Second), 0.001)
				session.sourceLastThroughput = math.Floor(float64((session.targetWritten-sessions[session.id].targetWritten)*8)/(duration*1000)) / 1000
				session.targetLastThroughput = math.Floor(float64((session.sourceWritten-sessions[session.id].sourceWritten)*8)/(duration*1000)) / 1000
			} else {
				session.sourceLastThroughput = session.sourceMeanThroughput
				session.targetLastThroughput = session.targetMeanThroughput
			}
			sessions[session.id].last = session.last
			sessions[session.id].done = session.done
			sessions[session.id].sourceRead = session.sourceRead
			sessions[session.id].targetWritten = session.targetWritten
			sessions[session.id].targetRead = session.targetRead
			sessions[session.id].sourceWritten = session.sourceWritten
			sessions[session.id].sourceMeanThroughput = session.sourceMeanThroughput
			sessions[session.id].targetMeanThroughput = session.targetMeanThroughput
			sessions[session.id].sourceLastThroughput = session.sourceLastThroughput
			sessions[session.id].targetLastThroughput = session.targetLastThroughput
		case <-cleaner:
			var ids []string
			sessionsLock.RLock()
			for id, session := range sessions {
				if time.Now().Sub(session.last) >= time.Second*3 {
					ids = append(ids, id)
				}
			}
			sessionsLock.RUnlock()
			sessionsLock.Lock()
			for _, id := range ids {
				delete(sessions, id)
			}
			sessionsLock.Unlock()
			if len(ids) > 0 {
				logger.Info(map[string]interface{}{"type": "clean", "sessions": len(ids)})
			}
		}
	}
}
