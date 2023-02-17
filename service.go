package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/acl"
	"github.com/pyke369/golang-support/listener"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/uuid"
)

var (
	serviceBlacklist = map[string]*BLACKLIST{}
	serviceLock      sync.Mutex
)

type BLACKLIST struct {
	reason   string
	deadline time.Time
}

type LISTENER struct {
	handle *listener.TCPListener
	seen   time.Time
}

type METRICS struct {
	read, write int64
	mean, last  float64
}

type SESSION struct {
	id, name, opaque        string
	source, local, target   string
	smetrics, tmetrics      METRICS
	started, active, update time.Time
	secure, spliced         bool
	loggued, done           bool
	multi                   int
	abort                   chan bool
}

func serviceHandle(name string, certificate []string, listener net.Listener) {
	prefix, secure := PROGNAME+".service."+name+".", len(certificate) == 2

	for {
		source, err := listener.Accept()
		if err != nil {
			break
		}
		targets := Config.GetPaths(prefix + "target")
		if len(targets) == 0 {
			source.Close()
			continue
		}

		rscan := Config.GetString(prefix+"scan.1", "")
		ssize := int(Config.GetSizeBounds(prefix+"size.source", 0, 4<<10, 8<<20))
		tsize := int(Config.GetSizeBounds(prefix+"size.target", 0, 4<<10, 8<<20))
		bsize := Config.GetSizeBounds(prefix+"size.buffer", 128<<10, 4<<10, 8<<20)
		csize := Config.GetSizeBounds(prefix+"size.session", 16<<10, 0, math.MaxInt64)
		lsize := Config.GetSizeBounds(prefix+"size.log", 16<<10, 0, math.MaxInt64)
		osize := int(Config.GetSizeBounds(prefix+"size.opaque", 16<<10, 0, 64<<10))
		wtimeout := uconfig.Duration(Config.GetDurationBounds(prefix+"timeout.write", 10, 1, 30))
		itimeout := uconfig.Duration(Config.GetDurationBounds(prefix+"timeout.idle", 7, 0, 30))
		btimeout := Config.GetDurationBounds(prefix+"timeout.blacklist", 45, 10, 300)

		go func() {
			var (
				target net.Conn
				err    error
			)

			if ssize != 0 {
				source.(*net.TCPConn).SetReadBuffer(ssize)
				source.(*net.TCPConn).SetWriteBuffer(ssize)
			}
			if secure {
				if certificate, err := tls.LoadX509KeyPair(certificate[0], certificate[1]); err == nil {
					source.SetDeadline(time.Now().Add(wtimeout))
					sconn := tls.Server(source, &tls.Config{
						Certificates: []tls.Certificate{certificate},
						MinVersion:   tls.VersionTLS12,
						CipherSuites: []uint16{
							tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
							tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
							tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
							tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
							tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
							tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
						},
					})
					sconn.Handshake()
					if state := sconn.ConnectionState(); !state.HandshakeComplete {
						source.Close()
						return
					}
					source.SetDeadline(time.Time{})
					source = net.Conn(sconn)
				} else {
					source.Close()
					return
				}
			}

			ctimeout, index, remote := uconfig.Duration(Config.GetDurationBounds(prefix+"timeout.connect", 10, 1, 30)), 0, ""
			for index, remote = range targets {
				remote = Config.GetString(remote, "")
				parts := strings.SplitN(remote, "@", 2)
				if len(parts) > 1 && parts[0] == "tls" {
					remote = parts[1]
				}
				serviceLock.Lock()
				if blacklist := serviceBlacklist[remote]; blacklist != nil && time.Now().Before(blacklist.deadline) {
					Logger.Warn(map[string]any{
						"scope": "service", "event": "skip", "service": name, "remote": remote,
						"reason": blacklist.reason, "remaining": blacklist.deadline.Sub(time.Now()) / time.Second,
					})
					serviceLock.Unlock()
					if index >= len(targets)-1 {
						Logger.Error(map[string]any{
							"scope": "service", "event": "error", "service": name,
							"source": source.RemoteAddr().String(), "error": "no available target",
						})
						source.Close()
						return
					}
					continue
				}
				serviceLock.Unlock()
				start := time.Now()
				if target, err = net.DialTimeout("tcp", remote, time.Duration(math.Max(float64(time.Second), float64(ctimeout)/float64(len(targets))))); err != nil {
					Logger.Warn(map[string]any{
						"scope": "service", "event": "blacklist", "service": name,
						"remote": remote, "reason": "connect", "duration": int(btimeout),
					})
					serviceLock.Lock()
					serviceBlacklist[remote] = &BLACKLIST{reason: "connection error", deadline: time.Now().Add(uconfig.Duration(btimeout))}
					serviceLock.Unlock()
					ctimeout -= time.Since(start)
					if ctimeout <= 0 || index >= len(targets)-1 {
						Logger.Error(map[string]any{
							"scope": "service", "event": "error", "service": name,
							"source": source.RemoteAddr().String(), "target": remote, "error": fmt.Sprintf("%v", err),
						})
						source.Close()
						return
					}
					Logger.Warn(map[string]any{
						"scope": "service", "event": "retry", "service": name,
						"source": source.RemoteAddr().String(), "target": remote, "error": fmt.Sprintf("%v", err),
					})
					continue
				}
				if tsize != 0 {
					target.(*net.TCPConn).SetReadBuffer(tsize)
					target.(*net.TCPConn).SetWriteBuffer(tsize)
				}
				if len(parts) > 1 && parts[0] == "tls" {
					target.SetDeadline(time.Now().Add(wtimeout))
					sconn := tls.Client(target, &tls.Config{InsecureSkipVerify: true})
					sconn.Handshake()
					if state := sconn.ConnectionState(); !state.HandshakeComplete {
						source.Close()
						return
					}
					target.SetDeadline(time.Time{})
					target = net.Conn(sconn)
				}
				break
			}

			session := &SESSION{
				id:      uuid.UUID(),
				name:    name,
				source:  source.RemoteAddr().String(),
				local:   source.LocalAddr().String(),
				target:  target.RemoteAddr().String(),
				started: time.Now(),
				active:  time.Now(),
				secure:  secure,
				multi:   1,
				abort:   make(chan bool, 1),
			}
			session.spliced = len(Config.GetPaths(PROGNAME+".monitor.spliced")) > 0 && acl.CIDRConfig(session.source, Config, PROGNAME+".monitor.spliced")
			if lsize == 0 {
				Logger.Info(map[string]any{
					"scope": "service", "event": "splice", "id": session.id, "service": name,
					"source": session.source, "target": session.target,
				})
				session.loggued = true
			}
			if csize == 0 {
				MonitorUpdate <- session
			}

			go func() {
				data, opaque, scan := make([]byte, bsize), make([]byte, 0, osize), rcache.Get(Config.GetString(prefix+"scan.0", "["))
				for {
					read, err := source.Read(data)
					if read > 0 {
						if scan != nil && session.opaque == "" && len(opaque) < osize {
							opaque = append(opaque, data[:int(math.Min(float64(read), float64(osize-len(opaque))))]...)
							if scan.Match(opaque) {
								parts := scan.FindSubmatch(opaque)
								if rscan != "" {
									for index := 1; index < len(parts); index++ {
										rscan = strings.ReplaceAll(rscan, fmt.Sprintf("${%d}", index), string(parts[index]))
									}
									session.opaque = rscan
								} else {
									session.opaque = string(bytes.Join(parts[1:], []byte{}))
								}
							}
						}
						session.smetrics.read += int64(read)
						session.active = time.Now()
						target.SetWriteDeadline(time.Now().Add(wtimeout))
						write, err := target.Write(data[0:read])
						if write > 0 {
							session.tmetrics.write += int64(write)
						}
						if err != nil {
							Logger.Warn(map[string]any{
								"scope": "service", "event": "error", "id": session.id, "service": name,
								"source": session.source, "target": session.target, "error": fmt.Sprintf("%v", err),
							})
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

			data, opaque, scan, close := make([]byte, bsize), make([]byte, 0, osize), rcache.Get(Config.GetString(prefix+"scan.0", "[")), false
			for !close {
				target.SetReadDeadline(time.Now().Add(time.Second))
				read, err := target.Read(data)
				if read > 0 {
					if scan != nil && session.opaque == "" && len(opaque) < osize {
						opaque = append(opaque, data[:int(math.Min(float64(read), float64(osize-len(opaque))))]...)
						if scan.Match(opaque) {
							parts := scan.FindSubmatch(opaque)
							if rscan != "" {
								for index := 1; index < len(parts); index++ {
									rscan = strings.ReplaceAll(rscan, fmt.Sprintf("${%d}", index), string(parts[index]))
								}
								session.opaque = rscan
							} else {
								session.opaque = string(bytes.Join(parts[1:], []byte{}))
							}
						}
					}
					session.tmetrics.read += int64(read)
					session.active = time.Now()
					source.SetWriteDeadline(time.Now().Add(wtimeout))
					write, err := source.Write(data[0:read])
					if write > 0 {
						session.smetrics.write += int64(write)
					}
					if err != nil {
						Logger.Warn(map[string]any{
							"scope": "service", "event": "error", "id": session.id, "service": name,
							"source": session.source, "target": session.target, "error": fmt.Sprintf("%v", err)})
						break
					}
				}
				if err != nil {
					if err, ok := err.(net.Error); !ok || !err.Timeout() {
						if session.tmetrics.write > 0 && session.tmetrics.read == 0 {
							Logger.Warn(map[string]any{
								"scope": "service", "event": "blacklist", "service": name,
								"remote": remote, "reason": "connection error", "duration": int(btimeout),
							})
							serviceLock.Lock()
							serviceBlacklist[remote] = &BLACKLIST{reason: "connection timeout", deadline: time.Now().Add(uconfig.Duration(btimeout))}
							serviceLock.Unlock()
						}
						break
					}
				}
				if !session.loggued && (session.tmetrics.write >= lsize || session.smetrics.write >= lsize) {
					Logger.Info(map[string]any{
						"scope": "service", "event": "splice", "id": session.id, "service": name,
						"source": session.source, "target": session.target,
					})
					session.loggued = true
				}
				if (session.tmetrics.write >= csize || session.smetrics.write >= csize) && time.Since(session.update) >= time.Second*2 {
					session.update = time.Now()
					MonitorUpdate <- session
				}
				select {
				case close = <-session.abort:
				default:
				}
				if itimeout != 0 && time.Since(session.active) >= itimeout {
					Logger.Warn(map[string]any{
						"scope": "service", "event": "error", "id": session.id, "service": name,
						"source": session.source, "target": session.target, "error": "idle timeout",
					})
					close = true
					Logger.Warn(map[string]any{
						"scope": "service", "event": "blacklist", "service": name,
						"remote": remote, "reason": "traffic timeout", "duration": int(btimeout),
					})
					serviceLock.Lock()
					serviceBlacklist[remote] = &BLACKLIST{reason: "traffic timeout", deadline: time.Now().Add(uconfig.Duration(btimeout))}
					serviceLock.Unlock()
				}
			}
			source.Close()
			target.Close()

			if session.tmetrics.write >= lsize || session.smetrics.write >= lsize {
				duration := math.Max(float64(time.Since(session.started))/float64(time.Second), 0.001)
				Logger.Info(map[string]any{
					"scope": "service", "event": "unsplice", "id": session.id, "service": name,
					"source": session.source, "target": session.target,
					"duration": math.Floor(duration*1000) / 1000, "bytes": [2]int64{session.tmetrics.write, session.smetrics.write},
					"throughput": [2]float64{math.Floor(float64(session.tmetrics.write*8)/(duration*1000)) / 1000,
						math.Floor(float64(session.smetrics.write*8)/(duration*1000)) / 1000},
				})
			}
			if session.tmetrics.write >= csize || session.smetrics.write >= csize {
				session.done = true
				session.update = time.Now()
				MonitorUpdate <- session
			}
		}()
	}
}

func ServiceRun() {
	var listeners = map[string]*LISTENER{}

	for {
		for _, name := range Config.GetPaths(PROGNAME + ".service") {
			for _, listen := range Config.GetPaths(name + ".listen") {
				if Unbind {
					continue
				}
				name = strings.TrimPrefix(name, PROGNAME+".service.")
				if parts := strings.Split(Config.GetStringMatch(listen, "_", `^.*?(:\d+)?((,[^,]+){2})?$`), ","); parts[0] != "_" {
					key := name + "@@" + strings.Join(parts, "@@")
					if listeners[key] == nil {
						listeners[key] = &LISTENER{seen: time.Now()}
						go func(name, key string, parts []string) {
						close:
							for {
								if handle, err := listener.NewTCPListener("tcp", strings.TrimLeft(parts[0], "*"), true, 0, 0, nil); err == nil {
									listeners[key].handle = handle
									if len(parts) > 1 {
										Logger.Info(map[string]any{
											"scope": "service", "event": "listen", "service": name, "listen": parts[0],
											"certificate": strings.Join(parts[1:], ","),
										})
									} else {
										Logger.Info(map[string]any{
											"scope": "service", "event": "listen", "service": name, "listen": parts[0],
										})
									}
									serviceHandle(name, parts[1:], handle)
									break close
								}
								time.Sleep(time.Second)
							}
						}(name, key, parts)
					} else {
						listeners[key].seen = time.Now()
					}
				}
			}
		}

		time.Sleep(time.Second)

		for key, listener := range listeners {
			if time.Since(listener.seen) >= 5*time.Second || Unbind {
				if listener.handle != nil {
					listener.handle.Close()
					listener.handle = nil
				}
				delete(listeners, key)
				parts := strings.Split(key, "@@")
				Logger.Info(map[string]any{
					"scope": "service", "event": "close", "service": parts[0], "listen": parts[1],
				})
			}
		}
	}
}
