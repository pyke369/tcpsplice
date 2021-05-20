package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/pyke369/golang-support/listener"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/uuid"
)

type LISTENER struct {
	handle   *listener.TCPListener
	seen     time.Time
	shutdown bool
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

func service_handle(name string, certificate []string, listener net.Listener) {
	prefix, secure := progname+".service."+name+".", len(certificate) == 2

	for {
		source, err := listener.Accept()
		if err != nil {
			break
		}
		targets := config.GetPaths(prefix + "target")
		if len(targets) == 0 {
			source.Close()
			continue
		}

		rscan := config.GetString(prefix+"scan.1", "")
		ssize := config.GetSizeBounds(prefix+"size.source", 128<<10, 4<<10, 512<<10)
		tsize := config.GetSizeBounds(prefix+"size.target", 128<<10, 4<<10, 512<<10)
		csize := config.GetSizeBounds(prefix+"size.session", 16<<10, 0, math.MaxInt64)
		lsize := config.GetSizeBounds(prefix+"size.log", 16<<10, 0, math.MaxInt64)
		osize := int(config.GetSizeBounds(prefix+"size.opaque", 16<<10, 0, 64<<10))
		wtimeout := uconfig.Duration(config.GetDurationBounds(prefix+"timeout.write", 10, 1, 60))
		itimeout := uconfig.Duration(config.GetDurationBounds(prefix+"timeout.idle", 20, 0, 300))

		go func() {
			var (
				target net.Conn
				err    error
			)

			source.(*net.TCPConn).SetReadBuffer(int(ssize))
			source.(*net.TCPConn).SetWriteBuffer(int(ssize))
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

			ctimeout := uconfig.Duration(config.GetDurationBounds(prefix+"timeout.connect", 10, 1, 60))
			for {
				remote := config.GetString(targets[rand.Int31n(int32(len(targets)))], "")
				parts := strings.SplitN(remote, "@", 2)
				if len(parts) > 1 && parts[0] == "tls" {
					remote = parts[1]
				}
				start := time.Now()
				if target, err = net.DialTimeout("tcp", remote, ctimeout); err != nil {
					ctimeout -= time.Now().Sub(start) + time.Second
					if ctimeout < 2*time.Second {
						logger.Warn(map[string]interface{}{"scope": "service", "event": "error", "name": name, "secure": secure,
							"source": source.RemoteAddr().String(), "local": source.LocalAddr().String(), "target": remote, "error": fmt.Sprintf("%v", err)})
						source.Close()
						return
					}
					logger.Warn(map[string]interface{}{"scope": "service", "event": "retry", "name": name, "secure": secure,
						"source": source.RemoteAddr().String(), "local": source.LocalAddr().String(), "target": remote, "error": fmt.Sprintf("%v", err)})
					time.Sleep(time.Second)
					continue
				}
				target.(*net.TCPConn).SetReadBuffer(int(tsize))
				target.(*net.TCPConn).SetWriteBuffer(int(tsize))
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
			if remote, _, err := net.SplitHostPort(session.source); err == nil {
				if remote := net.ParseIP(remote); remote != nil {
					for _, path := range config.GetPaths(progname + ".monitor.spliced") {
						if _, network, err := net.ParseCIDR(config.GetString(path, "")); err == nil && network.Contains(remote) {
							session.spliced = true
							break
						}
					}
				}
			}
			if lsize == 0 {
				logger.Info(map[string]interface{}{"scope": "service", "event": "splice", "id": session.id, "name": name, "secure": secure,
					"source": session.source, "local": session.local, "target": session.target})
				session.loggued = true
			}
			if csize == 0 {
				update <- session
			}

			go func() {
				data, opaque, scan := make([]byte, ssize), make([]byte, 0, osize), rcache.Get(config.GetString(prefix+"scan.0", "["))
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
							logger.Warn(map[string]interface{}{"scope": "service", "event": "error", "id": session.id, "name": name, "secure": secure,
								"source": session.source, "local": session.local, "target": session.target, "error": fmt.Sprintf("%v", err)})
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

			data, opaque, scan, close := make([]byte, tsize), make([]byte, 0, osize), rcache.Get(config.GetString(prefix+"scan.0", "[")), false
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
						logger.Warn(map[string]interface{}{"scope": "service", "event": "error", "id": session.id, "name": name, "secure": secure,
							"source": session.source, "local": session.local, "target": session.target, "error": fmt.Sprintf("%v", err)})
						break
					}
				}
				if err != nil {
					if err, ok := err.(net.Error); !ok || !err.Timeout() {
						break
					}
				}
				if !session.loggued && (session.tmetrics.write >= lsize || session.smetrics.write >= lsize) {
					logger.Info(map[string]interface{}{"scope": "service", "event": "splice", "id": session.id, "name": name, "secure": secure,
						"source": session.source, "local": session.local, "target": session.target})
					session.loggued = true
				}
				if (session.tmetrics.write >= csize || session.smetrics.write >= csize) && time.Now().Sub(session.update) >= time.Second*2 {
					session.update = time.Now()
					update <- session
				}
				select {
				case close = <-session.abort:
				default:
				}
				if itimeout != 0 && time.Now().Sub(session.active) >= itimeout {
					logger.Warn(map[string]interface{}{"scope": "service", "event": "error", "id": session.id, "name": name, "secure": secure,
						"source": session.source, "local": session.local, "target": session.target, "error": "idle timeout"})
					close = true
				}
			}
			source.Close()
			target.Close()

			if session.tmetrics.write >= lsize || session.smetrics.write >= lsize {
				duration := math.Max(float64(time.Now().Sub(session.started))/float64(time.Second), 0.001)
				logger.Info(map[string]interface{}{"scope": "service", "event": "unsplice", "id": session.id, "name": name,
					"source": session.source, "local": session.local, "target": session.target,
					"duration": math.Floor(duration*1000) / 1000, "bytes": [2]int64{session.tmetrics.write, session.smetrics.write},
					"throughput": [2]float64{math.Floor(float64(session.tmetrics.write*8)/(duration*1000)) / 1000,
						math.Floor(float64(session.smetrics.write*8)/(duration*1000)) / 1000}})
			}
			if session.tmetrics.write >= csize || session.smetrics.write >= csize {
				session.done = true
				session.update = time.Now()
				update <- session
			}
		}()
	}
}

func service_run() {
	var listeners = map[string]*LISTENER{}

	for {
		for _, name := range config.GetPaths(progname + ".service") {
			for _, listen := range config.GetPaths(name + ".listen") {
				if unbind {
					continue
				}
				name = strings.TrimPrefix(name, progname+".service.")
				if parts := strings.Split(config.GetStringMatch(listen, "_", `^.*?(:\d+)?((,[^,]+){2})?$`), ","); parts[0] != "_" {
					key := name + "@@" + strings.Join(parts, "@@")
					if listeners[key] == nil {
						listeners[key] = &LISTENER{seen: time.Now()}
						go func(name, key string, parts []string) {
						close:
							for {
								if handle, err := listener.NewTCPListener("tcp", strings.TrimLeft(parts[0], "*"), true, 0, 0, nil); err == nil {
									listeners[key].handle = handle
									if len(parts) > 1 {
										logger.Info(map[string]interface{}{"scope": "service", "event": "listen", "name": name, "listen": parts[0],
											"certificate": strings.Join(parts[1:], ",")})
									} else {
										logger.Info(map[string]interface{}{"scope": "service", "event": "listen", "name": name, "listen": parts[0]})
									}
									service_handle(name, parts[1:], handle)
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
			if time.Now().Sub(listener.seen) >= 5*time.Second || unbind {
				if listener.handle != nil {
					listener.handle.Close()
					listener.handle = nil
				}
				delete(listeners, key)
				parts := strings.Split(key, "@@")
				logger.Info(map[string]interface{}{"scope": "service", "event": "close", "name": parts[0], "listen": parts[1]})
			}
		}
	}
}
