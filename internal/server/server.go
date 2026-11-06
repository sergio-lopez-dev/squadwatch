// Package server serves the local dashboard.
//
// It only listens on loopback, only answers requests whose Host header is
// localhost (so a malicious web page cannot reach it through DNS
// rebinding), and only serves already-redacted data.
package server

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sergio-lopez-dev/squadwatch/internal/diff"
	"github.com/sergio-lopez-dev/squadwatch/internal/i18n"
	"github.com/sergio-lopez-dev/squadwatch/internal/model"
	"github.com/sergio-lopez-dev/squadwatch/internal/store"
)

//go:embed web
var webFS embed.FS

// Serve runs the dashboard until the process stops.
func Serve(addr string, lang i18n.Lang, scan func(i18n.Lang) *model.Scan) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New(lang.T("por seguridad el dashboard solo escucha en localhost (127.0.0.1, ::1)"))
	}

	type entry struct {
		scan *model.Scan
		at   time.Time
	}
	var (
		mu    sync.Mutex
		cache = map[i18n.Lang]entry{}
	)
	current := func(l i18n.Lang, refresh bool) *model.Scan {
		mu.Lock()
		defer mu.Unlock()
		c, ok := cache[l]
		if !ok || refresh || time.Since(c.at) > 15*time.Second {
			c = entry{scan(l), time.Now()}
			cache[l] = c
		}
		return c.scan
	}
	langOf := func(r *http.Request) i18n.Lang {
		if l, ok := i18n.Parse(r.URL.Query().Get("lang")); ok {
			return l
		}
		return lang
	}

	sub, _ := fs.Sub(webFS, "web")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(sub))
	mux.HandleFunc("GET /api/scan", func(w http.ResponseWriter, r *http.Request) {
		s := current(langOf(r), r.URL.Query().Get("refresh") == "1")
		if r.URL.Query().Get("refresh") == "1" {
			_, _ = store.Save(s)
		}
		writeJSON(w, s)
	})
	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		h := store.History()
		if h == nil {
			h = []store.Point{}
		}
		writeJSON(w, h)
	})
	mux.HandleFunc("GET /api/diff", func(w http.ResponseWriter, r *http.Request) {
		files, _ := store.List()
		if len(files) < 2 {
			writeJSON(w, map[string]any{"changes": []diff.Change{}, "from": nil, "to": nil})
			return
		}
		old, err1 := store.Load(files[len(files)-2])
		cur, err2 := store.Load(files[len(files)-1])
		if err1 != nil || err2 != nil {
			http.Error(w, lang.T("no se pudieron leer los escaneos guardados"), http.StatusInternalServerError)
			return
		}
		ch := diff.Compare(old, cur, langOf(r))
		if ch == nil {
			ch = []diff.Change{}
		}
		writeJSON(w, map[string]any{"changes": ch, "from": old.Time, "to": cur.Time})
	})

	allowed := map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true, "[::1]:" + port: true}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed[r.Host] {
			http.Error(w, lang.T("host no permitido"), http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		h.Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})

	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	fmt.Print(lang.T("Squadwatch en http://%s · solo accesible desde este equipo · Ctrl+C para salir\n", addr))
	return srv.ListenAndServe()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
