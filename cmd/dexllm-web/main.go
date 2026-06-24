// dexllm-web local launcher.
//
// Bundles every static asset of the dexllm-web demo (index.html, the wasm
// engine, worker, MP4 clips, dangerous-perm dataset) into a single executable.
// Double-click the .exe → a tiny in-process HTTP server binds to a random
// loopback port and the user's default browser opens the page. Closing the
// console window (or Ctrl+C) stops the server.
//
// We need a real HTTP origin because the engine uses a Web Worker + a wasm
// fetched by emscripten's locateFile callback; both fail under file:// in
// every major browser (workers refuse to load, wasm streaming compile
// rejects non-http origins).

package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// All siblings of the launcher source: the dexllm-web static bundle.
// The repo root sits one level above; use `..` paths so a single `go build`
// in cmd/dexllm-web picks up the artifacts the GitHub Pages site serves.
//
//go:embed static
var staticFS embed.FS

func main() {
	// Emscripten requires application/wasm; the Go default mime table doesn't
	// register it. The streaming compile path silently falls back to a
	// non-streaming decode without it — works, but slower. Force the right
	// type so the engine boots as fast as the hosted demo.
	_ = mime.AddExtensionType(".wasm", "application/wasm")
	_ = mime.AddExtensionType(".mjs", "text/javascript")

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("embedded fs: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", noCache(http.FileServer(http.FS(sub))))

	// Loopback-only, OS-assigned port. Loopback so a random scan of the LAN
	// can't see whoever opened a malware sample's strings. OS-assigned so a
	// second instance (or whatever else might be running on a fixed port)
	// can't collide.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)

	fmt.Println("┌──────────────────────────────────────────────────────────────")
	fmt.Println("│ dexllm-web — in-browser DEX / APK decompiler (local)")
	fmt.Println("│")
	fmt.Printf("│   Serving at  %s\n", url)
	fmt.Println("│   Stop with   Ctrl+C  (or close this window)")
	fmt.Println("└──────────────────────────────────────────────────────────────")

	// Open after a short delay so the server is definitely accepting by the
	// time the browser issues its first request.
	go func() {
		time.Sleep(150 * time.Millisecond)
		if err := openBrowser(url); err != nil {
			fmt.Printf("(could not auto-open browser: %v — paste the URL above)\n", err)
		}
	}()

	server := &http.Server{Handler: mux}
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}

// Strip cache headers so re-launches with an updated bundle never serve stale
// files from the user's browser cache. This is a local single-user server so
// there's no perf reason to negotiate validation; just always re-deliver.
func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		// Workers need the same-origin guarantees the page has — these
		// headers are no-ops for our content but make the COOP/COEP flags
		// explicit if a future build wants SharedArrayBuffer.
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		// The .wasm streaming-compile path checks the response MIME — Go's
		// content-type sniffing returns octet-stream for wasm magic since
		// the registered table is consulted by ext only, and the FileServer
		// reads ext at the time of serve. The mime.AddExtensionType call
		// above handles it; this is a safety belt for the few servers in
		// the chain that ignore the extension hint.
		if strings.HasSuffix(r.URL.Path, ".wasm") {
			w.Header().Set("Content-Type", "application/wasm")
		}
		h.ServeHTTP(w, r)
	})
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// cmd /c start "" <url>  — the empty title is required, else `start`
		// would treat the URL as the window title.
		cmd = exec.Command("cmd", "/c", "start", "", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
