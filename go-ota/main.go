package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

// --- Configuration & Globals ---

var (
	storageDir   = "storage"
	versionsFile = filepath.Join(storageDir, "versions.json")
	androidDir   = filepath.Join(storageDir, "android")
	iosDir       = filepath.Join(storageDir, "ios")

	// Env Vars
	jwtSecret           []byte
	downloadTokenExpiry time.Duration
	maxUploadSize       int64
	hostURL             string
	adminUser           string
	adminPass           string
)

// Versions Struct
type Versions struct {
	Android *string `json:"android"`
	IOS     *string `json:"ios"`
}

// Rate Limiter
type IPLimiter struct {
	ips map[string]*rate.Limiter
	mu  sync.Mutex
	r   rate.Limit
	b   int
}

func NewIPLimiter(r rate.Limit, b int) *IPLimiter {
	return &IPLimiter{
		ips: make(map[string]*rate.Limiter),
		r:   r,
		b:   b,
	}
}

func (i *IPLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(i.r, i.b)
		i.ips[ip] = limiter
	}

	return limiter
}

var limiter = NewIPLimiter(100.0/60.0, 100) // 100 reqs per minute

// --- Helpers ---

func loadEnv() {
	file, err := os.Open(".env")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				os.Setenv(parts[0], parts[1])
			}
		}
	}

	adminUser = getEnv("ADMIN_USER", "admin")
	adminPass = getEnv("ADMIN_PASS", "secret123")
	hostURL = getEnv("HOST_URL", "http://localhost:8080")
	maxMB, _ := strconv.Atoi(getEnv("MAX_UPLOAD_SIZE_MB", "50"))
	maxUploadSize = int64(maxMB) << 20
	jwtSecret = []byte(getEnv("JWT_SECRET", "secret"))

	durStr := getEnv("DOWNLOAD_TOKEN_EXPIRY", "15m")
	dur, err := time.ParseDuration(durStr)
	if err != nil {
		dur = 15 * time.Minute
	}
	downloadTokenExpiry = dur
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getVersions() (Versions, error) {
	var v Versions
	data, err := os.ReadFile(versionsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return Versions{Android: nil, IOS: nil}, nil
		}
		return v, err
	}
	err = json.Unmarshal(data, &v)
	return v, err
}

func saveVersion(platform, version string) error {
	v, err := getVersions()
	if err != nil {
		return err
	}
	if platform == "android" {
		v.Android = &version
	} else if platform == "ios" {
		v.IOS = &version
	}

	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(versionsFile, data, 0644)
}

func getSafePath(platform, version string) string {
	// Sanitize version: allow only alphanumeric, dot, dash, underscore
	reg := regexp.MustCompile(`[^a-zA-Z0-9.-_]`) // Note: '-' needs escaping in character class
	safeVersion := reg.ReplaceAllString(version, "")

	dir := androidDir
	if platform == "ios" {
		dir = iosDir
	}
	return filepath.Join(dir, safeVersion+".zip")
}

// --- JWT Helpers ---

type CustomClaims struct {
	User     string `json:"user,omitempty"`
	Version  string `json:"version,omitempty"`
	Platform string `json:"platform,omitempty"`
	Allowed  bool   `json:"allowed,omitempty"`
	jwt.RegisteredClaims
}

func signToken(claims CustomClaims, expiry time.Duration) (string, error) {
	claims.RegisteredClaims = jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func verifyToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// --- Middleware ---

func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Helmet-like headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// CSP allowing inline scripts/styles/forms
		csp := []string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline'",
			"style-src 'self' 'unsafe-inline'",
			"connect-src 'self'",
			"img-src 'self' data:",
			"form-action 'self'",
			"frame-ancestors 'self'",
			"base-uri 'self'",
			"object-src 'none'",
		}
		w.Header().Set("Content-Security-Policy", strings.Join(csp, "; "))

		next(w, r)
	}
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := strings.Split(r.RemoteAddr, ":")[0]
		limiter := limiter.GetLimiter(ip)
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Prevent caching for protected routes
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		cookie, err := r.Cookie("auth")
		if err != nil {
			log.Printf("[Auth] No cookie: %v", err)
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := verifyToken(cookie.Value)
		if err != nil || claims.User == "" {
			log.Printf("[Auth] Invalid token: %v", err)
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		log.Printf("[Auth] Authorized user: %s", claims.User)
		next(w, r)
	}
}

// --- Handlers ---

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		html := `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login</title>
            <style>
                body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f4f4f4; }
                form { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); width: 300px; }
                .form-group { margin-bottom: 1rem; }
                label { display: block; margin-bottom: .5rem; font-weight: bold; }
                input { width: 100%; padding: 0.5rem; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
                button { width: 100%; padding: 0.75rem; background: #333; color: white; border: none; border-radius: 4px; cursor: pointer; }
                button:hover { background: #000; }
                .error { color: red; margin-bottom: 1rem; font-size: 0.9rem; display: none; }
            </style>
        </head>
        <body>
            <form onsubmit="login(event)" method="POST">
                <div id="err" class="error">Invalid credentials</div>
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit">Login</button>
            </form>
            <script>
                async function login(e) {
                    e.preventDefault();
                    const formData = new FormData(e.target);
                    // Convert FormData to JSON
                    const data = {};
                    formData.forEach((value, key) => data[key] = value);

                    const res = await fetch('/login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(data)
                    });
                    if (res.ok) {
                        window.location.href = '/';
                    } else {
                        document.getElementById('err').style.display = 'block';
                    }
                }
            </script>
        </body>
        </html>
		`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
		return
	}

	if r.Method == "POST" {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		// Handle both JSON and Form (fallback)
		ctype := r.Header.Get("Content-Type")
		if strings.Contains(ctype, "application/json") {
			json.NewDecoder(r.Body).Decode(&creds)
		} else {
			r.ParseForm()
			creds.Username = r.FormValue("username")
			creds.Password = r.FormValue("password")
		}

		if creds.Username == adminUser && creds.Password == adminPass {
			token, err := signToken(CustomClaims{User: creds.Username}, 3*time.Minute)
			if err != nil {
				http.Error(w, "Internal Error", http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     "auth",
				Value:    token,
				Expires:  time.Now().Add(3 * time.Minute),
				HttpOnly: true,
				Secure:   r.TLS != nil, // Approximation for HTTPS
				SameSite: http.SameSiteStrictMode,
				Path:     "/",
			})
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true}`)) // Use raw string literal for JSON
			return
		}
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}

func handleAdminUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	v, _ := getVersions()
	vAndroid := "None"
	if v.Android != nil {
		vAndroid = *v.Android
	}
	vIOS := "None"
	if v.IOS != nil {
		vIOS = *v.IOS
	}

	html := fmt.Sprintf(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OTA Manager</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 600px; margin: 2rem auto; padding: 0 1rem; color: #333; }
            .card { border: 1px solid #ddd; border-radius: 8px; padding: 2rem; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
            h1 { margin-top: 0; }
            .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem; }
            .stat { background: #e9ecef; padding: 1rem; border-radius: 4px; text-align: center; }
            .stat h3 { margin: 0 0 0.5rem 0; font-size: 0.9rem; text-transform: uppercase; color: #666; }
            .stat .val { font-size: 1.2rem; font-weight: bold; }
            
            .form-group { margin-bottom: 1rem; }
            label { display: block; margin-bottom: .5rem; font-weight: 600; }
            input[type="text"], select { width: 100%; padding: 0.5rem; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
            input[type="file"] { width: 100%; }
            button { background: #007bff; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 4px; cursor: pointer; font-size: 1rem; width: 100%; }
            button:hover { background: #0056b3; }
            
            .alert { padding: 1rem; margin-top: 1rem; border-radius: 4px; }
            .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>OTA Manager</h1>
            
            <div class="grid">
                <div class="stat">
                    <h3>Android Version</h3>
                    <div class="val">%s</div>
                </div>
                <div class="stat">
                    <h3>iOS Version</h3>
                    <div class="val">%s</div>
                </div>
            </div>

            <div id="status"></div>

            <form id="uploadForm" onsubmit="upload(event)">
                <div class="form-group">
                    <label for="platform">Platform</label>
                    <select id="platform" name="platform" required>
                        <option value="android">Android</option>
                        <option value="ios">iOS</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="version">New Version</label>
                    <input type="text" id="version" name="version" required placeholder="e.g. 1.0.1">
                </div>
                
                <div class="form-group">
                    <label for="bundle">Bundle File (.zip only)</label>
                    <input type="file" id="bundle" name="bundle" accept=".zip,application/zip" required>
                    <small>Max size: %dMB</small>
                </div>

                <button type="submit">Upload & Publish</button>
            </form>
        </div>

        <script>
            // Auto logout after 3 minutes (180 seconds)
            setTimeout(() => {
                window.location.reload(); 
            }, 3 * 60 * 1000);

            async function upload(e) {
                e.preventDefault();
                const status = document.getElementById('status');
                status.innerHTML = '<div class="alert" style="background:#e2e3e5;color:#383d41">Uploading... please wait.</div>';
                
                const formData = new FormData(e.target);
                
                try {
                    const res = await fetch('/upload', {
                        method: 'POST',
                        body: formData
                    });
                    
                    if (res.ok) {
                        status.innerHTML = '<div class="alert success">Success! Version updated. Refreshing...</div>';
                        e.target.reset();
                        setTimeout(() => window.location.reload(), 1500);
                    } else {
                        const txt = await res.text();
                        status.innerHTML = '<div class="alert error">Error: ' + txt + '</div>';
                    }
                } catch (err) {
                    status.innerHTML = '<div class="alert error">Network Error</div>';
                }
            }
        </script>
    </body>
    </html>
	`, vAndroid, vIOS, maxUploadSize>>20)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	version := r.FormValue("version")
	platform := r.FormValue("platform")
	if version == "" || platform == "" {
		http.Error(w, "Missing version or platform", http.StatusBadRequest)
		return
	}

	if platform != "android" && platform != "ios" {
		http.Error(w, "Invalid platform", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("bundle")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if !strings.HasSuffix(strings.ToLower(header.Filename), ".zip") {
		http.Error(w, "File must be a .zip", http.StatusBadRequest)
		return
	}

	savePath := getSafePath(platform, version)

	dst, err := os.Create(savePath)
	if err != nil {
		log.Printf("Save error: %v", err)
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Error writing file", http.StatusInternalServerError)
		return
	}

	if err := saveVersion(platform, version); err != nil {
		http.Error(w, "Error updating version", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Upload successful"))
}

func handleLatest(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	// /api/latest/{platform} -> parts: ["", "api", "latest", "platform"]
	if len(parts) < 4 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	platform := strings.ToLower(parts[3])
	if platform != "android" && platform != "ios" {
		http.Error(w, "Invalid platform", http.StatusBadRequest)
		return
	}

	v, _ := getVersions()
	var version *string
	if platform == "android" {
		version = v.Android
	} else {
		version = v.IOS
	}

	if version == nil {
		json.NewEncoder(w).Encode(map[string]any{"version": nil, "message": "No version published"})
		return
	}

	// Check file existence
	filePath := getSafePath(platform, *version)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		json.NewEncoder(w).Encode(map[string]any{"version": nil, "message": "File not found"})
		return
	}

	token, err := signToken(CustomClaims{
		Version:  *version,
		Platform: platform,
		Allowed:  true,
	}, downloadTokenExpiry)

	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"version_url":  fmt.Sprintf("%s/api/version/%s", hostURL, token),
		"download_url": fmt.Sprintf("%s/api/download/%s", hostURL, token),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}
	token := parts[3]

	claims, err := verifyToken(token)
	if err != nil || !claims.Allowed {
		http.Error(w, "Invalid or expired link", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(claims.Version))
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}
	token := parts[3]

	claims, err := verifyToken(token)
	if err != nil || !claims.Allowed {
		http.Error(w, "Invalid or expired link", http.StatusForbidden)
		return
	}

	filePath := getSafePath(claims.Platform, claims.Version)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Sanitize again for header
	reg := regexp.MustCompile(`[^a-zA-Z0-9.-_]`) // Note: '-' needs escaping in character class
	safeVersion := reg.ReplaceAllString(claims.Version, "")
	filename := fmt.Sprintf("%s-%s.zip", claims.Platform, safeVersion)

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	http.ServeFile(w, r, filePath)
}

func main() {
	loadEnv()

	// Ensure Dirs
	os.MkdirAll(androidDir, 0755)
	os.MkdirAll(iosDir, 0755)

	mux := http.NewServeMux()

	// Public API (Rate Limited + Security Headers)
	mux.HandleFunc("/api/latest/", securityHeaders(rateLimitMiddleware(handleLatest)))
	mux.HandleFunc("/api/version/", securityHeaders(rateLimitMiddleware(handleVersion)))
	mux.HandleFunc("/api/download/", securityHeaders(rateLimitMiddleware(handleDownload)))

	// Auth & Admin
	mux.HandleFunc("/login", securityHeaders(rateLimitMiddleware(handleLogin)))
	mux.HandleFunc("/", securityHeaders(authMiddleware(handleAdminUI)))
	mux.HandleFunc("/upload", securityHeaders(authMiddleware(handleUpload)))

	fmt.Printf("Go OTA Server running on port %s\n", strings.TrimPrefix(hostURL, "http://localhost:"))
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), mux))
}
