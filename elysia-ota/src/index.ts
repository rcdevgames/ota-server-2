import { Elysia, t, redirect } from 'elysia';
import { html } from '@elysiajs/html';
import { jwt } from '@elysiajs/jwt';
import { rateLimit } from 'elysia-rate-limit';
import { helmet } from 'elysia-helmet';
import { mkdir } from 'node:fs/promises';
import { join, normalize, basename } from 'node:path';

// Storage Paths
const STORAGE_DIR = join(process.cwd(), 'storage');
const ANDROID_DIR = join(STORAGE_DIR, 'android');
const IOS_DIR = join(STORAGE_DIR, 'ios');
const VERSIONS_FILE = join(STORAGE_DIR, 'versions.json');

// Ensure directories exist
await mkdir(ANDROID_DIR, { recursive: true });
await mkdir(IOS_DIR, { recursive: true });

// Env Vars
const USER = Bun.env.ADMIN_USER || 'admin';
const PASS = Bun.env.ADMIN_PASS || 'secret';
const HOST_URL = Bun.env.HOST_URL || 'http://localhost:3000';
const MAX_SIZE_MB = parseInt(Bun.env.MAX_UPLOAD_SIZE_MB || '50');
const JWT_SECRET = Bun.env.JWT_SECRET || 'secret';
const TOKEN_EXPIRY = Bun.env.DOWNLOAD_TOKEN_EXPIRY || '15m';

// Helper: Get Versions
async function getVersions() {
    const file = Bun.file(VERSIONS_FILE);
    if (await file.exists()) {
        try {
            return await file.json();
        } catch { return { android: null, ios: null }; }
    }
    return { android: null, ios: null };
}

// Helper: Save Version
async function updateVersion(platform: 'android' | 'ios', version: string) {
    const versions = await getVersions();
    versions[platform] = version;
    await Bun.write(VERSIONS_FILE, JSON.stringify(versions, null, 2));
}

// Helper: Strict Filename Sanitization
function getSafePath(platform: 'android' | 'ios', version: string) {
    // Only allow alphanumeric, dots, dashes, underscores
    // This effectively blocks path traversal (../)
    const safeVersion = version.replace(/[^a-zA-Z0-9.\-_]/g, ''); 
    const filename = `${safeVersion}.zip`;
    const dir = platform === 'android' ? ANDROID_DIR : IOS_DIR;
    return join(dir, filename);
}

const app = new Elysia()
    .use(helmet({
        contentSecurityPolicy: {
            directives: {
                "default-src": ["'self'"],
                "script-src": ["'self'", "'unsafe-inline'"],
                "script-src-attr": ["'unsafe-inline'"], // Allow inline event handlers
                "style-src": ["'self'", "'unsafe-inline'"],
                "connect-src": ["'self'"],
                "img-src": ["'self'", "data:"],
                "font-src": ["'self'", "https:", "data:"],
                "object-src": ["'none'"],
                "base-uri": ["'self'"],
                "form-action": ["'self'"],
                "frame-ancestors": ["'self'"],
                "upgrade-insecure-requests": []
            },
        },
    })) // Security Headers
    .use(rateLimit({ duration: 60000, max: 100 })) // Limit: 100 reqs per minute
    .use(html())
    .use(
        jwt({
            name: 'jwt',
            secret: JWT_SECRET,
            exp: TOKEN_EXPIRY
        })
    )
    .use(
        jwt({
            name: 'auth',
            secret: JWT_SECRET,
            exp: '3m' // 3 minute session
        })
    )

    // ---------------------------------------------------------
    // AUTH (Login)
    // ---------------------------------------------------------
    .get('/login', () => `
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
                    const res = await fetch('/login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(Object.fromEntries(formData))
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
    `)

    .post('/login', async ({ body, auth, cookie: { session }, set }) => {
        const { username, password } = body as any;
        if (username === USER && password === PASS) {
            session.set({
                value: await auth.sign({ user: username }),
                httpOnly: true,
                maxAge: 3 * 60, // 3 minutes in seconds
                path: '/',
                secure: true, // Only send over HTTPS (if applicable)
                sameSite: 'strict', // CSRF Protection
            });
            return { success: true };
        }
        set.status = 401;
        return { success: false };
    })
    
    // ---------------------------------------------------------
    // PUBLIC API
    // ---------------------------------------------------------
    
    // Check latest version for specific platform
    .get('/api/latest/:platform', async ({ params: { platform }, jwt, set }) => {
        const plat = platform.toLowerCase();
        if (plat !== 'android' && plat !== 'ios') {
            set.status = 400;
            return { error: "Invalid platform. Use 'android' or 'ios'." };
        }

        const versions = await getVersions();
        const version = versions[plat as keyof typeof versions];

        if (version) {
            // Use safe path helper
            const filePath = getSafePath(plat as 'android'|'ios', version);
            const file = Bun.file(filePath);

            if (await file.exists()) {
                 const token = await jwt.sign({
                    version: version,
                    platform: plat,
                    allowed: true
                });

                return {
                    version_url: `${HOST_URL}/api/version/${token}`,
                    download_url: `${HOST_URL}/api/download/${token}`
                };
            }
        }

        return { version: null, message: "No version published yet." };
    })

    // Secure Version Check (Returns plain text version)
    .get('/api/version/:token', async ({ params: { token }, jwt, set }) => {
        const profile = await jwt.verify(token);

        if (!profile || !profile.allowed || !profile.version) {
            set.status = 403;
            return "Invalid or expired link";
        }

        return profile.version;
    })

    // Secure Download
    .get('/api/download/:token', async ({ params: { token }, jwt, set }) => {
        const profile = await jwt.verify(token);

        if (!profile || !profile.allowed || !profile.version || !profile.platform) {
            set.status = 403;
            return { error: "Invalid or expired download link" };
        }

        const version = profile.version as string;
        const platform = profile.platform as 'android' | 'ios';
        
        // Use safe path helper
        const filePath = getSafePath(platform, version);
        const file = Bun.file(filePath);

        if (await file.exists()) {
            // Force download filename: android-1.0.0.zip or ios-1.0.0.zip
            // Sanitize again just for the header filename
            const safeVersion = version.replace(/[^a-zA-Z0-9.\-_]/g, '');
            set.headers['Content-Disposition'] = `attachment; filename="${platform}-${safeVersion}.zip"`;
            return file;
        }

        set.status = 404;
        return { error: "Bundle not found" };
    })

    // ---------------------------------------------------------
    // ADMIN UI & UPLOAD (Protected)
    // ---------------------------------------------------------
    
    .guard(
        {
            async beforeHandle({ auth, cookie: { session }, set, request }) {
                console.log(`[Auth] Checking access to ${new URL(request.url).pathname}`);
                
                // Prevent Caching
                set.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
                set.headers['Pragma'] = 'no-cache';
                set.headers['Expires'] = '0';

                const authorized = await auth.verify(session?.value as string | undefined);
                
                if (!authorized) {
                    console.log('[Auth] Unauthorized or Session Expired. Redirecting to /login');
                    if (new URL(request.url).pathname === '/') {
                         return redirect('/login');
                    }
                    set.status = 401;
                    return 'Unauthorized';
                }
                console.log('[Auth] Authorized');
            }
        },
        app => app
            // Admin Dashboard
            .get('/', async () => {
                const versions = await getVersions();

                return `
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
                                <div class="val">${versions.android || 'None'}</div>
                            </div>
                            <div class="stat">
                                <h3>iOS Version</h3>
                                <div class="val">${versions.ios || 'None'}</div>
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
                                <small>Max size: ${MAX_SIZE_MB}MB</small>
                            </div>

                            <button type="submit">Upload & Publish</button>
                        </form>
                    </div>

                    <script>
                        // Auto logout after 3 minutes (180 seconds)
                        setTimeout(() => {
                            window.location.reload(); // Refreshing will trigger the server auth check
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
                `;
            })

            // Handle Upload
            .post('/upload', async ({ body, set }) => {
                const { version, bundle, platform } = body as { version: string, bundle: File, platform: string };

                if (!version || !bundle || !platform) {
                    set.status = 400;
                    return "Missing fields";
                }

                const plat = platform.toLowerCase();
                if (plat !== 'android' && plat !== 'ios') {
                    set.status = 400;
                    return "Invalid platform";
                }

                // Validate zip
                if (!bundle.name.toLowerCase().endsWith('.zip')) {
                     set.status = 400;
                     return "File must be a .zip file";
                }

                // Validate Size
                const maxBytes = MAX_SIZE_MB * 1024 * 1024;
                if (bundle.size > maxBytes) {
                    set.status = 400;
                    return `File too large. Max allowed is ${MAX_SIZE_MB}MB`;
                }

                // Save File
                const savePath = getSafePath(plat as 'android'|'ios', version);

                try {
                    await Bun.write(savePath, bundle);
                    await updateVersion(plat as 'android' | 'ios', version);
                    
                    return "Upload successful";
                } catch (err) {
                    console.error(err);
                    set.status = 500;
                    return "Failed to save file";
                } 
            }, {
                body: t.Object({
                    version: t.String(),
                    platform: t.String(),
                    bundle: t.File()
                })
            })
    )
    .listen(Bun.env.PORT || 3000);

console.log(`🦊 OTA Server is running at ${app.server?.hostname}:${app.server?.port}`);
console.log(`📂 Storage: ${STORAGE_DIR}`);