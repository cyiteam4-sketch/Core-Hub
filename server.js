
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const net = require("net");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;

// ============================================================
// CONFIG
// ============================================================

const SESSION_TIMEOUT_SECONDS = 60;

const RATE_LIMIT_WINDOW_MS = 10_000;
const RATE_LIMIT_MAX = 30;

const ADMIN_ROUTE_PREFIX = "/api/admin";

const ADMIN_SESSION_HOURS = 8;
const ADMIN_COOKIE_NAME = "corehub_admin";

const ADMIN_SECURITY_WINDOW_MINUTES = 15;
const ADMIN_AUTO_BLOCK_MINUTES = 15;
const ADMIN_AUTO_BLOCK_FAILED_ATTEMPTS = 5;

// Global admin-login burst protection.
const GLOBAL_ADMIN_FAILURE_WINDOW_MS = 60_000;
const GLOBAL_ADMIN_FAILURE_THRESHOLD = 10;
const GLOBAL_ADMIN_COOLDOWN_MS = 30_000;

// Secret used to create stable IP fingerprints.
// Set ADMIN_IP_SECRET in Render.
const ADMIN_IP_SECRET =
    process.env.ADMIN_IP_SECRET ||
    process.env.ADMIN_LOGIN_CODE ||
    "CHANGE_THIS_SECRET";

// ============================================================
// EXPRESS
// ============================================================

app.set("trust proxy", 1);

// ============================================================
// DATABASE
// ============================================================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    ssl: {
        rejectUnauthorized: false
    },

    max: 10,

    idleTimeoutMillis: 30_000,

    connectionTimeoutMillis: 10_000
});

// ============================================================
// CORS
// ============================================================

const allowedOrigins = (process.env.CORS_ORIGIN || "*")
    .split(",")
    .map(origin => origin.trim())
    .filter(Boolean);

app.use(
    cors({
        origin: (origin, callback) => {

            if (!origin) {
                return callback(null, true);
            }

            if (allowedOrigins.includes("*")) {
                return callback(null, true);
            }

            if (allowedOrigins.includes(origin)) {
                return callback(null, true);
            }

            return callback(
                new Error("CORS blocked")
            );
        },

        credentials: true,

        methods: [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS"
        ],

        allowedHeaders: [
            "Content-Type",
            "Authorization",
            "X-Admin-Action"
        ]
    })
);

app.use(
    express.json({
        limit: "20kb"
    })
);

// ============================================================
// CLIENT IP
// ============================================================

function normalizeIP(ip) {

    let value =
        String(ip)
            .trim()
            .toLowerCase();

    // Convert IPv4-mapped IPv6 to normal IPv4.
    if (
        value.startsWith("::ffff:") &&
        net.isIP(value.slice(7)) === 4
    ) {
        value = value.slice(7);
    }

    return value;
}

function getClientIP(req) {

    // Cloudflare's original client address.
    const cloudflareIP =
        req.headers["cf-connecting-ip"];

    if (
        typeof cloudflareIP === "string" &&
        net.isIP(cloudflareIP.trim())
    ) {

        return normalizeIP(
            cloudflareIP.trim()
        );
    }

    // Render/proxy forwarded address.
    const forwarded =
        req.headers["x-forwarded-for"];

    if (
        typeof forwarded === "string" &&
        forwarded.trim()
    ) {

        const firstIP =
            forwarded
                .split(",")[0]
                .trim();

        if (net.isIP(firstIP)) {
            return normalizeIP(firstIP);
        }
    }

    return normalizeIP(
        req.socket.remoteAddress ||
        "unknown"
    );
}

// ============================================================
// STANDARD RATE LIMITER
// ============================================================

const rateLimits = new Map();

function getClientKey(req) {
    return getClientIP(req);
}

function rateLimit(req, res, next) {

    const key =
        getClientKey(req);

    const now =
        Date.now();

    let entry =
        rateLimits.get(key);

    if (
        !entry ||
        now - entry.start >
        RATE_LIMIT_WINDOW_MS
    ) {

        entry = {
            start: now,
            count: 0
        };

        rateLimits.set(
            key,
            entry
        );
    }

    entry.count++;

    if (
        entry.count >
        RATE_LIMIT_MAX
    ) {

        return res.status(429).json({
            success: false,
            error:
                "Too many requests"
        });
    }

    next();
}

app.use(
    "/api",
    rateLimit
);

setInterval(() => {

    const now =
        Date.now();

    for (
        const [key, entry]
        of rateLimits
    ) {

        if (
            now - entry.start >
            RATE_LIMIT_WINDOW_MS * 2
        ) {

            rateLimits.delete(key);
        }
    }

}, 60_000);

// ============================================================
// GLOBAL ADMIN LOGIN BURST PROTECTION
// ============================================================

const globalAdminFailures = [];

let globalAdminCooldownUntil = 0;

function cleanupGlobalAdminFailures() {

    const cutoff =
        Date.now() -
        GLOBAL_ADMIN_FAILURE_WINDOW_MS;

    while (
        globalAdminFailures.length > 0 &&
        globalAdminFailures[0] < cutoff
    ) {

        globalAdminFailures.shift();
    }
}

function recordGlobalAdminFailure() {

    cleanupGlobalAdminFailures();

    globalAdminFailures.push(
        Date.now()
    );

    if (
        globalAdminFailures.length >=
        GLOBAL_ADMIN_FAILURE_THRESHOLD
    ) {

        globalAdminCooldownUntil =
            Date.now() +
            GLOBAL_ADMIN_COOLDOWN_MS;

        // Start a fresh failure window after
        // the cooldown has been triggered.
        globalAdminFailures.length = 0;

        return true;
    }

    return false;
}

function getGlobalAdminCooldownRemaining() {

    const remaining =
        globalAdminCooldownUntil -
        Date.now();

    return Math.max(
        0,
        remaining
    );
}

function isGlobalAdminLoginBlocked() {

    return (
        getGlobalAdminCooldownRemaining() > 0
    );
}

// Cleanup old entries.
setInterval(
    cleanupGlobalAdminFailures,
    10_000
);

// ============================================================
// HELPERS
// ============================================================

function hashToken(token) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function createToken(bytes = 32) {

    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function getBearerToken(req) {

    const header =
        req.headers.authorization;

    if (!header) {
        return null;
    }

    if (
        !header.startsWith("Bearer ")
    ) {
        return null;
    }

    const token =
        header
            .slice(7)
            .trim();

    return token || null;
}

function getCookie(req, name) {

    const cookieHeader =
        req.headers.cookie || "";

    const cookies =
        cookieHeader
            .split(";")
            .map(item => item.trim());

    for (
        const cookie
        of cookies
    ) {

        const separator =
            cookie.indexOf("=");

        if (separator === -1) {
            continue;
        }

        const key =
            cookie.slice(
                0,
                separator
            );

        const value =
            cookie.slice(
                separator + 1
            );

        if (key === name) {

            try {
                return decodeURIComponent(value);
            } catch {
                return value;
            }
        }
    }

    return null;
}

function timingSafeEqualString(
    a,
    b
) {

    const aBuffer =
        Buffer.from(String(a));

    const bBuffer =
        Buffer.from(String(b));

    if (
        aBuffer.length !==
        bBuffer.length
    ) {

        return false;
    }

    return crypto.timingSafeEqual(
        aBuffer,
        bBuffer
    );
}

function getIPFingerprint(req) {

    return crypto
        .createHmac(
            "sha256",
            ADMIN_IP_SECRET
        )
        .update(
            getClientIP(req)
        )
        .digest("hex");
}

function sendServerError(
    res,
    message = "Internal server error"
) {

    return res.status(500).json({
        success: false,
        error: message
    });
}

// ============================================================
// HEALTH
// ============================================================

app.get(
    "/api/health",
    async (req, res) => {

        try {

            await pool.query(
                "SELECT 1"
            );

            res.json({
                success: true,
                status: "ok",
                service: "Core Hub API",
                database: "connected"
            });

        } catch (error) {

            console.error(
                "HEALTH ERROR:",
                error
            );

            res.status(503).json({
                success: false,
                status: "error",
                service: "Core Hub API",
                database: "unavailable"
            });
        }
    }
);

// ============================================================
// GUEST SESSIONS
// ============================================================

app.post(
    "/api/sessions",
    async (req, res) => {

        try {

            const token =
                createToken();

            const tokenHash =
                hashToken(token);

            await pool.query(
                `
                INSERT INTO guest_sessions
                    (token_hash)
                VALUES
                    ($1)
                `,
                [tokenHash]
            );

            res.status(201).json({
                success: true,
                session: token,
                expiresIn:
                    SESSION_TIMEOUT_SECONDS
            });

        } catch (error) {

            console.error(
                "SESSION CREATE ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not create session"
            );
        }
    }
);

// ============================================================
// SESSION AUTHENTICATION
// ============================================================

async function requireSession(
    req,
    res,
    next
) {

    try {

        const token =
            getBearerToken(req);

        if (
            !token ||
            token.length !== 64
        ) {

            return res.status(401).json({
                success: false,
                error:
                    "Invalid or missing session"
            });
        }

        const tokenHash =
            hashToken(token);

        const result =
            await pool.query(
                `
                SELECT
                    id,
                    last_seen,
                    current_game_id
                FROM guest_sessions
                WHERE token_hash = $1
                  AND last_seen >=
                      NOW() - INTERVAL '60 seconds'
                `,
                [tokenHash]
            );

        if (
            result.rows.length === 0
        ) {

            return res.status(401).json({
                success: false,
                error:
                    "Session expired"
            });
        }

        req.session =
            result.rows[0];

        next();

    } catch (error) {

        console.error(
            "SESSION AUTH ERROR:",
            error
        );

        sendServerError(
            res,
            "Session validation failed"
        );
    }
}

// ============================================================
// SESSION HEARTBEAT
// ============================================================

app.post(
    "/api/sessions/heartbeat",
    requireSession,
    async (req, res) => {

        try {

            let gameId =
                req.body?.gameId ?? null;

            if (
                typeof gameId !== "string" ||
                gameId.trim() === ""
            ) {

                gameId = null;

            } else {

                gameId =
                    gameId.trim();
            }

            if (
                gameId !== null
            ) {

                const game =
                    await pool.query(
                        `
                        SELECT game_id
                        FROM games
                        WHERE game_id = $1
                        `,
                        [gameId]
                    );

                if (
                    game.rows.length === 0
                ) {

                    return res.status(404).json({
                        success: false,
                        error:
                            "Game not found"
                    });
                }
            }

            await pool.query(
                `
                UPDATE guest_sessions
                SET
                    last_seen = NOW(),
                    current_game_id = $1
                WHERE id = $2
                `,
                [
                    gameId,
                    req.session.id
                ]
            );

            res.json({
                success: true,
                gameId,
                expiresIn:
                    SESSION_TIMEOUT_SECONDS
            });

        } catch (error) {

            console.error(
                "HEARTBEAT ERROR:",
                error
            );

            sendServerError(
                res,
                "Heartbeat failed"
            );
        }
    }
);

// ============================================================
// ONLINE USERS
// ============================================================

app.get(
    "/api/online",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        COUNT(*)::int AS online
                    FROM guest_sessions
                    WHERE last_seen >=
                        NOW() - INTERVAL '60 seconds'
                    `
                );

            res.json({
                success: true,
                online:
                    result.rows[0].online
            });

        } catch (error) {

            console.error(
                "ONLINE ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not get online users"
            );
        }
    }
);

// ============================================================
// CURRENTLY PLAYING
// ============================================================

app.get(
    "/api/online/games",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        current_game_id AS game_id,
                        COUNT(*)::int AS players
                    FROM guest_sessions
                    WHERE last_seen >=
                        NOW() - INTERVAL '60 seconds'
                      AND current_game_id IS NOT NULL
                    GROUP BY current_game_id
                    ORDER BY players DESC
                    `
                );

            res.json({
                success: true,
                games:
                    result.rows
            });

        } catch (error) {

            console.error(
                "ONLINE GAMES ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not get active games"
            );
        }
    }
);

// ============================================================
// SESSION CLEANUP
// ============================================================

async function cleanupSessions() {

    try {

        const result =
            await pool.query(
                `
                DELETE FROM guest_sessions
                WHERE last_seen <
                    NOW() - INTERVAL '2 minutes'
                `
            );

        if (
            result.rowCount > 0
        ) {

            console.log(
                `Cleaned ${result.rowCount} expired sessions`
            );
        }

    } catch (error) {

        console.error(
            "SESSION CLEANUP ERROR:",
            error
        );
    }
}

setInterval(
    cleanupSessions,
    60_000
);

// ============================================================
// GAMES
// ============================================================

app.get(
    "/api/games",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        game_id,
                        name,
                        category,
                        url,
                        status
                    FROM games
                    ORDER BY id DESC
                    `
                );

            res.json({
                success: true,
                games:
                    result.rows
            });

        } catch (error) {

            console.error(
                "GAMES ERROR:",
                error
            );

            sendServerError(
                res,
                "Database error"
            );
        }
    }
);

app.get(
    "/api/games/:gameId",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        game_id,
                        name,
                        category,
                        url,
                        status
                    FROM games
                    WHERE game_id = $1
                    `,
                    [req.params.gameId]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    error:
                        "Game not found"
                });
            }

            res.json({
                success: true,
                game:
                    result.rows[0]
            });

        } catch (error) {

            console.error(
                "GAME ERROR:",
                error
            );

            sendServerError(
                res,
                "Database error"
            );
        }
    }
);

// ============================================================
// GAME LAUNCHES
// ============================================================

app.post(
    "/api/games/:gameId/launch",
    requireSession,
    async (req, res) => {

        try {

            const gameId =
                req.params.gameId;

            const game =
                await pool.query(
                    `
                    SELECT game_id
                    FROM games
                    WHERE game_id = $1
                    `,
                    [gameId]
                );

            if (
                game.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    error:
                        "Game not found"
                });
            }

            await pool.query(
                `
                INSERT INTO game_launches
                    (game_id, session_id)
                VALUES
                    ($1, $2)
                `,
                [
                    gameId,
                    req.session.id
                ]
            );

            await pool.query(
                `
                UPDATE guest_sessions
                SET
                    last_seen = NOW(),
                    current_game_id = $1
                WHERE id = $2
                `,
                [
                    gameId,
                    req.session.id
                ]
            );

            res.json({
                success: true,
                gameId
            });

        } catch (error) {

            console.error(
                "LAUNCH ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not record launch"
            );
        }
    }
);

// ============================================================
// GAME STATS
// ============================================================

app.get(
    "/api/games/:gameId/stats",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        COUNT(*)::int AS total_launches,

                        COUNT(*) FILTER (
                            WHERE created_at >=
                                NOW() - INTERVAL '24 hours'
                        )::int AS launches_today,

                        COUNT(*) FILTER (
                            WHERE created_at >=
                                NOW() - INTERVAL '7 days'
                        )::int AS launches_week

                    FROM game_launches
                    WHERE game_id = $1
                    `,
                    [req.params.gameId]
                );

            res.json({
                success: true,
                gameId:
                    req.params.gameId,
                stats:
                    result.rows[0]
            });

        } catch (error) {

            console.error(
                "STATS ERROR:",
                error
            );

            sendServerError(
                res,
                "Database error"
            );
        }
    }
);

// ============================================================
// TRENDING
// ============================================================

app.get(
    "/api/trending",
    async (req, res) => {

        try {

            const requestedLimit =
                Number.parseInt(
                    req.query.limit,
                    10
                );

            const limit =
                Math.min(
                    Number.isFinite(
                        requestedLimit
                    )
                        ? requestedLimit
                        : 10,
                    50
                );

            const result =
                await pool.query(
                    `
                    SELECT
                        g.game_id,
                        g.name,
                        g.category,
                        g.url,
                        g.status,
                        COUNT(l.id)::int AS launch_count

                    FROM games g

                    LEFT JOIN game_launches l
                        ON l.game_id = g.game_id
                        AND l.created_at >=
                            NOW() - INTERVAL '7 days'

                    GROUP BY
                        g.game_id,
                        g.name,
                        g.category,
                        g.url,
                        g.status

                    ORDER BY launch_count DESC

                    LIMIT $1
                    `,
                    [limit]
                );

            res.json({
                success: true,
                games:
                    result.rows
            });

        } catch (error) {

            console.error(
                "TRENDING ERROR:",
                error
            );

            sendServerError(
                res,
                "Database error"
            );
        }
    }
);

// ============================================================
// NEWS
// ============================================================

app.get(
    "/api/news",
    async (req, res) => {

        try {

            const requestedLimit =
                Number.parseInt(
                    req.query.limit,
                    10
                );

            const limit =
                Math.min(
                    Number.isFinite(
                        requestedLimit
                    )
                        ? requestedLimit
                        : 20,
                    50
                );

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        title,
                        content,
                        created_at
                    FROM news
                    ORDER BY created_at DESC
                    LIMIT $1
                    `,
                    [limit]
                );

            res.json({
                success: true,
                news:
                    result.rows
            });

        } catch (error) {

            console.error(
                "NEWS ERROR:",
                error
            );

            sendServerError(
                res,
                "Database error"
            );
        }
    }
);

// ============================================================
// ADMIN TABLES
// ============================================================

async function ensureAdminTables() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS admin_sessions (
            id BIGSERIAL PRIMARY KEY,
            token_hash TEXT UNIQUE NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS admin_login_logs (
            id BIGSERIAL PRIMARY KEY,
            ip_hash TEXT NOT NULL,
            successful BOOLEAN NOT NULL,
            reason TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS admin_ip_blacklist (
            id BIGSERIAL PRIMARY KEY,
            ip_hash TEXT UNIQUE NOT NULL,
            reason TEXT,
            expires_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        admin_login_logs_ip_hash_idx
        ON admin_login_logs(ip_hash)
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        admin_login_logs_created_at_idx
        ON admin_login_logs(created_at)
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        admin_ip_blacklist_expires_at_idx
        ON admin_ip_blacklist(expires_at)
    `);
}

// ============================================================
// ADMIN SECURITY HELPERS
// ============================================================

async function logAdminLogin(
    ipHash,
    successful,
    reason
) {

    try {

        await pool.query(
            `
            INSERT INTO admin_login_logs
                (
                    ip_hash,
                    successful,
                    reason
                )
            VALUES
                (
                    $1,
                    $2,
                    $3
                )
            `,
            [
                ipHash,
                successful,
                reason || null
            ]
        );

    } catch (error) {

        console.error(
            "ADMIN LOGIN LOG ERROR:",
            error
        );
    }
}

async function cleanupExpiredIPBlocks() {

    try {

        await pool.query(
            `
            DELETE FROM admin_ip_blacklist
            WHERE expires_at IS NOT NULL
              AND expires_at <= NOW()
            `
        );

    } catch (error) {

        console.error(
            "IP BLOCK CLEANUP ERROR:",
            error
        );
    }
}

async function getActiveIPBlock(
    ipHash
) {

    const result =
        await pool.query(
            `
            SELECT
                id,
                ip_hash,
                reason,
                expires_at
            FROM admin_ip_blacklist
            WHERE ip_hash = $1
              AND (
                    expires_at IS NULL
                    OR expires_at > NOW()
                  )
            LIMIT 1
            `,
            [ipHash]
        );

    return (
        result.rows[0] ||
        null
    );
}

async function getRecentFailures(
    ipHash
) {

    const result =
        await pool.query(
            `
            SELECT
                COUNT(*)::int AS failures
            FROM admin_login_logs
            WHERE ip_hash = $1
              AND successful = false
              AND reason = 'invalid_code'
              AND created_at >=
                    NOW() -
                    INTERVAL '${ADMIN_SECURITY_WINDOW_MINUTES} minutes'
            `,
            [ipHash]
        );

    return (
        result.rows[0].failures
    );
}

async function autoBlockIfNeeded(
    ipHash
) {

    const failures =
        await getRecentFailures(
            ipHash
        );

    if (
        failures <
        ADMIN_AUTO_BLOCK_FAILED_ATTEMPTS
    ) {

        return false;
    }

    await pool.query(
        `
        INSERT INTO admin_ip_blacklist
            (
                ip_hash,
                reason,
                expires_at
            )
        VALUES
            (
                $1,
                $2,
                NOW() +
                INTERVAL '${ADMIN_AUTO_BLOCK_MINUTES} minutes'
            )
        ON CONFLICT (ip_hash)
        DO UPDATE SET
            reason = EXCLUDED.reason,
            expires_at = EXCLUDED.expires_at
        `,
        [
            ipHash,
            `Automatic block after ${ADMIN_AUTO_BLOCK_FAILED_ATTEMPTS} failed login attempts`
        ]
    );

    return true;
}

// ============================================================
// REQUIRE ADMIN
// ============================================================

async function requireAdmin(
    req,
    res,
    next
) {

    try {

        const token =
            getCookie(
                req,
                ADMIN_COOKIE_NAME
            );

        if (!token) {

            return res.status(401).json({
                success: false,
                error:
                    "Admin authentication required"
            });
        }

        const tokenHash =
            hashToken(token);

        const result =
            await pool.query(
                `
                SELECT
                    id,
                    expires_at
                FROM admin_sessions
                WHERE token_hash = $1
                  AND expires_at > NOW()
                LIMIT 1
                `,
                [tokenHash]
            );

        if (
            result.rows.length === 0
        ) {

            return res.status(401).json({
                success: false,
                error:
                    "Admin session expired or invalid"
            });
        }

        req.admin = {
            id:
                result.rows[0].id,
            role:
                "admin"
        };

        next();

    } catch (error) {

        console.error(
            "ADMIN AUTH ERROR:",
            error
        );

        sendServerError(
            res,
            "Admin authentication failed"
        );
    }
}

// ============================================================
// ADMIN LOGIN
// ============================================================

app.post(
    `${ADMIN_ROUTE_PREFIX}/auth/login`,
    async (req, res) => {

        const ipHash =
            getIPFingerprint(req);

        try {

            // ------------------------------------------------
            // GLOBAL BURST CHECK
            // ------------------------------------------------

            const globalCooldown =
                getGlobalAdminCooldownRemaining();

            if (globalCooldown > 0) {

                await logAdminLogin(
                    ipHash,
                    false,
                    "global_cooldown"
                );

                res.set(
                    "Retry-After",
                    String(
                        Math.ceil(
                            globalCooldown / 1000
                        )
                    )
                );

                return res.status(429).json({
                    success: false,
                    error:
                        "Admin login is temporarily paused because of a high volume of failed attempts.",
                    retryAfter:
                        Math.ceil(
                            globalCooldown / 1000
                        )
                });
            }

            await cleanupExpiredIPBlocks();

            // ------------------------------------------------
            // IP BLOCK CHECK
            // ------------------------------------------------

            const blocked =
                await getActiveIPBlock(
                    ipHash
                );

            if (blocked) {

                await logAdminLogin(
                    ipHash,
                    false,
                    "blocked"
                );

                return res.status(429).json({
                    success: false,
                    error:
                        "This IP is temporarily blocked from admin login.",
                    expiresAt:
                        blocked.expires_at
                });
            }

            // ------------------------------------------------
            // GET ADMIN CODE
            // ------------------------------------------------

            const submittedCode =
                String(
                    req.body?.code || ""
                );

            const configuredCode =
                String(
                    process.env.ADMIN_LOGIN_CODE || ""
                );

            if (!configuredCode) {

                await logAdminLogin(
                    ipHash,
                    false,
                    "not_configured"
                );

                return res.status(500).json({
                    success: false,
                    error:
                        "Admin login is not configured"
                });
            }

            if (!submittedCode) {

                const triggered =
                    recordGlobalAdminFailure();

                await logAdminLogin(
                    ipHash,
                    false,
                    "missing_code"
                );

                if (triggered) {

                    return res.status(429).json({
                        success: false,
                        error:
                            "Admin login is temporarily paused because of a high volume of failed attempts."
                    });
                }

                return res.status(400).json({
                    success: false,
                    error:
                        "Admin login code required"
                });
            }

            // ------------------------------------------------
            // CHECK CODE
            // ------------------------------------------------

            if (
                !timingSafeEqualString(
                    submittedCode,
                    configuredCode
                )
            ) {

                const triggered =
                    recordGlobalAdminFailure();

                await logAdminLogin(
                    ipHash,
                    false,
                    "invalid_code"
                );

                const shouldBlockIP =
                    await autoBlockIfNeeded(
                        ipHash
                    );

                // If the IP qualifies for a personal block,
                // store that independently from the global
                // burst protection.
                if (shouldBlockIP) {

                    return res.status(429).json({
                        success: false,
                        error:
                            "Too many failed admin login attempts. This IP is temporarily blocked."
                    });
                }

                // If the entire admin login system is
                // experiencing a burst, activate the
                // global cooldown.
                if (triggered) {

                    return res.status(429).json({
                        success: false,
                        error:
                            "Admin login is temporarily paused because of a high volume of failed attempts.",
                        retryAfter:
                            Math.ceil(
                                GLOBAL_ADMIN_COOLDOWN_MS /
                                1000
                            )
                    });
                }

                return res.status(401).json({
                    success: false,
                    error:
                        "Invalid admin login code"
                });
            }

            // ------------------------------------------------
            // SUCCESSFUL LOGIN
            // ------------------------------------------------

            const sessionToken =
                createToken(48);

            const sessionHash =
                hashToken(
                    sessionToken
                );

            await pool.query(
                `
                INSERT INTO admin_sessions
                    (
                        token_hash,
                        expires_at
                    )
                VALUES
                    (
                        $1,
                        NOW() +
                        INTERVAL '${ADMIN_SESSION_HOURS} hours'
                    )
                `,
                [sessionHash]
            );

            await logAdminLogin(
                ipHash,
                true,
                "success"
            );

            // Successful login is not counted
            // as a failure and therefore does
            // not trigger the burst system.

            res.setHeader(
                "Set-Cookie",
                [
                    `${ADMIN_COOKIE_NAME}=${encodeURIComponent(sessionToken)}`,
                    "Path=/",
                    "HttpOnly",
                    "Secure",
                    "SameSite=None",
                    `Max-Age=${ADMIN_SESSION_HOURS * 60 * 60}`
                ].join("; ")
            );

            res.json({
                success: true,
                message:
                    "Admin login successful"
            });

        } catch (error) {

            console.error(
                "ADMIN LOGIN ERROR:",
                error
            );

            await logAdminLogin(
                ipHash,
                false,
                "server_error"
            );

            sendServerError(
                res,
                "Admin login failed"
            );
        }
    }
);

// ============================================================
// ADMIN SESSION CHECK
// ============================================================

app.get(
    `${ADMIN_ROUTE_PREFIX}/auth/me`,
    requireAdmin,
    async (req, res) => {

        res.json({
            success: true,
            authenticated: true,
            admin: {
                role:
                    "admin"
            }
        });
    }
);

// ============================================================
// ADMIN LOGOUT
// ============================================================

app.post(
    `${ADMIN_ROUTE_PREFIX}/auth/logout`,
    requireAdmin,
    async (req, res) => {

        try {

            const token =
                getCookie(
                    req,
                    ADMIN_COOKIE_NAME
                );

            if (token) {

                await pool.query(
                    `
                    DELETE FROM admin_sessions
                    WHERE token_hash = $1
                    `,
                    [
                        hashToken(token)
                    ]
                );
            }

            res.setHeader(
                "Set-Cookie",
                [
                    `${ADMIN_COOKIE_NAME}=`,
                    "Path=/",
                    "HttpOnly",
                    "Secure",
                    "SameSite=None",
                    "Max-Age=0"
                ].join("; ")
            );

            res.json({
                success: true,
                message:
                    "Admin logged out"
            });

        } catch (error) {

            console.error(
                "ADMIN LOGOUT ERROR:",
                error
            );

            sendServerError(
                res,
                "Logout failed"
            );
        }
    }
);

// ============================================================
// ADMIN SECURITY — LOGIN LOGS
// ============================================================

app.get(
    `${ADMIN_ROUTE_PREFIX}/security/logins`,
    requireAdmin,
    async (req, res) => {

        try {

            const requestedLimit =
                Number.parseInt(
                    req.query.limit,
                    10
                );

            const limit =
                Math.min(
                    Number.isFinite(
                        requestedLimit
                    )
                        ? requestedLimit
                        : 50,
                    100
                );

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        ip_hash,
                        successful,
                        reason,
                        created_at
                    FROM admin_login_logs
                    ORDER BY created_at DESC
                    LIMIT $1
                    `,
                    [limit]
                );

            res.json({
                success: true,
                logs:
                    result.rows
            });

        } catch (error) {

            console.error(
                "SECURITY LOG GET ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not load security logs"
            );
        }
    }
);

// ============================================================
// ADMIN SECURITY — BLACKLIST GET
// ============================================================

app.get(
    `${ADMIN_ROUTE_PREFIX}/security/blacklist`,
    requireAdmin,
    async (req, res) => {

        try {

            await cleanupExpiredIPBlocks();

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        ip_hash,
                        reason,
                        expires_at,
                        created_at
                    FROM admin_ip_blacklist
                    ORDER BY created_at DESC
                    `
                );

            res.json({
                success: true,
                blacklist:
                    result.rows
            });

        } catch (error) {

            console.error(
                "BLACKLIST GET ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not load blacklist"
            );
        }
    }
);

// ============================================================
// ADMIN SECURITY — MANUAL BLOCK
// ============================================================

app.post(
    `${ADMIN_ROUTE_PREFIX}/security/blacklist`,
    requireAdmin,
    async (req, res) => {

        try {

            const ipHash =
                String(
                    req.body?.ip_hash || ""
                ).trim();

            const requestedMinutes =
                Number.parseInt(
                    req.body?.minutes,
                    10
                );

            const minutes =
                Math.min(
                    Math.max(
                        Number.isFinite(
                            requestedMinutes
                        )
                            ? requestedMinutes
                            : 60,
                        1
                    ),
                    43_200
                );

            const reason =
                String(
                    req.body?.reason ||
                    "Manually blocked by admin"
                ).trim();

            if (
                !/^[a-f0-9]{64}$/i.test(
                    ipHash
                )
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Invalid IP fingerprint"
                });
            }

            await pool.query(
                `
                INSERT INTO admin_ip_blacklist
                    (
                        ip_hash,
                        reason,
                        expires_at
                    )
                VALUES
                    (
                        $1,
                        $2,
                        NOW() +
                        ($3 * INTERVAL '1 minute')
                    )
                ON CONFLICT (ip_hash)
                DO UPDATE SET
                    reason = EXCLUDED.reason,
                    expires_at = EXCLUDED.expires_at
                `,
                [
                    ipHash,
                    reason,
                    minutes
                ]
            );

            res.json({
                success: true,
                message:
                    "IP fingerprint blocked",
                minutes
            });

        } catch (error) {

            console.error(
                "BLACKLIST CREATE ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not blacklist fingerprint"
            );
        }
    }
);

// ============================================================
// ADMIN SECURITY — UNBLOCK
// ============================================================

app.delete(
    `${ADMIN_ROUTE_PREFIX}/security/blacklist/:ipHash`,
    requireAdmin,
    async (req, res) => {

        try {

            const ipHash =
                String(
                    req.params.ipHash || ""
                ).trim();

            if (
                !/^[a-f0-9]{64}$/i.test(
                    ipHash
                )
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Invalid IP fingerprint"
                });
            }

            const result =
                await pool.query(
                    `
                    DELETE FROM admin_ip_blacklist
                    WHERE ip_hash = $1
                    RETURNING ip_hash
                    `,
                    [ipHash]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    error:
                        "Fingerprint is not blacklisted"
                });
            }

            res.json({
                success: true,
                message:
                    "IP fingerprint unblocked"
            });

        } catch (error) {

            console.error(
                "BLACKLIST DELETE ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not unblock fingerprint"
            );
        }
    }
);

// ============================================================
// ADMIN GAMES
// ============================================================

app.get(
    `${ADMIN_ROUTE_PREFIX}/games`,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        game_id,
                        name,
                        category,
                        url,
                        status
                    FROM games
                    ORDER BY id DESC
                    `
                );

            res.json({
                success: true,
                games:
                    result.rows
            });

        } catch (error) {

            console.error(
                "ADMIN GAMES GET ERROR:",
                error
            );

            sendServerError(
                res,
                "Database error"
            );
        }
    }
);

app.post(
    `${ADMIN_ROUTE_PREFIX}/games`,
    requireAdmin,
    async (req, res) => {

        try {

            const gameId =
                String(
                    req.body?.game_id || ""
                ).trim();

            const name =
                String(
                    req.body?.name || ""
                ).trim();

            const category =
                String(
                    req.body?.category || ""
                ).trim();

            const url =
                String(
                    req.body?.url || ""
                ).trim();

            const status =
                String(
                    req.body?.status || "online"
                ).trim();

            if (
                !gameId ||
                !name ||
                !category ||
                !url
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "game_id, name, category and url are required"
                });
            }

            const result =
                await pool.query(
                    `
                    INSERT INTO games
                        (
                            game_id,
                            name,
                            category,
                            url,
                            status
                        )
                    VALUES
                        (
                            $1,
                            $2,
                            $3,
                            $4,
                            $5
                        )
                    RETURNING
                        game_id,
                        name,
                        category,
                        url,
                        status
                    `,
                    [
                        gameId,
                        name,
                        category,
                        url,
                        status
                    ]
                );

            res.status(201).json({
                success: true,
                game:
                    result.rows[0]
            });

        } catch (error) {

            console.error(
                "ADMIN GAME CREATE ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not create game"
            );
        }
    }
);

app.put(
    `${ADMIN_ROUTE_PREFIX}/games/:gameId`,
    requireAdmin,
    async (req, res) => {

        try {

            const name =
                String(
                    req.body?.name || ""
                ).trim();

            const category =
                String(
                    req.body?.category || ""
                ).trim();

            const url =
                String(
                    req.body?.url || ""
                ).trim();

            const status =
                String(
                    req.body?.status || "online"
                ).trim();

            if (
                !name ||
                !category ||
                !url
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "name, category and url are required"
                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE games
                    SET
                        name = $1,
                        category = $2,
                        url = $3,
                        status = $4
                    WHERE game_id = $5
                    RETURNING
                        game_id,
                        name,
                        category,
                        url,
                        status
                    `,
                    [
                        name,
                        category,
                        url,
                        status,
                        req.params.gameId
                    ]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    error:
                        "Game not found"
                });
            }

            res.json({
                success: true,
                game:
                    result.rows[0]
            });

        } catch (error) {

            console.error(
                "ADMIN GAME UPDATE ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not update game"
            );
        }
    }
);

app.delete(
    `${ADMIN_ROUTE_PREFIX}/games/:gameId`,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM games
                    WHERE game_id = $1
                    RETURNING game_id
                    `,
                    [req.params.gameId]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    error:
                        "Game not found"
                });
            }

            res.json({
                success: true,
                message:
                    "Game deleted"
            });

        } catch (error) {

            console.error(
                "ADMIN GAME DELETE ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not delete game"
            );
        }
    }
);

// ============================================================
// ADMIN NEWS
// ============================================================

app.get(
    `${ADMIN_ROUTE_PREFIX}/news`,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        title,
                        content,
                        created_at
                    FROM news
                    ORDER BY created_at DESC
                    `
                );

            res.json({
                success: true,
                news:
                    result.rows
            });

        } catch (error) {

            console.error(
                "ADMIN NEWS GET ERROR:",
                error
            );

            sendServerError(
                res,
                "Database error"
            );
        }
    }
);

app.post(
    `${ADMIN_ROUTE_PREFIX}/news`,
    requireAdmin,
    async (req, res) => {

        try {

            const title =
                String(
                    req.body?.title || ""
                ).trim();

            const content =
                String(
                    req.body?.content || ""
                ).trim();

            if (
                !title ||
                !content
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "title and content are required"
                });
            }

            const result =
                await pool.query(
                    `
                    INSERT INTO news
                        (
                            title,
                            content,
                            created_at
                        )
                    VALUES
                        (
                            $1,
                            $2,
                            NOW()
                        )
                    RETURNING
                        id,
                        title,
                        content,
                        created_at
                    `,
                    [
                        title,
                        content
                    ]
                );

            res.status(201).json({
                success: true,
                news:
                    result.rows[0]
            });

        } catch (error) {

            console.error(
                "ADMIN NEWS CREATE ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not create news"
            );
        }
    }
);

app.put(
    `${ADMIN_ROUTE_PREFIX}/news/:id`,
    requireAdmin,
    async (req, res) => {

        try {

            const title =
                String(
                    req.body?.title || ""
                ).trim();

            const content =
                String(
                    req.body?.content || ""
                ).trim();

            if (
                !title ||
                !content
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "title and content are required"
                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE news
                    SET
                        title = $1,
                        content = $2
                    WHERE id = $3
                    RETURNING
                        id,
                        title,
                        content,
                        created_at
                    `,
                    [
                        title,
                        content,
                        req.params.id
                    ]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    error:
                        "News article not found"
                });
            }

            res.json({
                success: true,
                news:
                    result.rows[0]
            });

        } catch (error) {

            console.error(
                "ADMIN NEWS UPDATE ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not update news"
            );
        }
    }
);

app.delete(
    `${ADMIN_ROUTE_PREFIX}/news/:id`,
    requireAdmin,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM news
                    WHERE id = $1
                    RETURNING id
                    `,
                    [req.params.id]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    error:
                        "News article not found"
                });
            }

            res.json({
                success: true,
                message:
                    "News article deleted"
            });

        } catch (error) {

            console.error(
                "ADMIN NEWS DELETE ERROR:",
                error
            );

            sendServerError(
                res,
                "Could not delete news"
            );
        }
    }
);

// ============================================================
// CLEANUP ADMIN DATA
// ============================================================

async function cleanupAdminData() {

    try {

        await cleanupExpiredIPBlocks();

        await pool.query(
            `
            DELETE FROM admin_sessions
            WHERE expires_at <= NOW()
            `
        );

        // Keep security logs for 90 days.

        await pool.query(
            `
            DELETE FROM admin_login_logs
            WHERE created_at <
                NOW() - INTERVAL '90 days'
            `
        );

    } catch (error) {

        console.error(
            "ADMIN CLEANUP ERROR:",
            error
        );
    }
}

setInterval(
    cleanupAdminData,
    60 * 60 * 1000
);

// ============================================================
// 404
// ============================================================

app.use(
    (req, res) => {

        res.status(404).json({
            success: false,
            error:
                "Endpoint not found"
        });
    }
);

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
    (error, req, res, next) => {

        console.error(
            "SERVER ERROR:",
            error
        );

        if (
            error.message ===
            "CORS blocked"
        ) {

            return res.status(403).json({
                success: false,
                error:
                    "CORS blocked"
            });
        }

        res.status(500).json({
            success: false,
            error:
                "Internal server error"
        });
    }
);

// ============================================================
// START SERVER
// ============================================================

async function startServer() {

    try {

        await pool.query(
            "SELECT 1"
        );

        await ensureAdminTables();

        await cleanupAdminData();

        const server =
            app.listen(
                PORT,
                "0.0.0.0",
                () => {

                    console.log(
                        `Core Hub API running on port ${PORT}`
                    );

                    console.log(
                        "Public API ready."
                    );

                    console.log(
                        "Admin API ready."
                    );

                    console.log(
                        "Admin IP security enabled."
                    );

                    console.log(
                        "Global admin burst protection enabled."
                    );
                }
            );

        // ====================================================
        // GRACEFUL SHUTDOWN
        // ====================================================

        async function shutdown(
            signal
        ) {

            console.log(
                `${signal} received. Shutting down...`
            );

            server.close(
                async () => {

                    try {

                        await pool.end();

                        console.log(
                            "Database pool closed."
                        );

                        process.exit(0);

                    } catch (error) {

                        console.error(
                            "SHUTDOWN ERROR:",
                            error
                        );

                        process.exit(1);
                    }
                }
            );
        }

        process.on(
            "SIGTERM",
            () => shutdown("SIGTERM")
        );

        process.on(
            "SIGINT",
            () => shutdown("SIGINT")
        );

    } catch (error) {

        console.error(
            "STARTUP ERROR:",
            error
        );

        process.exit(1);
    }
}

startServer();

