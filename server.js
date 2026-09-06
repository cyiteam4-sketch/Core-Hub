
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const net = require("net");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");

const app = express();

app.set("trust proxy", 1);

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

/* =========================================================
   CORS
========================================================= */

const allowedOrigins = [
    "https://corehubgames.com",
    "https://www.corehubgames.com",
    "https://corehub-web.web.app",
    "https://project-4al7k.vercel.app"
];

app.use(cors({
    origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        return callback(new Error("CORS not allowed"));
    },
    credentials: true
}));

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

const PORT = process.env.PORT || 10000;

const ADMIN_LOGIN_CODE = process.env.ADMIN_LOGIN_CODE;
const ADMIN_IP_SECRET = process.env.ADMIN_IP_SECRET;

if (!ADMIN_LOGIN_CODE) {
    console.error("Missing ADMIN_LOGIN_CODE");
    process.exit(1);
}

if (!ADMIN_IP_SECRET) {
    console.error("Missing ADMIN_IP_SECRET");
    process.exit(1);
}

/* =========================================================
   HELPERS
========================================================= */

function normalizeIP(ip) {
    if (!ip) return "unknown";

    ip = String(ip).trim();

    if (ip.startsWith("::ffff:")) {
        ip = ip.substring(7);
    }

    return net.isIP(ip) ? ip : "unknown";
}

function getClientIP(req) {
    const cfIP = req.headers["cf-connecting-ip"];

    if (cfIP) {
        const normalized = normalizeIP(cfIP);

        if (normalized !== "unknown") {
            return normalized;
        }
    }

    const forwarded = req.headers["x-forwarded-for"];

    if (forwarded) {
        const first = String(forwarded)
            .split(",")[0]
            .trim();

        const normalized = normalizeIP(first);

        if (normalized !== "unknown") {
            return normalized;
        }
    }

    return normalizeIP(req.socket?.remoteAddress);
}

function hashIP(ip) {
    return crypto
        .createHmac("sha256", ADMIN_IP_SECRET)
        .update(ip)
        .digest("hex");
}

function hashToken(token) {
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function generateToken() {
    return crypto.randomBytes(32).toString("hex");
}

function safeCodeMatch(a, b) {
    const aBuffer = Buffer.from(String(a || ""));
    const bBuffer = Buffer.from(String(b || ""));

    if (aBuffer.length !== bBuffer.length) {
        return false;
    }

    return crypto.timingSafeEqual(aBuffer, bBuffer);
}

/* =========================================================
   STANDARD API RATE LIMIT
========================================================= */

const rateState = new Map();

const RATE_WINDOW_MS = 10_000;
const RATE_LIMIT = 30;

function standardRateLimit(req, res, next) {
    const ip = getClientIP(req);
    const now = Date.now();

    let entry = rateState.get(ip);

    if (!entry || now - entry.start >= RATE_WINDOW_MS) {
        entry = {
            start: now,
            count: 0
        };

        rateState.set(ip, entry);
    }

    entry.count++;

    if (entry.count > RATE_LIMIT) {
        return res.status(429).json({
            success: false,
            error: "Too many requests"
        });
    }

    next();
}

app.use(standardRateLimit);

/* =========================================================
   GLOBAL ADMIN BURST PROTECTION
========================================================= */

const GLOBAL_ADMIN_FAILURE_WINDOW_MS = 60_000;
const GLOBAL_ADMIN_FAILURE_THRESHOLD = 10;
const GLOBAL_ADMIN_COOLDOWN_MS = 30_000;

let globalAdminFailures = [];
let globalAdminCooldownUntil = 0;

function cleanupGlobalAdminFailures() {
    const cutoff =
        Date.now() - GLOBAL_ADMIN_FAILURE_WINDOW_MS;

    globalAdminFailures =
        globalAdminFailures.filter(
            timestamp => timestamp >= cutoff
        );
}

function recordGlobalAdminFailure() {
    cleanupGlobalAdminFailures();

    globalAdminFailures.push(Date.now());

    if (
        globalAdminFailures.length >=
        GLOBAL_ADMIN_FAILURE_THRESHOLD
    ) {
        globalAdminCooldownUntil =
            Date.now() + GLOBAL_ADMIN_COOLDOWN_MS;

        globalAdminFailures = [];
    }
}

function getGlobalAdminCooldownRemaining() {
    const remaining =
        globalAdminCooldownUntil - Date.now();

    return remaining > 0 ? remaining : 0;
}

/* =========================================================
   CLEANUP
========================================================= */

async function cleanupExpiredSecurityData() {
    try {
        await pool.query(`
            DELETE FROM admin_sessions
            WHERE expires_at < NOW()
        `);

        await pool.query(`
            DELETE FROM admin_ip_blacklist
            WHERE expires_at IS NOT NULL
              AND expires_at < NOW()
        `);

        await pool.query(`
            DELETE FROM admin_login_logs
            WHERE created_at < NOW() - INTERVAL '90 days'
        `);

        await pool.query(`
            DELETE FROM admin_approved_logins
            WHERE created_at < NOW() - INTERVAL '90 days'
        `);

        await pool.query(`
            DELETE FROM guest_sessions
            WHERE last_seen < NOW() - INTERVAL '1 day'
        `);
    } catch (error) {
        console.error(
            "Security cleanup error:",
            error.message
        );
    }
}

setInterval(
    cleanupExpiredSecurityData,
    60 * 60 * 1000
);

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", async (req, res) => {
    try {
        await pool.query("SELECT 1");

        res.json({
            success: true,
            status: "ok",
            service: "Core Hub API",
            database: "connected"
        });
    } catch (error) {
        console.error("Health error:", error.message);

        res.status(500).json({
            success: false,
            status: "error",
            service: "Core Hub API",
            database: "disconnected"
        });
    }
});

/* =========================================================
   GUEST SESSIONS
========================================================= */

app.post("/api/sessions", async (req, res) => {
    try {
        const token = generateToken();
        const tokenHash = hashToken(token);
        const anonymousSessionId =
            crypto.randomUUID();

        await pool.query(`
            INSERT INTO guest_sessions (
                token_hash,
                anonymous_session_id,
                last_seen
            )
            VALUES ($1, $2, NOW())
        `, [
            tokenHash,
            anonymousSessionId
        ]);

        res.status(201).json({
            success: true,
            token,
            sessionId: anonymousSessionId
        });
    } catch (error) {
        console.error(
            "Create session error:",
            error.message
        );

        res.status(500).json({
            success: false,
            error: "Failed to create session"
        });
    }
});

app.post(
    "/api/sessions/heartbeat",
    async (req, res) => {
        try {
            const auth =
                req.headers.authorization || "";

            if (!auth.startsWith("Bearer ")) {
                return res.status(401).json({
                    success: false,
                    error: "Missing token"
                });
            }

            const token = auth.substring(7);
            const tokenHash = hashToken(token);

            const currentGameId =
                req.body?.currentGameId || null;

            const result = await pool.query(`
                UPDATE guest_sessions
                SET
                    last_seen = NOW(),
                    current_game_id = $2
                WHERE token_hash = $1
                RETURNING anonymous_session_id
            `, [
                tokenHash,
                currentGameId
            ]);

            if (!result.rowCount) {
                return res.status(401).json({
                    success: false,
                    error: "Invalid session"
                });
            }

            res.json({
                success: true,
                sessionId:
                    result.rows[0].anonymous_session_id
            });
        } catch (error) {
            console.error(
                "Heartbeat error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Heartbeat failed"
            });
        }
    }
);

/* =========================================================
   ONLINE
========================================================= */

app.get("/api/online", async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT COUNT(*)::int AS online
            FROM guest_sessions
            WHERE last_seen >= NOW() - INTERVAL '60 seconds'
        `);

        res.json({
            success: true,
            online: result.rows[0].online
        });
    } catch (error) {
        console.error(
            "Online error:",
            error.message
        );

        res.status(500).json({
            success: false,
            online: 0
        });
    }
});

app.get("/api/online/games", async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                current_game_id,
                COUNT(*)::int AS players
            FROM guest_sessions
            WHERE last_seen >= NOW() - INTERVAL '60 seconds'
              AND current_game_id IS NOT NULL
            GROUP BY current_game_id
            ORDER BY players DESC
        `);

        res.json({
            success: true,
            games: result.rows
        });
    } catch (error) {
        console.error(
            "Online games error:",
            error.message
        );

        res.status(500).json({
            success: false,
            games: []
        });
    }
});

/* =========================================================
   PUBLIC GAMES
========================================================= */

app.get("/api/games", async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                id,
                url,
                name,
                status,
                game_id,
                category,
                created_at
            FROM games
            ORDER BY created_at DESC
        `);

        res.json({
            success: true,
            games: result.rows
        });
    } catch (error) {
        console.error(
            "Games error:",
            error.message
        );

        res.status(500).json({
            success: false,
            games: []
        });
    }
});

app.get("/api/games/:gameId", async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                id,
                url,
                name,
                status,
                game_id,
                category,
                created_at
            FROM games
            WHERE game_id = $1
            LIMIT 1
        `, [
            req.params.gameId
        ]);

        if (!result.rowCount) {
            return res.status(404).json({
                success: false,
                error: "Game not found"
            });
        }

        res.json({
            success: true,
            game: result.rows[0]
        });
    } catch (error) {
        console.error(
            "Single game error:",
            error.message
        );

        res.status(500).json({
            success: false,
            error: "Failed to load game"
        });
    }
});

/* =========================================================
   GAME LAUNCHES
========================================================= */

app.post(
    "/api/games/:gameId/launch",
    async (req, res) => {
        try {
            const gameId = req.params.gameId;

            const sessionId =
                req.body?.sessionId || null;

            await pool.query(`
                INSERT INTO game_launches (
                    game_id,
                    session_id,
                    created_at
                )
                VALUES ($1, $2, NOW())
            `, [
                gameId,
                sessionId
            ]);

            res.json({
                success: true
            });
        } catch (error) {
            console.error(
                "Launch error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Failed to record launch"
            });
        }
    }
);

app.get(
    "/api/games/:gameId/stats",
    async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (
                        WHERE created_at >= NOW() - INTERVAL '1 day'
                    )::int AS today,
                    COUNT(*) FILTER (
                        WHERE created_at >= NOW() - INTERVAL '7 days'
                    )::int AS week
                FROM game_launches
                WHERE game_id = $1
            `, [
                req.params.gameId
            ]);

            res.json({
                success: true,
                stats: result.rows[0]
            });
        } catch (error) {
            console.error(
                "Game stats error:",
                error.message
            );

            res.status(500).json({
                success: false,
                stats: {
                    total: 0,
                    today: 0,
                    week: 0
                }
            });
        }
    }
);

app.get("/api/trending", async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                game_id,
                COUNT(*)::int AS launches
            FROM game_launches
            WHERE created_at >= NOW() - INTERVAL '7 days'
            GROUP BY game_id
            ORDER BY launches DESC
            LIMIT 10
        `);

        res.json({
            success: true,
            games: result.rows
        });
    } catch (error) {
        console.error(
            "Trending error:",
            error.message
        );

        res.status(500).json({
            success: false,
            games: []
        });
    }
});

/* =========================================================
   PUBLIC NEWS
========================================================= */

app.get("/api/news", async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                id,
                type,
                title,
                content,
                featured,
                published,
                created_at
            FROM news
            ORDER BY created_at DESC
        `);

        res.json({
            success: true,
            news: result.rows
        });
    } catch (error) {
        console.error(
            "News error:",
            error.message
        );

        res.status(500).json({
            success: false,
            news: []
        });
    }
});

/* =========================================================
   ADMIN SESSION
========================================================= */

async function createAdminSession() {
    const token = generateToken();
    const tokenHash = hashToken(token);

    const expiresAt = new Date(
        Date.now() + 8 * 60 * 60 * 1000
    );

    const result = await pool.query(`
        INSERT INTO admin_sessions (
            token_hash,
            created_at,
            expires_at
        )
        VALUES ($1, NOW(), $2)
        RETURNING id
    `, [
        tokenHash,
        expiresAt
    ]);

    return {
        token,
        id: result.rows[0].id,
        expiresAt
    };
}

async function requireAdmin(req, res, next) {
    try {
        const token =
            req.cookies.corehub_admin;

        if (!token) {
            return res.status(401).json({
                success: false,
                error: "Unauthorized"
            });
        }

        const tokenHash = hashToken(token);

        const result = await pool.query(`
            SELECT id
            FROM admin_sessions
            WHERE token_hash = $1
              AND expires_at > NOW()
            LIMIT 1
        `, [
            tokenHash
        ]);

        if (!result.rowCount) {
            return res.status(401).json({
                success: false,
                error: "Unauthorized"
            });
        }

        req.adminSessionId =
            result.rows[0].id;

        next();
    } catch (error) {
        console.error(
            "Admin auth error:",
            error.message
        );

        res.status(500).json({
            success: false,
            error: "Authentication error"
        });
    }
}

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
    "/api/admin/auth/login",
    async (req, res) => {
        const ip = getClientIP(req);
        const ipHash = hashIP(ip);

        try {
            /* GLOBAL COOLDOWN */

            const cooldownRemaining =
                getGlobalAdminCooldownRemaining();

            if (cooldownRemaining > 0) {
                await pool.query(`
                    INSERT INTO admin_login_logs (
                        ip_hash,
                        successful,
                        reason,
                        created_at
                    )
                    VALUES ($1, FALSE, 'global_cooldown', NOW())
                `, [
                    ipHash
                ]);

                return res
                    .status(429)
                    .set(
                        "Retry-After",
                        String(
                            Math.ceil(
                                cooldownRemaining / 1000
                            )
                        )
                    )
                    .json({
                        success: false,
                        error:
                            "Admin login temporarily restricted",
                        retryAfter:
                            Math.ceil(
                                cooldownRemaining / 1000
                            )
                    });
            }

            /* IP BLACKLIST */

            const blacklist =
                await pool.query(`
                    SELECT id
                    FROM admin_ip_blacklist
                    WHERE ip_hash = $1
                      AND (
                          expires_at IS NULL
                          OR expires_at > NOW()
                      )
                    LIMIT 1
                `, [
                    ipHash
                ]);

            if (blacklist.rowCount) {
                await pool.query(`
                    INSERT INTO admin_login_logs (
                        ip_hash,
                        successful,
                        reason,
                        created_at
                    )
                    VALUES ($1, FALSE, 'blocked', NOW())
                `, [
                    ipHash
                ]);

                return res.status(429).json({
                    success: false,
                    error: "IP blocked"
                });
            }

            const submittedCode =
                req.body?.code || "";

            /* WRONG CODE */

            if (
                !safeCodeMatch(
                    submittedCode,
                    ADMIN_LOGIN_CODE
                )
            ) {
                await pool.query(`
                    INSERT INTO admin_login_logs (
                        ip_hash,
                        successful,
                        reason,
                        created_at
                    )
                    VALUES ($1, FALSE, 'invalid_code', NOW())
                `, [
                    ipHash
                ]);

                recordGlobalAdminFailure();

                const failureResult =
                    await pool.query(`
                        SELECT COUNT(*)::int AS count
                        FROM admin_login_logs
                        WHERE ip_hash = $1
                          AND successful = FALSE
                          AND reason = 'invalid_code'
                          AND created_at >=
                              NOW() - INTERVAL '15 minutes'
                    `, [
                        ipHash
                    ]);

                const count =
                    failureResult.rows[0]?.count || 0;

                if (count >= 5) {
                    await pool.query(`
                        INSERT INTO admin_ip_blacklist (
                            ip_hash,
                            reason,
                            expires_at,
                            created_at
                        )
                        VALUES (
                            $1,
                            'Automatic block after 5 failed login attempts',
                            NOW() + INTERVAL '15 minutes',
                            NOW()
                        )
                        ON CONFLICT (ip_hash)
                        DO UPDATE SET
                            reason = EXCLUDED.reason,
                            expires_at = EXCLUDED.expires_at
                    `, [
                        ipHash
                    ]);

                    await pool.query(`
                        INSERT INTO admin_login_logs (
                            ip_hash,
                            successful,
                            reason,
                            created_at
                        )
                        VALUES ($1, FALSE, 'blocked', NOW())
                    `, [
                        ipHash
                    ]);

                    return res.status(429).json({
                        success: false,
                        error:
                            "IP temporarily blocked"
                    });
                }

                return res.status(401).json({
                    success: false,
                    error: "Invalid code"
                });
            }

            /* SUCCESSFUL LOGIN */

            const session =
                await createAdminSession();

            await pool.query(`
                INSERT INTO admin_login_logs (
                    ip_hash,
                    successful,
                    reason,
                    created_at
                )
                VALUES ($1, TRUE, 'approved', NOW())
            `, [
                ipHash
            ]);

            await pool.query(`
                INSERT INTO admin_approved_logins (
                    ip_hash,
                    reason,
                    session_id,
                    created_at
                )
                VALUES ($1, 'valid_code', $2, NOW())
            `, [
                ipHash,
                session.id
            ]);

            return res
                .cookie(
                    "corehub_admin",
                    session.token,
                    {
                        httpOnly: true,
                        secure: true,
                        sameSite: "none",
                        maxAge:
                            8 * 60 * 60 * 1000,
                        path: "/"
                    }
                )
                .json({
                    success: true,
                    authenticated: true,
                    admin: {
                        role: "admin"
                    }
                });
        } catch (error) {
            console.error(
                "Admin login error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Login failed"
            });
        }
    }
);

/* =========================================================
   ADMIN ME
========================================================= */

app.get(
    "/api/admin/auth/me",
    requireAdmin,
    async (req, res) => {
        res.json({
            success: true,
            authenticated: true,
            admin: {
                role: "admin"
            }
        });
    }
);

/* =========================================================
   ADMIN LOGOUT
========================================================= */

app.post(
    "/api/admin/auth/logout",
    requireAdmin,
    async (req, res) => {
        try {
            const token =
                req.cookies.corehub_admin;

            if (token) {
                await pool.query(`
                    DELETE FROM admin_sessions
                    WHERE token_hash = $1
                `, [
                    hashToken(token)
                ]);
            }

            res.clearCookie(
                "corehub_admin",
                {
                    httpOnly: true,
                    secure: true,
                    sameSite: "none",
                    path: "/"
                }
            );

            res.json({
                success: true
            });
        } catch (error) {
            console.error(
                "Logout error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Logout failed"
            });
        }
    }
);

/* =========================================================
   ADMIN SECURITY LOGS
========================================================= */

app.get(
    "/api/admin/security/logins",
    requireAdmin,
    async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT
                    id,
                    ip_hash,
                    successful,
                    reason,
                    created_at
                FROM admin_login_logs
                ORDER BY created_at DESC
                LIMIT 200
            `);

            res.json({
                success: true,
                logs: result.rows
            });
        } catch (error) {
            console.error(
                "Security logs error:",
                error.message
            );

            res.status(500).json({
                success: false,
                logs: []
            });
        }
    }
);

/* =========================================================
   APPROVED LOGINS
========================================================= */

app.get(
    "/api/admin/security/approved",
    requireAdmin,
    async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT
                    id,
                    ip_hash,
                    reason,
                    session_id,
                    created_at
                FROM admin_approved_logins
                ORDER BY created_at DESC
                LIMIT 200
            `);

            const countResult =
                await pool.query(`
                    SELECT COUNT(*)::int AS count
                    FROM admin_approved_logins
                    WHERE created_at >=
                        NOW() - INTERVAL '90 days'
                `);

            res.json({
                success: true,
                approved: result.rows,
                count:
                    countResult.rows[0].count
            });
        } catch (error) {
            console.error(
                "Approved logins error:",
                error.message
            );

            res.status(500).json({
                success: false,
                approved: [],
                count: 0
            });
        }
    }
);

/* =========================================================
   BLACKLIST
========================================================= */

app.get(
    "/api/admin/security/blacklist",
    requireAdmin,
    async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT
                    id,
                    ip_hash,
                    reason,
                    expires_at,
                    created_at
                FROM admin_ip_blacklist
                WHERE expires_at IS NULL
                   OR expires_at > NOW()
                ORDER BY created_at DESC
            `);

            res.json({
                success: true,
                blacklist: result.rows
            });
        } catch (error) {
            console.error(
                "Blacklist error:",
                error.message
            );

            res.status(500).json({
                success: false,
                blacklist: []
            });
        }
    }
);

app.post(
    "/api/admin/security/blacklist",
    requireAdmin,
    async (req, res) => {
        try {
            const {
                ipHash,
                reason,
                durationMinutes
            } = req.body;

            if (!ipHash) {
                return res.status(400).json({
                    success: false,
                    error: "Missing ipHash"
                });
            }

            let minutes =
                Number(durationMinutes) || 60;

            minutes = Math.max(
                1,
                Math.min(
                    minutes,
                    30 * 24 * 60
                )
            );

            await pool.query(`
                INSERT INTO admin_ip_blacklist (
                    ip_hash,
                    reason,
                    expires_at,
                    created_at
                )
                VALUES (
                    $1,
                    $2,
                    NOW() +
                        ($3 * INTERVAL '1 minute'),
                    NOW()
                )
                ON CONFLICT (ip_hash)
                DO UPDATE SET
                    reason = EXCLUDED.reason,
                    expires_at = EXCLUDED.expires_at
            `, [
                ipHash,
                reason || "Manual admin block",
                minutes
            ]);

            res.json({
                success: true
            });
        } catch (error) {
            console.error(
                "Manual blacklist error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Failed to block IP"
            });
        }
    }
);

app.delete(
    "/api/admin/security/blacklist/:ipHash",
    requireAdmin,
    async (req, res) => {
        try {
            await pool.query(`
                DELETE FROM admin_ip_blacklist
                WHERE ip_hash = $1
            `, [
                req.params.ipHash
            ]);

            res.json({
                success: true
            });
        } catch (error) {
            console.error(
                "Unblock error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Failed to unblock IP"
            });
        }
    }
);

/* =========================================================
   ADMIN GAMES
========================================================= */

app.get(
    "/api/admin/games",
    requireAdmin,
    async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT
                    id,
                    url,
                    name,
                    status,
                    game_id,
                    category,
                    created_at
                FROM games
                ORDER BY created_at DESC
            `);

            res.json({
                success: true,
                games: result.rows
            });
        } catch (error) {
            console.error(
                "Admin games error:",
                error.message
            );

            res.status(500).json({
                success: false,
                games: []
            });
        }
    }
);

app.get(
    "/api/admin/games/:gameId",
    requireAdmin,
    async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT
                    id,
                    url,
                    name,
                    status,
                    game_id,
                    category,
                    created_at
                FROM games
                WHERE game_id = $1
                LIMIT 1
            `, [
                req.params.gameId
            ]);

            if (!result.rowCount) {
                return res.status(404).json({
                    success: false,
                    error: "Game not found"
                });
            }

            res.json({
                success: true,
                game: result.rows[0]
            });
        } catch (error) {
            console.error(
                "Admin single game error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Failed to load game"
            });
        }
    }
);

app.post(
    "/api/admin/games",
    requireAdmin,
    async (req, res) => {
        try {
            const {
                gameId,
                name,
                url,
                category,
                status
            } = req.body;

            if (!gameId || !name || !url) {
                return res.status(400).json({
                    success: false,
                    error:
                        "gameId, name and url are required"
                });
            }

            await pool.query(`
                INSERT INTO games (
                    game_id,
                    name,
                    url,
                    status,
                    category,
                    created_at
                )
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5,
                    NOW()
                )
            `, [
                gameId,
                name,
                url,
                status || "online",
                category || null
            ]);

            res.status(201).json({
                success: true
            });
        } catch (error) {
            console.error(
                "Admin create game error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Failed to create game"
            });
        }
    }
);

app.put(
    "/api/admin/games/:gameId",
    requireAdmin,
    async (req, res) => {
        try {
            const {
                name,
                url,
                category,
                status
            } = req.body;

            const result = await pool.query(`
                UPDATE games
                SET
                    name = COALESCE($1, name),
                    url = COALESCE($2, url),
                    category = COALESCE($3, category),
                    status = COALESCE($4, status)
                WHERE game_id = $5
            `, [
                name || null,
                url || null,
                category || null,
                status || null,
                req.params.gameId
            ]);

            if (!result.rowCount) {
                return res.status(404).json({
                    success: false,
                    error: "Game not found"
                });
            }

            res.json({
                success: true
            });
        } catch (error) {
            console.error(
                "Admin update game error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Failed to update game"
            });
        }
    }
);

app.delete(
    "/api/admin/games/:gameId",
    requireAdmin,
    async (req, res) => {
        try {
            const result = await pool.query(`
                DELETE FROM games
                WHERE game_id = $1
            `, [
                req.params.gameId
            ]);

            if (!result.rowCount) {
                return res.status(404).json({
                    success: false,
                    error: "Game not found"
                });
            }

            res.json({
                success: true
            });
        } catch (error) {
            console.error(
                "Admin delete game error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Failed to delete game"
            });
        }
    }
);

/* =========================================================
   ADMIN NEWS
========================================================= */

app.get(
    "/api/admin/news",
    requireAdmin,
    async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT
                    id,
                    type,
                    title,
                    content,
                    featured,
                    published,
                    created_at
                FROM news
                ORDER BY created_at DESC
            `);

            res.json({
                success: true,
                news: result.rows
            });
        } catch (error) {
            console.error(
                "Admin news error:",
                error.message
            );

            res.status(500).json({
                success: false,
                news: []
            });
        }
    }
);

app.post(
    "/api/admin/news",
    requireAdmin,
    async (req, res) => {
        try {
            const {
                type,
                title,
                content,
                featured,
                published
            } = req.body;

            if (!title || !content) {
                return res.status(400).json({
                    success: false,
                    error:
                        "title and content are required"
                });
            }

            await pool.query(`
                INSERT INTO news (
                    type,
                    title,
                    content,
                    featured,
                    published,
                    created_at
                )
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5,
                    NOW()
                )
            `, [
                type || "Update",
                title,
                content,
                Boolean(featured),
                published !== false
            ]);

            res.status(201).json({
                success: true
            });
        } catch (error) {
            console.error(
                "Admin create news error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Failed to create news"
            });
        }
    }
);

app.put(
    "/api/admin/news/:id",
    requireAdmin,
    async (req, res) => {
        try {
            const {
                type,
                title,
                content,
                featured,
                published
            } = req.body;

            const result = await pool.query(`
                UPDATE news
                SET
                    type = COALESCE($1, type),
                    title = COALESCE($2, title),
                    content = COALESCE($3, content),
                    featured = COALESCE($4, featured),
                    published = COALESCE($5, published)
                WHERE id = $6
            `, [
                type || null,
                title || null,
                content || null,
                typeof featured === "boolean"
                    ? featured
                    : null,
                typeof published === "boolean"
                    ? published
                    : null,
                req.params.id
            ]);

            if (!result.rowCount) {
                return res.status(404).json({
                    success: false,
                    error: "News post not found"
                });
            }

            res.json({
                success: true
            });
        } catch (error) {
            console.error(
                "Admin update news error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Failed to update news"
            });
        }
    }
);

app.delete(
    "/api/admin/news/:id",
    requireAdmin,
    async (req, res) => {
        try {
            const result = await pool.query(`
                DELETE FROM news
                WHERE id = $1
            `, [
                req.params.id
            ]);

            if (!result.rowCount) {
                return res.status(404).json({
                    success: false,
                    error: "News post not found"
                });
            }

            res.json({
                success: true
            });
        } catch (error) {
            console.error(
                "Admin delete news error:",
                error.message
            );

            res.status(500).json({
                success: false,
                error: "Failed to delete news"
            });
        }
    }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {
    console.error(
        "Unhandled error:",
        err.message
    );

    res.status(500).json({
        success: false,
        error: "Internal server error"
    });
});

/* =========================================================
   START
========================================================= */

app.listen(PORT, () => {
    console.log(
        `Core Hub API running on port ${PORT}`
    );
});

