require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
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
// MIDDLEWARE
// ============================================================

const allowedOrigins = (process.env.CORS_ORIGIN || "*")
    .split(",")
    .map(origin => origin.trim())
    .filter(Boolean);

app.use(
    cors({
        origin: (origin, callback) => {

            // Requests without an Origin header
            // are allowed for tools/server-to-server calls.
            if (!origin) {
                return callback(null, true);
            }

            // Temporary open CORS mode.
            // Set CORS_ORIGIN later for production lockdown.
            if (allowedOrigins.includes("*")) {
                return callback(null, true);
            }

            if (allowedOrigins.includes(origin)) {
                return callback(null, true);
            }

            return callback(new Error("CORS blocked"));
        },

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
// RATE LIMITER
// ============================================================

const rateLimits = new Map();

function getClientKey(req) {

    const forwarded =
        req.headers["x-forwarded-for"];

    if (forwarded) {

        return String(forwarded)
            .split(",")[0]
            .trim();
    }

    return (
        req.socket.remoteAddress ||
        "unknown"
    );
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
            error: "Too many requests"
        });
    }

    next();
}

app.use(
    "/api",
    rateLimit
);

// Cleanup old rate-limit records.

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
// HELPERS
// ============================================================

function hashToken(token) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function createToken() {

    return crypto
        .randomBytes(32)
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
// ROUTE MAP
// ============================================================

/*

PUBLIC API
----------

GET    /api/health

POST   /api/sessions
POST   /api/sessions/heartbeat

GET    /api/online
GET    /api/online/games

GET    /api/games
GET    /api/games/:gameId
POST   /api/games/:gameId/launch
GET    /api/games/:gameId/stats

GET    /api/trending

GET    /api/news


FUTURE ADMIN API
----------------

POST   /api/admin/auth/login
POST   /api/admin/auth/logout
GET    /api/admin/auth/me

GET    /api/admin/games
POST   /api/admin/games
PUT    /api/admin/games/:gameId
DELETE /api/admin/games/:gameId

GET    /api/admin/news
POST   /api/admin/news
PUT    /api/admin/news/:id
DELETE /api/admin/news/:id

These routes are reserved now so the
admin panel can be added cleanly later.

*/

// ============================================================
// GUEST SESSIONS
// ============================================================

// CREATE GUEST SESSION

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

            if (gameId !== null) {

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

// GET ALL GAMES

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

// GET ONE GAME

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
                    Number.isFinite(requestedLimit)
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

                    ORDER BY
                        launch_count DESC

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

// PUBLIC NEWS FEED
//
// This is the endpoint the public
// Core Hub Games News page will use.

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
                    Number.isFinite(requestedLimit)
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
// FUTURE ADMIN AUTH
// ============================================================
//
// Reserved for the separate admin panel.
//
// Planned:
// POST /api/admin/auth/login
// POST /api/admin/auth/logout
// GET  /api/admin/auth/me
//
// The actual admin authentication should be
// implemented server-side before these routes
// are used in production.
//
// ============================================================

app.post(
    `${ADMIN_ROUTE_PREFIX}/auth/login`,
    (req, res) => {

        res.status(501).json({
            success: false,
            error:
                "Admin authentication is not enabled yet"
        });
    }
);

app.post(
    `${ADMIN_ROUTE_PREFIX}/auth/logout`,
    (req, res) => {

        res.status(501).json({
            success: false,
            error:
                "Admin authentication is not enabled yet"
        });
    }
);

app.get(
    `${ADMIN_ROUTE_PREFIX}/auth/me`,
    (req, res) => {

        res.status(501).json({
            success: false,
            error:
                "Admin authentication is not enabled yet"
        });
    }
);

// ============================================================
// FUTURE ADMIN GAMES
// ============================================================

app.get(
    `${ADMIN_ROUTE_PREFIX}/games`,
    (req, res) => {

        res.status(501).json({
            success: false,
            error:
                "Admin games API is not enabled yet"
        });
    }
);

app.post(
    `${ADMIN_ROUTE_PREFIX}/games`,
    (req, res) => {

        res.status(501).json({
            success: false,
            error:
                "Admin games API is not enabled yet"
        });
    }
);

app.put(
    `${ADMIN_ROUTE_PREFIX}/games/:gameId`,
    (req, res) => {

        res.status(501).json({
            success: false,
            error:
                "Admin games API is not enabled yet"
        });
    }
);

app.delete(
    `${ADMIN_ROUTE_PREFIX}/games/:gameId`,
    (req, res) => {

        res.status(501).json({
            success: false,
            error:
                "Admin games API is not enabled yet"
        });
    }
);

// ============================================================
// FUTURE ADMIN NEWS
// ============================================================

app.get(
    `${ADMIN_ROUTE_PREFIX}/news`,
    (req, res) => {

        res.status(501).json({
            success: false,
            error:
                "Admin news API is not enabled yet"
        });
    }
);

app.post(
    `${ADMIN_ROUTE_PREFIX}/news`,
    (req, res) => {

        res.status(501).json({
            success: false,
            error:
                "Admin news API is not enabled yet"
        });
    }
);

app.put(
    `${ADMIN_ROUTE_PREFIX}/news/:id`,
    (req, res) => {

        res.status(501).json({
            success: false,
            error:
                "Admin news API is not enabled yet"
        });
    }
);

app.delete(
    `${ADMIN_ROUTE_PREFIX}/news/:id`,
    (req, res) => {

        res.status(501).json({
            success: false,
            error:
                "Admin news API is not enabled yet"
        });
    }
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

const server =
    app.listen(
        PORT,
        "0.0.0.0",
        () => {

            console.log(
                `Core Hub API running on port ${PORT}`
            );

            console.log(
                `Public API ready at port ${PORT}`
            );

            console.log(
                `Future admin API reserved at ${ADMIN_ROUTE_PREFIX}`
            );
        }
    );

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

async function shutdown(signal) {

    console.log(
        `${signal} received. Shutting down...`
    );

    server.close(async () => {

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
    });
}

process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);
