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

// ============================================================
// DATABASE
// ============================================================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// ============================================================
// MIDDLEWARE
// ============================================================

const allowedOrigins = (process.env.CORS_ORIGIN || "*")
    .split(",")
    .map(origin => origin.trim())
    .filter(Boolean);

app.use(cors({
    origin: (origin, callback) => {

        if (!origin || allowedOrigins.includes("*")) {
            return callback(null, true);
        }

        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        return callback(new Error("CORS blocked"));
    }
}));

app.use(express.json({
    limit: "20kb"
}));

// ============================================================
// BASIC RATE LIMITER
// ============================================================

const rateLimits = new Map();

function getClientKey(req) {

    const forwarded =
        req.headers["x-forwarded-for"];

    const ip =
        forwarded
            ? String(forwarded).split(",")[0].trim()
            : req.socket.remoteAddress || "unknown";

    return ip;
}

function rateLimit(req, res, next) {

    const key = getClientKey(req);
    const now = Date.now();

    let entry = rateLimits.get(key);

    if (!entry || now - entry.start > RATE_LIMIT_WINDOW_MS) {

        entry = {
            start: now,
            count: 0
        };

        rateLimits.set(key, entry);
    }

    entry.count++;

    if (entry.count > RATE_LIMIT_MAX) {

        return res.status(429).json({
            success: false,
            error: "Too many requests"
        });
    }

    next();
}

app.use("/api", rateLimit);

// Clean old in-memory rate-limit entries
setInterval(() => {

    const now = Date.now();

    for (const [key, entry] of rateLimits) {

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

    return crypto.randomBytes(32).toString("hex");
}

function getBearerToken(req) {

    const header =
        req.headers.authorization;

    if (!header) {
        return null;
    }

    if (!header.startsWith("Bearer ")) {
        return null;
    }

    return header.slice(7).trim();
}

// ============================================================
// HEALTH
// ============================================================

app.get("/api/health", async (req, res) => {

    try {

        await pool.query("SELECT 1");

        res.json({
            status: "ok",
            service: "Core Hub API",
            database: "connected"
        });

    } catch (error) {

        console.error("HEALTH ERROR:", error);

        res.status(503).json({
            status: "error",
            service: "Core Hub API",
            database: "unavailable"
        });
    }
});

// ============================================================
// GUEST SESSIONS
// ============================================================

// CREATE GUEST SESSION
app.post("/api/sessions", async (req, res) => {

    try {

        const token = createToken();
        const tokenHash = hashToken(token);

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
            expiresIn: SESSION_TIMEOUT_SECONDS
        });

    } catch (error) {

        console.error(
            "SESSION CREATE ERROR:",
            error
        );

        res.status(500).json({
            success: false,
            error: "Could not create session"
        });
    }
});

// ============================================================
// SESSION AUTHENTICATION
// ============================================================

async function requireSession(req, res, next) {

    try {

        const token =
            getBearerToken(req);

        if (!token || token.length !== 64) {

            return res.status(401).json({
                success: false,
                error: "Invalid or missing session"
            });
        }

        const tokenHash =
            hashToken(token);

        const result =
            await pool.query(
                `
                SELECT
                    id,
                    last_seen
                FROM guest_sessions
                WHERE token_hash = $1
                  AND last_seen >=
                      NOW() - INTERVAL '60 seconds'
                `,
                [tokenHash]
            );

        if (result.rows.length === 0) {

            return res.status(401).json({
                success: false,
                error: "Session expired"
            });
        }

        req.session = result.rows[0];

        next();

    } catch (error) {

        console.error(
            "SESSION AUTH ERROR:",
            error
        );

        res.status(500).json({
            success: false,
            error: "Session validation failed"
        });
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

            await pool.query(
                `
                UPDATE guest_sessions
                SET last_seen = NOW()
                WHERE id = $1
                `,
                [req.session.id]
            );

            res.json({
                success: true,
                expiresIn: SESSION_TIMEOUT_SECONDS
            });

        } catch (error) {

            console.error(
                "HEARTBEAT ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                error: "Heartbeat failed"
            });
        }
    }
);

// ============================================================
// ONLINE USERS
// ============================================================

app.get("/api/online", async (req, res) => {

    try {

        const result =
            await pool.query(
                `
                SELECT COUNT(*)::int AS online
                FROM guest_sessions
                WHERE last_seen >=
                    NOW() - INTERVAL '60 seconds'
                `
            );

        res.json({
            success: true,
            online: result.rows[0].online
        });

    } catch (error) {

        console.error(
            "ONLINE ERROR:",
            error
        );

        res.status(500).json({
            success: false,
            error: "Could not get online users"
        });
    }
});

// ============================================================
// DELETE EXPIRED SESSIONS
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

        if (result.rowCount > 0) {

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
app.get("/api/games", async (req, res) => {

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
            games: result.rows
        });

    } catch (error) {

        console.error(
            "GAMES ERROR:",
            error
        );

        res.status(500).json({
            success: false,
            error: "Database error"
        });
    }
});

// GET ONE GAME
app.get("/api/games/:gameId", async (req, res) => {

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

        if (result.rows.length === 0) {

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
            "GAME ERROR:",
            error
        );

        res.status(500).json({
            success: false,
            error: "Database error"
        });
    }
});

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

            // Verify game actually exists
            const game =
                await pool.query(
                    `
                    SELECT game_id
                    FROM games
                    WHERE game_id = $1
                    `,
                    [gameId]
                );

            if (game.rows.length === 0) {

                return res.status(404).json({
                    success: false,
                    error: "Game not found"
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

            res.json({
                success: true,
                gameId
            });

        } catch (error) {

            console.error(
                "LAUNCH ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                error: "Could not record launch"
            });
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
                gameId: req.params.gameId,
                stats: result.rows[0]
            });

        } catch (error) {

            console.error(
                "STATS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                error: "Database error"
            });
        }
    }
);

// ============================================================
// TRENDING
// ============================================================

app.get("/api/trending", async (req, res) => {

    try {

        const limit =
            Math.min(
                Number.parseInt(
                    req.query.limit
                ) || 10,
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
            games: result.rows
        });

    } catch (error) {

        console.error(
            "TRENDING ERROR:",
            error
        );

        res.status(500).json({
            success: false,
            error: "Database error"
        });
    }
});

// ============================================================
// NEWS
// ============================================================

app.get("/api/news", async (req, res) => {

    try {

        const limit =
            Math.min(
                Number.parseInt(
                    req.query.limit
                ) || 20,
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
            news: result.rows
        });

    } catch (error) {

        console.error(
            "NEWS ERROR:",
            error
        );

        res.status(500).json({
            success: false,
            error: "Database error"
        });
    }
});

// ============================================================
// 404
// ============================================================

app.use((req, res) => {

    res.status(404).json({
        success: false,
        error: "Endpoint not found"
    });
});

// ============================================================
// ERROR HANDLER
// ============================================================

app.use((error, req, res, next) => {

    console.error(
        "SERVER ERROR:",
        error
    );

    res.status(500).json({
        success: false,
        error: "Internal server error"
    });
});

// ============================================================
// START
// ============================================================

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `Core Hub API running on port ${PORT}`
        );
    }
);
