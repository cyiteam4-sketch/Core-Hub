require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;

// ===============================
// DATABASE
// ===============================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// ===============================
// MIDDLEWARE
// ===============================

app.use(cors({
    origin: process.env.CORS_ORIGIN || "*"
}));

app.use(express.json());

// ===============================
// HEALTH
// ===============================

app.get("/api/health", (req, res) => {
    res.json({
        status: "ok",
        service: "Core Hub API"
    });
});

// ===============================
// GAMES
// ===============================

// GET ALL GAMES
app.get("/api/games", async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                game_id,
                name,
                category,
                url,
                status
            FROM games
            ORDER BY id DESC
        `);

        res.json({
            success: true,
            games: result.rows
        });

    } catch (error) {
        console.error("GAMES ERROR:", error);

        res.status(500).json({
            success: false,
            error: "Database error"
        });
    }
});

// GET ONE GAME
app.get("/api/games/:gameId", async (req, res) => {
    try {
        const result = await pool.query(
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
        console.error("GAME ERROR:", error);

        res.status(500).json({
            success: false,
            error: "Database error"
        });
    }
});

// ===============================
// GAME LAUNCHES
// ===============================

// RECORD GAME LAUNCH
app.post("/api/games/:gameId/launch", async (req, res) => {
    try {
        const gameId = req.params.gameId;
        const sessionId = req.body?.sessionId || null;

        await pool.query(
            `
            INSERT INTO game_launches
                (game_id, session_id)
            VALUES
                ($1, $2)
            `,
            [gameId, sessionId]
        );

        res.json({
            success: true,
            gameId
        });

    } catch (error) {
        console.error("LAUNCH ERROR:", error);

        res.status(500).json({
            success: false,
            error: "Could not record launch"
        });
    }
});

// ===============================
// GAME STATS
// ===============================

app.get("/api/games/:gameId/stats", async (req, res) => {
    try {
        const result = await pool.query(
            `
            SELECT
                COUNT(*)::int AS total_launches,

                COUNT(*) FILTER (
                    WHERE created_at >= NOW() - INTERVAL '24 hours'
                )::int AS launches_today,

                COUNT(*) FILTER (
                    WHERE created_at >= NOW() - INTERVAL '7 days'
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
        console.error("STATS ERROR:", error);

        res.status(500).json({
            success: false,
            error: "Database error"
        });
    }
});

// ===============================
// TRENDING
// ===============================

app.get("/api/trending", async (req, res) => {
    try {
        const limit = Math.min(
            Number.parseInt(req.query.limit) || 10,
            50
        );

        const result = await pool.query(
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
                AND l.created_at >= NOW() - INTERVAL '7 days'

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
        console.error("TRENDING ERROR:", error);

        res.status(500).json({
            success: false,
            error: "Database error"
        });
    }
});

// ===============================
// NEWS
// ===============================

app.get("/api/news", async (req, res) => {
    try {
        const limit = Math.min(
            Number.parseInt(req.query.limit) || 20,
            50
        );

        const result = await pool.query(
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
        console.error("NEWS ERROR:", error);

        res.status(500).json({
            success: false,
            error: "Database error"
        });
    }
});

// ===============================
// 404
// ===============================

app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: "Endpoint not found"
    });
});

// ===============================
// START SERVER
// ===============================

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Core Hub API running on port ${PORT}`);
});
