CREATE TABLE IF NOT EXISTS games (
    id SERIAL PRIMARY KEY,
    game_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    category VARCHAR(100),
    url TEXT NOT NULL,
    status VARCHAR(30) DEFAULT 'online',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS game_launches (
    id BIGSERIAL PRIMARY KEY,
    game_id VARCHAR(100) NOT NULL REFERENCES games(game_id) ON DELETE CASCADE,
    session_id VARCHAR(200),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_game_launches_game
ON game_launches(game_id);

CREATE INDEX IF NOT EXISTS idx_game_launches_date
ON game_launches(created_at);
