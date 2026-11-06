-- Cached investigation reports, one row per network and mint.
CREATE TABLE IF NOT EXISTS reports (
    network    TEXT        NOT NULL,
    mint       TEXT        NOT NULL,
    report     TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (network, mint)
);
