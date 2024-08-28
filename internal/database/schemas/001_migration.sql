-- +goose Up
-- +goose StatementBegin
-- Table: Users
CREATE TABLE Users (
  user_id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  email TEXT NOT NULL,
  ip_address TEXT
);

-- Table: Tokens
CREATE TABLE Tokens (
  token_id BIGSERIAL PRIMARY KEY,
  user_id UUID REFERENCES Users(user_id),
  refresh_token_hash TEXT NOT NULL,
  ip_address_issue TEXT,
  refreshed BOOL NOT NULL DEFAULT FALSE
);
-- Add index
CREATE INDEX tokens_user_id ON Tokens (user_id);
CREATE INDEX tokens_refresh_token_hash ON Tokens (refresh_token_hash);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE Tokens;
DROP TABLE Users;
-- +goose StatementEnd
