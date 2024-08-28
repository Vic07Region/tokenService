-- name: CreateToken :one
    INSERT INTO Tokens (user_id, refresh_token_hash, ip_address_issue)
    VALUES (sqlc.arg(user_id),
            sqlc.arg(refresh_token_hash),
            sqlc.arg(ip_address_issue)
            )
    RETURNING token_id;

-- name: FetchToken :one
    SElECT * FROM Tokens WHERE
    refresh_token_hash = sqlc.arg(refresh_token_hash) LIMIT 1;


-- name: RefreshedToken :exec
    UPDATE Tokens
    SET refreshed = TRUE
    WHERE token_id = sqlc.arg(token_id);