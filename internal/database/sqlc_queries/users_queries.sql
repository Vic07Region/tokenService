-- name: FetchUser :one
    SElECT * FROM Users WHERE
    user_id = sqlc.arg(user_id) LIMIT 1;