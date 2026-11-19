CREATE TABLE customer_account (
    id BIGSERIAL PRIMARY KEY,
    rainyun_uid BIGINT NOT NULL UNIQUE,
    rainyun_name VARCHAR(160) NOT NULL,
    email VARCHAR(254),
    api_key_ciphertext TEXT NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX idx_customer_account_name ON customer_account (rainyun_name);

CREATE TABLE oauth_client (
    id BIGSERIAL PRIMARY KEY,
    client_id VARCHAR(80) NOT NULL UNIQUE,
    display_name VARCHAR(160) NOT NULL,
    client_secret_hash VARCHAR(256),
    redirect_uris TEXT NOT NULL,
    allowed_scopes TEXT NOT NULL,
    public_client BOOLEAN NOT NULL DEFAULT FALSE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE oauth_authorization_code (
    id BIGSERIAL PRIMARY KEY,
    code_hash VARCHAR(64) NOT NULL UNIQUE,
    client_id VARCHAR(80) NOT NULL,
    customer_uid BIGINT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge VARCHAR(128) NOT NULL,
    code_challenge_method VARCHAR(16) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX idx_oauth_code_expiry ON oauth_authorization_code (expires_at);

CREATE TABLE oauth_access_token (
    id BIGSERIAL PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    client_id VARCHAR(80) NOT NULL,
    customer_uid BIGINT NOT NULL,
    scopes TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX idx_oauth_token_customer ON oauth_access_token (customer_uid);
