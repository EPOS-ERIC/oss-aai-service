# OSS AAAI Auth Service

Small Go application that provides:
- User registration and login (HTML templates)
- Session-based web authentication
- OAuth2/OIDC-style token issuance, introspection and user info
- Local persistence with SQLite (`data/auth.db`)

## Quick start

```bash
make build
make run
```

Open: `http://localhost:8080`

## Run with Docker

```bash
docker build -t oss-aaai .
docker run --rm -p 8080:8080 oss-aaai
```

If you want persistent local data when using Docker:

```bash
docker run --rm -p 8080:8080 -v $(pwd)/data:/app/data oss-aaai
```

## Default seeded accounts

- Initial user (created once):
  - Name: `Admin`
  - Surname: `Admin`
  - Email: `admin@admin.org`
  - Password: `adminadmin` (or set `INITIAL_ADMIN_PASSWORD` before first run)
- OAuth client:
  - `client_id`: `local-dev-client`
  - `client_secret`: `dev-secret`

The initial admin user can be updated or deleted after first login and will not be recreated.

## Environment variables

- `INITIAL_ADMIN_PASSWORD` - password used for the seeded admin user (only on first initialization)
- `APP_SECURE_COOKIES=true` - forces the `Secure` cookie flag (recommended behind HTTPS)
- `OIDC_ISSUER` - overrides issuer URL in OIDC discovery metadata

## Main endpoints

- Web UI:
  - `GET /register`
  - `GET /login`
  - `GET /` (requires login)
- OAuth/API:
  - `POST /oauth/token`
  - `GET /oauth/validate`
  - `GET /api/me`
  - `POST /oauth2/token`
  - `POST /oauth2/introspect`
  - `POST /oauth2/revoke`
  - `GET /oauth2/userinfo`
  - `GET /oauth2/jwk`
  - `GET /oauth2/.well-known/openid-configuration`
  - `GET /.well-known/openid-configuration`

## OIDC discovery example

```bash
curl http://localhost:8080/oauth2/.well-known/openid-configuration
```

The validation/introspection response includes:
- `active`
- `eduPersonUniqueId`
- `firstname`
- `lastName`
- `email`
- `exp`

## Token example

```bash
curl -X POST http://localhost:8080/oauth/token \
  -u local-dev-client:dev-secret \
  -d "grant_type=password" \
  -d "username=admin@admin.org" \
  -d "password=adminadmin"
```

## Make targets

- `make run` - run app
- `make build` - build binary to `bin/oss-aaai`
- `make test` - run tests
- `make fmt` - format Go files
- `make tidy` - tidy Go modules
- `make clean` - remove `bin/`
