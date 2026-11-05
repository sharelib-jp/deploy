#!/usr/bin/env bash
set -euo pipefail

# The official image runs this only when the data volume is empty.
psql --no-psqlrc --set=ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    --set=auth_db="$AUTH_POSTGRES_DB" \
    --set=auth_user="$AUTH_POSTGRES_USER" \
    --set=auth_password="$AUTH_POSTGRES_PASSWORD" \
    --set=repository_db="$REPOSITORY_POSTGRES_DB" \
    --set=repository_user="$REPOSITORY_POSTGRES_USER" \
    --set=repository_password="$REPOSITORY_POSTGRES_PASSWORD" <<'SQL'
CREATE ROLE :"auth_user" LOGIN PASSWORD :'auth_password';
CREATE ROLE :"repository_user" LOGIN PASSWORD :'repository_password';
CREATE DATABASE :"auth_db" OWNER :"auth_user";
CREATE DATABASE :"repository_db" OWNER :"repository_user";
REVOKE ALL ON DATABASE :"auth_db" FROM PUBLIC;
REVOKE ALL ON DATABASE :"repository_db" FROM PUBLIC;
SQL
