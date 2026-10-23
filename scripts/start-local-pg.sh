#!/usr/bin/env bash
set -e

# Starts the local PostgreSQL 16 instance if not already running
if ! pg_isready -h localhost -p 5432 -U caim_ci_admin -d caim_ci_db >/dev/null 2>&1; then
  mkdir -p /var/run/postgresql /tmp/pgdata
  chown -R node:node /var/run/postgresql /tmp/pgdata 2>/dev/null || true
  if [ ! -f /tmp/pgdata/PG_VERSION ]; then
    su node -c "/usr/lib/postgresql/16/bin/initdb -D /tmp/pgdata --auth-local=trust --auth-host=trust -U postgres"
  fi
  su node -c "/usr/lib/postgresql/16/bin/pg_ctl -D /tmp/pgdata -l /tmp/pgdata/logfile -w start" || true
  CI_ADMIN_PW="${CI_DB_PASSWORD:-$(openssl rand -hex 18)}"
  /usr/lib/postgresql/16/bin/psql -U postgres -c "CREATE USER caim_ci_admin WITH SUPERUSER PASSWORD '${CI_ADMIN_PW}';" 2>/dev/null || true
  /usr/lib/postgresql/16/bin/psql -U postgres -c "CREATE DATABASE caim_ci_db OWNER caim_ci_admin;" 2>/dev/null || true
  export DATABASE_URL="postgresql://caim_ci_admin:${CI_ADMIN_PW}@localhost:5432/caim_ci_db"
fi

echo "PostgreSQL 16 is ready."
