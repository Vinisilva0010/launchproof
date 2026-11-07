#!/usr/bin/env bash
# Builds the static site into web/dist. LP_API_URL sets the API address.
set -euo pipefail
cd "$(dirname "$0")"
API_URL="${LP_API_URL:-http://localhost:8080}"
CLEAN=$(node -p "JSON.parse(require('fs').readFileSync('demo-mints.json','utf8')).clean")
BUNDLED=$(node -p "JSON.parse(require('fs').readFileSync('demo-mints.json','utf8')).bundled")
[ -d node_modules ] || npm install --no-audit --no-fund
rm -rf dist && mkdir -p dist
npx esbuild src/app.ts --bundle --minify --format=esm --target=es2020 --outfile=dist/app.js \
  --define:__API_URL__="\"$API_URL\"" \
  --define:__DEMO_CLEAN__="\"$CLEAN\"" \
  --define:__DEMO_BUNDLED__="\"$BUNDLED\""
cp index.html style.css dist/
[ -d assets ] && cp -r assets dist/
echo "built web/dist for API $API_URL"
