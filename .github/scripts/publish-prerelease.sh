#!/usr/bin/env bash
# Publish the next ${base}-${channel}.N build.
# A previous run can stage a version before `npm view` lists it. Retrying the
# same number then fails with "Cannot publish over previously staged version".
set -euo pipefail

dir="${1:?package dir}"
name="${2:?npm package name}"
channel="${3:?dev or rc}"

base="$(node -p "require('./${dir}/package.json').version")"

# Ask npm on its own, with its exit status kept apart from the parser's. Under
# pipefail, `npm view | node || echo -1` printed node's number AND a second -1
# when npm failed, and `$((latest + 1))` then published `*-channel.-1` or
# republished the current max.
view_err="$(mktemp)"
trap 'rm -f "$view_err"' EXIT
set +e
view_out="$(npm view "$name" versions --json 2>"$view_err")"
view_status=$?
set -e

if [ "$view_status" -ne 0 ]; then
  # A package that has never been published is a valid "none yet" answer.
  # npm reports it as E404 (in the --json body on stdout, or on stderr).
  if printf '%s\n%s\n' "$view_out" "$(cat "$view_err")" | grep -q 'E404'; then
    view_out=""
  else
    echo "npm view ${name} versions failed (exit ${view_status}); refusing to publish." >&2
    cat "$view_err" >&2
    printf '%s\n' "$view_out" >&2
    exit 1
  fi
fi

set +e
latest="$(
  printf '%s' "$view_out" | node -e '
    const fs = require("fs");
    const raw = fs.readFileSync(0, "utf8").trim();
    let versions = [];
    if (raw) {
      try {
        versions = JSON.parse(raw);
      } catch {
        console.error("npm view did not return JSON: " + raw.slice(0, 200));
        process.exit(1);
      }
    }
    const list = Array.isArray(versions) ? versions : [versions];
    const prefix = process.argv[1] + "-" + process.argv[2] + ".";
    const nums = list
      .filter((v) => typeof v === "string" && v.startsWith(prefix))
      .map((v) => v.slice(prefix.length))
      .filter((n) => /^[0-9]+$/.test(n))
      .map(Number);
    console.log(nums.length ? Math.max(...nums) : -1);
  ' "$base" "$channel"
)"
parse_status=$?
set -e

if [ "$parse_status" -ne 0 ] || ! [[ "$latest" =~ ^-?[0-9]+$ ]]; then
  echo "could not read the latest ${base}-${channel}.N of ${name} (got: ${latest}); refusing to publish." >&2
  exit 1
fi
next=$((latest + 1))

cd "$dir"
for _ in 1 2 3 4 5 6; do
  version="${base}-${channel}.${next}"
  echo "Publishing ${name}@${version}"
  node -e '
    const fs = require("fs");
    const pkg = require("./package.json");
    pkg.version = process.argv[1];
    fs.writeFileSync("./package.json", JSON.stringify(pkg, null, 4) + "\n");
  ' "$version"
  set +e
  output="$(pnpm publish --tag "$channel" --provenance --access public --no-git-checks 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output"
  if [ "$status" -eq 0 ]; then
    exit 0
  fi
  if printf '%s\n' "$output" | grep -q 'E409\|previously staged version'; then
    next=$((next + 1))
    continue
  fi
  exit "$status"
done

echo "gave up after staged-version collisions for ${name}" >&2
exit 1
