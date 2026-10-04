#!/usr/bin/env bash
# Fails if the README's demo block differs from what the built jar prints.
set -euo pipefail
cd "$(dirname "$0")/.."
jar=${NGINXWARDEN_JAR:-build/libs/nginxwarden.jar}
expected=$(awk '/<!-- demo:start -->/{f=1;next} /<!-- demo:end -->/{f=0} f' README.md | sed '1d;$d')
# exit 1 is expected: the fixture has findings at or above the default level;
# the include note goes to stderr, which is not part of the example.
actual=$( (java -jar "$jar" scan --brief testdata/vulnerable 2>/dev/null || test $? -eq 1) | tr -d '\r')
if [ "$expected" != "$actual" ]; then
  diff <(echo "$expected") <(echo "$actual") || true
  echo "README demo is out of date" >&2
  exit 1
fi
echo "README demo matches"
