#!/usr/bin/env bash
# Builds Authz-ExeC into dist/Authz-ExeC.jar (Git Bash / WSL / Linux / macOS)
set -euo pipefail
cd "$(dirname "$0")"

# --- locate burpsuite.jar (robust under `set -u`; override with BURP_JAR=/path) ---
BURP="${BURP_JAR:-}"
if [ -z "$BURP" ]; then
  who="${USERNAME:-${USER:-}}"
  for c in \
    "${HOME:-}/AppData/Local/Programs/BurpSuitePro/burpsuite.jar" \
    "${HOME:-}/AppData/Local/Programs/BurpSuiteCommunity/burpsuite_community.jar" \
    "/c/Users/${who}/AppData/Local/Programs/BurpSuitePro/burpsuite.jar" \
    "/c/Users/${who}/AppData/Local/Programs/BurpSuiteCommunity/burpsuite_community.jar" \
    "${HOME:-}/BurpSuitePro/burpsuite.jar" \
    "/opt/BurpSuitePro/burpsuite.jar"; do
    [ -n "$c" ] && [ -f "$c" ] && BURP="$c" && break
  done
fi
# last resort: search all user profiles
if [ -z "$BURP" ]; then
  BURP="$(ls /c/Users/*/AppData/Local/Programs/BurpSuite*/burpsuite*.jar 2>/dev/null | head -1 || true)"
fi
[ -z "$BURP" ] && { echo "burpsuite.jar not found; set BURP_JAR=/path/to/burpsuite.jar"; exit 1; }
echo "Burp jar : $BURP"

# --- locate javac >= 17 (prefer a real JDK bin over PATH shim so jar/javap exist) ---
JAVAC=""
for c in "/c/Program Files/Java/jdk-17/bin/javac.exe" "/c/Program Files/Java/jdk-21/bin/javac.exe" \
         "/c/Program Files/Java/jdk-22/bin/javac.exe" "$(command -v javac || true)"; do
  [ -n "$c" ] && [ -x "$c" ] && JAVAC="$c" && break
done
[ -z "$JAVAC" ] && { echo "no javac found"; exit 1; }
BIN="$(dirname "$JAVAC")"
JARTOOL="$BIN/jar"; [ -x "$BIN/jar.exe" ] && JARTOOL="$BIN/jar.exe"
echo "javac    : $JAVAC"

rm -rf out dist && mkdir -p out dist
"$JAVAC" -implicit:none -cp "$BURP" -d out $(find src -name '*.java')
"$JARTOOL" --create --file dist/Authz-ExeC.jar -C out authzmatrix
echo ""
echo "Built: $(pwd)/dist/Authz-ExeC.jar"
echo "Load in Burp: Extensions -> Installed -> Add -> Java -> select the jar."
