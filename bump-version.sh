#!/bin/sh
# Run before each commit: stamps a new build id so open apps reload into the new version.
B=$(date -u +%Y%m%d%H%M%S)
sed -i "s/const APP_BUILD = '[^']*';/const APP_BUILD = '$B';/" index.html
printf '%s\n' "$B" > version.txt
echo "build $B"
