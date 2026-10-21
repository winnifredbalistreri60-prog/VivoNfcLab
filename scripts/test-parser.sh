#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
KOTLINC="${KOTLINC:-kotlinc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
"$KOTLINC" app/src/main/java/dev/vivonfclab/DumpParser.kt app/src/main/java/dev/vivonfclab/TagComparator.kt \
    app/src/test/java/dev/vivonfclab/DumpParserTest.kt app/src/test/java/dev/vivonfclab/TagComparatorTest.kt \
    -d "$TMP/test.jar"
kotlin -classpath "$TMP/test.jar" dev.vivonfclab.DumpParserTest
kotlin -classpath "$TMP/test.jar" dev.vivonfclab.TagComparatorTest
