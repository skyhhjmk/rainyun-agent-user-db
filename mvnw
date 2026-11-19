#!/bin/sh
set -eu
MAVEN_VERSION=3.9.11
MAVEN_HOME_DIR="${MAVEN_USER_HOME:-${HOME:?}/.m2}/wrapper/dists/apache-maven-${MAVEN_VERSION}"
MAVEN_BIN="${MAVEN_HOME_DIR}/apache-maven-${MAVEN_VERSION}/bin/mvn"
if [ ! -x "$MAVEN_BIN" ]; then
  mkdir -p "$MAVEN_HOME_DIR"
  ARCHIVE="${MAVEN_HOME_DIR}/apache-maven-${MAVEN_VERSION}-bin.zip"
  if [ ! -f "$ARCHIVE" ]; then
    curl -fL --retry 3 "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/${MAVEN_VERSION}/apache-maven-${MAVEN_VERSION}-bin.zip" -o "$ARCHIVE"
  fi
  unzip -q -o "$ARCHIVE" -d "$MAVEN_HOME_DIR"
fi
exec "$MAVEN_BIN" "$@"
