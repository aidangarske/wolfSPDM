#!/bin/sh

set -e

echo "Running autoreconf..."
autoreconf -i -f

echo ""
echo "Now run ./configure && make"
