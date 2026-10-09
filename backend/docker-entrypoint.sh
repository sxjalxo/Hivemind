#!/bin/sh
# Bring the schema up to date, then hand off to the server.
#
# `set -e` matters here: if the migration fails the container must NOT start
# serving. A backend running against a schema it does not match fails later,
# further away, and as something that looks like a code bug.
#
# The app's own lifespan handles the Elasticsearch bootstrap and the corpus
# seed; only Alembic is missing from it, because a process that migrates the
# database on startup races every other replica that does the same. One
# container is one replica today, and `exec` below keeps it that way -- if
# this ever scales out, the migration moves to a one-shot job and comes out
# of here.
set -e

echo "entrypoint: applying database migrations"
alembic upgrade head

echo "entrypoint: starting $*"
exec "$@"
