#!/bin/sh
# For every VAR_FILE=/absolute/path to a readable file, export VAR with the file's content and
# drop VAR_FILE, then exec the service. Lets compose pass secrets as files to services that
# only read plain environment variables.
set -eu
file=""
for name in $(env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)_FILE=\/.*/\1/p'); do
  # name matches [A-Za-z_][A-Za-z0-9_]*, so eval only expands a variable
  eval "file=\${${name}_FILE}"
  [ -r "$file" ] || continue
  value=$(cat "$file")
  export "$name=$value"
  unset "${name}_FILE"
done
exec "$@"
