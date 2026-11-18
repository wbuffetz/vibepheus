#!/bin/bash
# Copies this case's project into the sandbox folder the run happens in.
set -e
cp -R "$(dirname "$0")/project/." .
