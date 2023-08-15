#!/bin/bash -e

if [ "$1" != "local" ]; then
    echo "Install Deno"
    curl -fsSL https://deno.land/install.sh | sh
    export PATH=~/.deno/bin:$PATH
    mkdir -p $DENO_DIR

    deno install -f --name silverbullet --unstable -A https://silverbullet.md/silverbullet.js
fi

deno task pub