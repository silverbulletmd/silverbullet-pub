#!/bin/bash -e

if [ "$1" != "local" ]; then
    echo "Install Deno"
    curl -fsSL https://deno.land/install.sh | sh
    export PATH=~/.deno/bin:$PATH
fi

SB_DB_BACKEND=memory deno run --unstable-kv --unstable-worker-options -A https://edge.silverbullet.md/silverbullet.js plug:run . pub.publishAll
cp _headers _public/

deno bundle silverbullet-pub-server.ts > silverbullet-pub-server.js