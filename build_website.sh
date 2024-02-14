#!/bin/bash -e

if [ "$1" != "local" ]; then
    echo "Install Deno"
    curl -fsSL https://deno.land/install.sh | sh
    export PATH=~/.deno/bin:$PATH

    deno install -f --name silverbullet --unstable -A https://edge.silverbullet.md/silverbullet.js
fi

silverbullet plug:run . pub.publishAll
cp _headers _public/
deno bundle silverbullet-pub-server.ts > silverbullet-pub-server.js