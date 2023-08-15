#!/bin/bash -e

if [ "$1" != "local" ]; then
    echo "Install Deno"
    curl -fsSL https://deno.land/install.sh | sh
    export PATH=~/.deno/bin:$PATH

    deno install -f --name silverbullet --unstable -A https://silverbullet.md/silverbullet.js
fi

silverbullet plug:run . publish.publishAll
cp _headers _public/