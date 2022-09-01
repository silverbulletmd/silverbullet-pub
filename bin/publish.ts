#!/usr/bin/env node
import {
  createSandbox,
  nodeModulesDir,
} from "@plugos/plugos/environments/node_sandbox";
import { EventHook } from "@plugos/plugos/hooks/event";
import { eventSyscalls } from "@plugos/plugos/syscalls/event";
import fileSystemSyscalls from "@plugos/plugos/syscalls/fs.node";
import {
  ensureFTSTable,
  fullTextSearchSyscalls,
} from "@plugos/plugos/syscalls/fulltext.knex_sqlite";
import { jwtSyscalls } from "@plugos/plugos/syscalls/jwt";
import sandboxSyscalls from "@plugos/plugos/syscalls/sandbox";
import shellSyscalls from "@plugos/plugos/syscalls/shell.node";
import {
  ensureTable as ensureStoreTable,
  storeSyscalls,
} from "@plugos/plugos/syscalls/store.knex_node";
import { System } from "@plugos/plugos/system";
import { Manifest, SilverBulletHooks } from "@silverbulletmd/common/manifest";
import { loadMarkdownExtensions } from "@silverbulletmd/common/markdown_ext";
import buildMarkdown from "@silverbulletmd/common/parser";
import { DiskSpacePrimitives } from "@silverbulletmd/common/spaces/disk_space_primitives";
import { EventedSpacePrimitives } from "@silverbulletmd/common/spaces/evented_space_primitives";
import { Space } from "@silverbulletmd/common/spaces/space";
import { markdownSyscalls } from "@silverbulletmd/common/syscalls/markdown";
import { PageNamespaceHook } from "@silverbulletmd/server/hooks/page_namespace";
import { PlugSpacePrimitives } from "@silverbulletmd/server/hooks/plug_space_primitives";
import {
  ensureTable as ensureIndexTable,
  pageIndexSyscalls,
} from "@silverbulletmd/server/syscalls";
import spaceSyscalls from "@silverbulletmd/server/syscalls/space";
import { safeRun } from "@silverbulletmd/server/util";
import { readFileSync } from "fs";
import { readdir, readFile } from "fs/promises";
import knex from "knex";
import path from "path";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

import publishPlugManifest from "../dist/publish.plug.json";

const globalModules: any = JSON.parse(
  readFileSync(
    nodeModulesDir + "/node_modules/@silverbulletmd/web/dist/global.plug.json",
    "utf-8"
  )
);

let args = yargs(hideBin(process.argv))
  .option("index", {
    type: "boolean",
    default: false,
  })
  .option("dist", {
    type: "string",
    default: "dist",
  })
  .parse();

if (!args._.length) {
  console.error(
    "Usage: silverbullet-publish [--index] [--dist <path>] <path-to-pages>"
  );
  process.exit(1);
}

const pagesPath = path.resolve(args._[0] as string);

console.log("Pages path", pagesPath);

async function main() {
  // Set up the PlugOS System
  const system = new System<SilverBulletHooks>("server");

  // Instantiate the event bus hook
  const eventHook = new EventHook();
  system.addHook(eventHook);

  // And the page namespace hook
  const namespaceHook = new PageNamespaceHook();
  system.addHook(namespaceHook);

  // The space
  const space = new Space(
    new EventedSpacePrimitives(
      new PlugSpacePrimitives(
        new DiskSpacePrimitives(pagesPath),
        namespaceHook
      ),
      eventHook
    ),
    true
  );

  await space.updatePageList();

  // The database used for persistence (SQLite)
  const db = knex({
    client: "better-sqlite3",
    connection: {
      filename: path.resolve(pagesPath, "data.db"),
    },
    useNullAsDefault: true,
  });

  // Register syscalls available on the server side
  system.registerSyscalls(
    [],
    pageIndexSyscalls(db),
    storeSyscalls(db, "store"),
    fullTextSearchSyscalls(db, "fts"),
    spaceSyscalls(space),
    eventSyscalls(eventHook),
    markdownSyscalls(buildMarkdown([])),
    sandboxSyscalls(system),
    jwtSyscalls()
  );
  // Danger zone
  system.registerSyscalls(["shell"], shellSyscalls(pagesPath));
  system.registerSyscalls(["fs"], fileSystemSyscalls("/"));

  system.on({
    plugLoaded: (plug) => {
      // Automatically inject some modules into each plug
      safeRun(async () => {
        for (let [modName, code] of Object.entries(
          globalModules.dependencies
        )) {
          await plug.sandbox.loadDependency(modName, code as string);
        }
      });
    },
  });

  const plugDir = nodeModulesDir + "/node_modules/@silverbulletmd/plugs/dist";
  for (let file of await readdir(plugDir)) {
    if (file.endsWith(".plug.json")) {
      let manifestJson = await readFile(path.join(plugDir, file), "utf8");
      let manifest: Manifest = JSON.parse(manifestJson);
      await system.load(manifest, createSandbox);
    }
  }

  let publishPlug = await system.load(publishPlugManifest, createSandbox);

  system.registerSyscalls(
    [],
    markdownSyscalls(buildMarkdown(loadMarkdownExtensions(system)))
  );

  await ensureIndexTable(db);
  await ensureStoreTable(db, "store");
  await ensureFTSTable(db, "fts");

  if (args.index) {
    console.log("Now indexing space");
    await system.loadedPlugs.get("core")?.invoke("reindexSpace", []);
  }

  await publishPlug.invoke("publishAll", [path.resolve(args.dist)]);
  console.log("Done!");
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
