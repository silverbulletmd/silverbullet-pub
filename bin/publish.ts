#!/usr/bin/env node
import {
  createSandbox,
} from "$silverbullet/plugos/environments/deno_sandbox.ts";
import { EventHook } from "$silverbullet/plugos/hooks/event.ts";
import { eventSyscalls } from "$silverbullet/plugos/syscalls/event.ts";
import fileSystemSyscalls from "$silverbullet/plugos/syscalls/fs.deno.ts";
import {
  ensureFTSTable,
  fullTextSearchSyscalls,
} from "$silverbullet/plugos/syscalls/fulltext.sqlite.ts";
import sandboxSyscalls from "$silverbullet/plugos/syscalls/sandbox.ts";
import shellSyscalls from "$silverbullet/plugos/syscalls/shell.deno.ts";
import {
  ensureTable as ensureStoreTable,
  storeSyscalls,
} from "$silverbullet/plugos/syscalls/store.deno.ts";
import { System } from "$silverbullet/plugos/system.ts";
import { Manifest, SilverBulletHooks } from "$silverbullet/common/manifest.ts";
import { loadMarkdownExtensions } from "$silverbullet/common/markdown_ext.ts";
import buildMarkdown from "$silverbullet/common/parser.ts";
import { DiskSpacePrimitives } from "$silverbullet/common/spaces/disk_space_primitives.ts";
import { EventedSpacePrimitives } from "$silverbullet/common/spaces/evented_space_primitives.ts";
import { Space } from "$silverbullet/common/spaces/space.ts";
import { markdownSyscalls } from "$silverbullet/common/syscalls/markdown.ts";
import { PageNamespaceHook } from "$silverbullet/server/hooks/page_namespace.ts";
import { PlugSpacePrimitives } from "$silverbullet/server/hooks/plug_space_primitives.ts";
import {
  ensureTable as ensureIndexTable,
  pageIndexSyscalls,
} from "$silverbullet/server/syscalls/index.ts";
import spaceSyscalls from "$silverbullet/server/syscalls/space.ts";

import { Command } from "https://deno.land/x/cliffy@v0.25.2/command/command.ts";

import globalModules from "https://get.silverbullet.md/global.plug.json" assert {
  type: "json",
};

import publishPlugManifest from "../publish.plug.json" assert { type: "json" };
import * as path from "https://deno.land/std@0.159.0/path/mod.ts";
import { AsyncSQLite } from "../../silverbullet/plugos/sqlite/async_sqlite.ts";

await new Command()
  .name("silverbullet-publish")
  .description("Publish a SilverBullet site")
  .arguments("<folder:string>")
  .option("--index [type:boolean]", "Index space first", { default: false })
  .option("--watch, -w [type:boolean]", "Watch for changes", { default: false })
  .option("-o <path:string>", "Output directory", { default: "web" })
  .action(async (options, pagesPath) => {
    // Set up the PlugOS System
    const system = new System<SilverBulletHooks>("server");

    // Instantiate the event bus hook
    const eventHook = new EventHook();
    system.addHook(eventHook);

    // And the page namespace hook
    const namespaceHook = new PageNamespaceHook();
    system.addHook(namespaceHook);

    pagesPath = path.resolve(pagesPath);

    // The space
    const space = new Space(
      new EventedSpacePrimitives(
        new PlugSpacePrimitives(
          new DiskSpacePrimitives(pagesPath),
          namespaceHook,
        ),
        eventHook,
      ),
    );

    await space.updatePageList();

    // The database used for persistence (SQLite)
    const db = new AsyncSQLite(path.join(pagesPath, "publish-data.db"));
    db.init().catch((e) => {
      console.error("Error initializing database", e);
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
    );
    // Danger zone
    system.registerSyscalls(["shell"], shellSyscalls(pagesPath));
    system.registerSyscalls(["fs"], fileSystemSyscalls("/"));

    system.on({
      sandboxInitialized: async (sandbox) => {
        for (
          const [modName, code] of Object.entries(
            globalModules.dependencies,
          )
        ) {
          await sandbox.loadDependency(modName, code as string);
        }
      },
    });

    const plugDir = nodeModulesDir + "/node_modules/$silverbullet/plugs/dist";
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
      markdownSyscalls(buildMarkdown(loadMarkdownExtensions(system))),
    );

    await ensureIndexTable(db);
    await ensureStoreTable(db, "store");
    await ensureFTSTable(db, "fts");

    if (args.index) {
      console.log("Now indexing space");
      await system.loadedPlugs.get("core")?.invoke("reindexSpace", []);
    }

    const outputDir = path.resolve(args.o);

    await mkdir(outputDir, { recursive: true });

    await publishPlug.invoke("publishAll", [outputDir]);

    if (args.w) {
      console.log("Watching for changes");
      watch(pagesPath, { recursive: true }, async () => {
        console.log("Change detected, republishing");
        await space.updatePageList();
        await publishPlug.invoke("publishAll", [outputDir]);
      });
    } else {
      console.log("Done!");
      process.exit(0);
    }
  })
  .parse(Deno.args);
