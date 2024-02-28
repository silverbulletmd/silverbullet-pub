import { HttpServer } from "./http_server.ts";

import type { SpacePrimitives } from "$silverbullet/common/spaces/space_primitives.ts";
import { DiskSpacePrimitives } from "$silverbullet/common/spaces/disk_space_primitives.ts";
import { ChunkedKvStoreSpacePrimitives } from "$silverbullet/common/spaces/chunked_datastore_space_primitives.ts";
import { DenoKvPrimitives } from "$silverbullet/lib/data/deno_kv_primitives.ts";
import { Command } from "./deps.ts";

await new Command()
  .name("silverbullet-pub")
  .description("SilverBullet Pub Server")
  .help({
    colors: false,
  })
  .usage("<options> <folder>")
  // Main command
  .arguments("[folder:string]")
  .option(
    "--hostname, -L <hostname:string>",
    "Hostname or address to listen on",
  )
  .option("-p, --port <port:number>", "Port to listen on")
  .option(
    "--token <token:string>",
    "Token",
  )
  .action(async (options, folder) => {
    const hostname = options.hostname || Deno.env.get("SB_HOSTNAME") ||
      "127.0.0.1";
    const port = options.port ||
      (Deno.env.get("SB_PORT") && +Deno.env.get("SB_PORT")!) || 8000;
    const token = options.token || Deno.env.get("SB_TOKEN");
    if (!token) {
      console.error(
        "No token specified. Please pass a --token flag, or set SB_TOKEN environment variable.",
      );
      Deno.exit(1);
    }

    let spacePrimitives: SpacePrimitives | undefined;
    if (!folder) {
      folder = Deno.env.get("SB_FOLDER");
    }
    if (folder) {
      spacePrimitives = new DiskSpacePrimitives(folder);
    } else {
      let dbFile: string | undefined = Deno.env.get("SB_DB_FILE") || "pub.db";
      if (Deno.env.get("DENO_DEPLOYMENT_ID") !== undefined) { // We're running in Deno Deploy
        dbFile = undefined; // Deno Deploy will use the default KV store
      }
      console.info(
        "No folder specified. Using Deno KV mode. Storing data in",
        dbFile ? dbFile : "the default KV store",
      );
      const kv = new DenoKvPrimitives(await Deno.openKv(dbFile));

      spacePrimitives = new ChunkedKvStoreSpacePrimitives(kv, 65536);
    }

    console.log(
      "Going to start SilverBullet Pub Server binding to",
      `${hostname}:${port}`,
    );
    // folder = path.resolve(Deno.cwd(), folder);

    const httpServer = new HttpServer(spacePrimitives, {
      hostname,
      port,
      token,
      pagesPath: folder || "kv://",
    });
    httpServer.start();
  })
  .parse(Deno.args);
