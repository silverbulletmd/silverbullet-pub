import { Command } from "https://deno.land/x/cliffy@v1.0.0-rc.3/command/command.ts";
import { HttpServer } from "./http_server.ts";

import type { SpacePrimitives } from "$silverbullet/common/spaces/space_primitives.ts";
import { DiskSpacePrimitives } from "$silverbullet/common/spaces/disk_space_primitives.ts";
import { DenoKVSpacePrimitives } from "$silverbullet/common/spaces/deno_kv_space_primitives.ts";

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
      (Deno.env.get("SB_PORT") && +Deno.env.get("SB_PORT")!) || 3000;
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
      console.info(
        "No folder specified. Using Deno KV mode.",
      );
      spacePrimitives = new DenoKVSpacePrimitives();
      await (spacePrimitives as DenoKVSpacePrimitives).init("pub.db");
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
