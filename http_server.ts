import { Application, oakCors, Request, Response, Router } from "./deps.ts";
import { SpacePrimitives } from "$silverbullet/common/spaces/space_primitives.ts";
import { FileMeta } from "$silverbullet/plug-api/types.ts";

export type ServerOptions = {
  hostname: string;
  port: number;
  pagesPath: string;
  token: string;
};

export class HttpServer {
  app = new Application();
  abortController?: AbortController;

  constructor(
    private spacePrimitives: SpacePrimitives,
    private options: ServerOptions,
  ) {
  }

  start() {
    const fsRouter = this.addFsRoutes(this.spacePrimitives);
    this.app.use(fsRouter.routes());
    this.app.use(fsRouter.allowedMethods());

    this.abortController = new AbortController();
    const listenOptions: any = {
      hostname: this.options.hostname,
      port: this.options.port,
      signal: this.abortController.signal,
    };
    this.app.listen(listenOptions)
      .catch((e: any) => {
        console.log("Server listen error:", e.message);
        Deno.exit(1);
      });
    const visibleHostname = this.options.hostname === "0.0.0.0"
      ? "localhost"
      : this.options.hostname;
    console.log(
      `SilverBullet Pub server is now running: http://${visibleHostname}:${this.options.port}`,
    );
  }

  private addFsRoutes(spacePrimitives: SpacePrimitives): Router {
    const fsRouter = new Router();
    const corsMiddleware = oakCors({
      allowedHeaders: "*",
      exposedHeaders: "*",
      methods: ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
    });

    fsRouter.use(corsMiddleware);

    // File list
    // fsRouter.get(
    //   "/index.json",
    //   // corsMiddleware,
    //   async ({ response }) => {
    //     // Only handle direct requests for a JSON representation of the file list
    //     response.headers.set("Content-type", "application/json");
    //     response.headers.set("X-Space-Path", this.options.pagesPath);
    //     const files = await spacePrimitives.fetchFileList();
    //     files.forEach((f) => {
    //       f.perm = "ro";
    //     });
    //     response.body = JSON.stringify(files);
    //   },
    // );

    const filePathRegex = "\/(.*)";

    fsRouter
      .get(
        filePathRegex,
        async ({ params, response, request }) => {
          let name = params[0];
          if (name === "") {
            name = "index.html";
          }
          console.log("Requested file", name);
          if (name.startsWith(".")) {
            // Don't expose hidden files
            response.status = 404;
            response.body = "Not exposed";
            return;
          }
          try {
            if (request.headers.has("X-Get-Meta")) {
              // Getting meta via GET request
              const fileData = await spacePrimitives.getFileMeta(name);
              response.status = 200;
              this.fileMetaToHeaders(response.headers, fileData);
              response.body = "";
              return;
            }
            let fileData: { meta: FileMeta; data: Uint8Array } | undefined;

            try {
              fileData = await spacePrimitives.readFile(name);
            } catch (e: any) {
              // console.error(e);
              if (e.message === "Not found") {
                fileData = await spacePrimitives.readFile(`${name}/index.html`);
              }
            }
            if (!fileData) {
              response.status = 404;
              response.body = "Not found";
              return;
            }
            const lastModifiedHeader = new Date(fileData.meta.lastModified)
              .toUTCString();
            if (
              request.headers.get("If-Modified-Since") === lastModifiedHeader
            ) {
              response.status = 304;
              return;
            }
            response.status = 200;
            this.fileMetaToHeaders(response.headers, fileData.meta);
            response.headers.set("Last-Modified", lastModifiedHeader);

            response.body = fileData.data;
          } catch (e: any) {
            console.error("Error GETting file", name, e.message);
            response.status = 404;
            response.body = "Not found";
          }
        },
      )
      .put(
        filePathRegex,
        async ({ request, response, params }) => {
          const name = params[0];
          if (!this.ensureAuth(request, response)) {
            return;
          }
          console.log("Saving file", name);
          if (name.startsWith(".")) {
            // Don't expose hidden files
            response.status = 403;
            return;
          }

          const body = await request.body({ type: "bytes" }).value;

          try {
            const meta = await spacePrimitives.writeFile(
              name,
              body,
            );
            response.status = 200;
            this.fileMetaToHeaders(response.headers, meta);
            response.body = "OK";
          } catch (err) {
            console.error("Write failed", err);
            response.status = 500;
            response.body = "Write failed";
          }
        },
      )
      .delete(filePathRegex, async ({ request, response, params }) => {
        if (!this.ensureAuth(request, response)) {
          return;
        }
        const name = params[0];
        console.log("Deleting file", name);
        if (name.startsWith(".")) {
          // Don't expose hidden files
          response.status = 403;
          return;
        }
        try {
          await spacePrimitives.deleteFile(name);
          response.status = 200;
          response.body = "OK";
        } catch (e: any) {
          console.error("Error deleting attachment", e);
          response.status = 500;
          response.body = e.message;
        }
      })
      .options(filePathRegex, corsMiddleware);
    return fsRouter;
  }

  ensureAuth(request: Request, response: Response): boolean {
    const authHeader = request.headers.get("Authorization");
    if (!authHeader) {
      response.status = 401;
      response.body = "No Authorization header";
      return false;
    }
    const token = authHeader.split(" ")[1];
    if (token !== this.options.token) {
      response.status = 401;
      response.body = "Invalid token";
      return false;
    }

    return true;
  }

  private fileMetaToHeaders(headers: Headers, fileMeta: FileMeta) {
    headers.set("Content-Type", fileMeta.contentType);
    headers.set(
      "X-Last-Modified",
      "" + fileMeta.lastModified,
    );
    headers.set("Cache-Control", "no-cache");
    headers.set("X-Permission", "ro");
    headers.set("X-Content-Length", "" + fileMeta.size);
  }

  stop() {
    if (this.abortController) {
      this.abortController.abort();
      console.log("stopped server");
    }
  }
}
