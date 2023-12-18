import "$sb/lib/fetch.ts";
import { FileMeta } from "$silverbullet/plug-api/types.ts";
import { Filesystem } from "./fs.ts";

export class HttpFilesystem implements Filesystem {
  constructor(private url: string, private token: string) {
  }

  authenticatedFetch(input: RequestInfo, init?: RequestInit) {
    return nativeFetch(input, {
      ...init,
      headers: {
        ...init?.headers,
        "X-Sync-Mode": "true",
        Authorization: `Bearer ${this.token}`,
      },
    });
  }

  async listFiles(): Promise<FileMeta[]> {
    const r = await this.authenticatedFetch(`${this.url}/index.json`, {
      method: "GET",
    });
    if (r.status === 404) {
      throw new Error("Not found");
    }
    return r.json();
  }
  async readFile(path: string): Promise<Uint8Array> {
    const r = await this.authenticatedFetch(`${this.url}/${path}`, {
      method: "GET",
    });
    return new Uint8Array(await r.arrayBuffer());
  }
  async getFileMeta(path: string): Promise<FileMeta> {
    const r = await this.authenticatedFetch(`${this.url}/${path}`, {
      method: "GET",
      headers: {
        "X-Get-Meta": "true",
      },
    });
    return this.headersToFileMeta(path, r.headers);
  }
  async writeFile(path: string, data: Uint8Array): Promise<FileMeta> {
    const r = await this.authenticatedFetch(`${this.url}/${path}`, {
      method: "PUT",
      body: data,
    });
    if (r.ok) {
      return this.headersToFileMeta(path, r.headers);
    } else {
      throw new Error(`Failed to write file: ${await r.text()}`);
    }
  }
  async deleteFile(path: string): Promise<void> {
    const r = await this.authenticatedFetch(`${this.url}/${path}`, {
      method: "DELETE",
    });
    if (!r.ok) {
      throw new Error(`Failed to delete file: ${path}: ${await r.text()}`);
    }
  }

  headersToFileMeta(path: string, headers: Headers): FileMeta {
    return {
      name: path,
      contentType: headers.get("Content-Type") || "application/octet-stream",
      perm: headers.get("X-Perm") as "ro" | "rw",
      created: +(headers.get("X-Created") || "0"),
      lastModified: +(headers.get("X-Last-Modified") || "0"),
      size: headers.has("X-Content-Length")
        ? +headers.get("X-Content-Length")!
        : +headers.get("Content-Length")!,
    };
  }
}
