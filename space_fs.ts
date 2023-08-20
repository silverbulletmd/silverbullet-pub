import { space } from "$sb/silverbullet-syscall/mod.ts";
import { FileMeta } from "$silverbullet/plug-api/types.ts";
import { Filesystem } from "./fs.ts";

export class SpaceFilesystem implements Filesystem {
  constructor(private prefix: string) {}
  async listFiles(): Promise<FileMeta[]> {
    return (await space.listFiles()).filter((f) =>
      f.name.startsWith(this.prefix)
    ).map((f) => ({
      ...f,
      name: f.name.slice(this.prefix.length),
    }));
  }
  readFile(path: string): Promise<Uint8Array> {
    return space.readFile(this.prefix + path);
  }
  getFileMeta(path: string): Promise<FileMeta> {
    return space.getFileMeta(this.prefix + path);
  }
  writeFile(path: string, data: Uint8Array): Promise<FileMeta> {
    return space.writeFile(this.prefix + path, data);
  }
  deleteFile(path: string): Promise<void> {
    return space.deleteFile(this.prefix + path);
  }
}
