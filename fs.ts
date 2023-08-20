import { FileMeta } from "$silverbullet/plug-api/types.ts";

export interface Filesystem {
  listFiles(): Promise<FileMeta[]>;
  readFile(path: string): Promise<Uint8Array>;
  getFileMeta(path: string): Promise<FileMeta>;
  writeFile(path: string, data: Uint8Array): Promise<FileMeta>;
  deleteFile(path: string): Promise<void>;
}
