import { editor, markdown, space, sync } from "$sb/silverbullet-syscall/mod.ts";
import { readCodeBlockPage } from "$sb/lib/yaml_page.ts";
import { readSecret } from "$sb/lib/secrets_page.ts";
import { readSetting } from "$sb/lib/settings_page.ts";
import { renderMarkdownToHtml } from "$silverbullet/plugs/markdown/markdown_render.ts";

import Handlebars from "handlebars";

import {
  collectNodesOfType,
  ParseTree,
  renderToText,
  replaceNodesMatching,
} from "$sb/lib/tree.ts";
import { parseMarkdown } from "$silverbullet/plug-api/silverbullet-syscall/markdown.ts";
import { FileMeta } from "$silverbullet/plug-api/types.ts";
import { SpaceFilesystem } from "./space_fs.ts";
import { HttpFilesystem } from "./http_fs.ts";
import { Filesystem } from "./fs.ts";

type PublishConfig = {
  title?: string;
  indexPage?: string;
  removeHashtags?: boolean;
  publishAll?: boolean;
  destPrefix?: string;
  publishServer?: string;
  publishToken?: string;
  tags?: string[];
  prefixes?: string[];
  template?: string;
};

const defaultPublishConfig: PublishConfig = {
  removeHashtags: true,
  template: "!pub.silverbullet.md/template/page",
  destPrefix: "_public/",
};

async function generatePage(
  fs: Filesystem,
  pageName: string,
  htmlPath: string,
  mdPath: string,
  publishedPages: string[],
  publishConfig: PublishConfig,
  template: Handlebars.TemplateDelegate<any>,
) {
  const text = await space.readPage(pageName);
  console.log("Writing", pageName);
  const mdTree = await markdown.parseMarkdown(text);
  const publishMd = cleanMarkdown(
    mdTree,
    publishConfig,
    publishedPages,
  );
  // console.log("CLean md", publishMd)
  const attachments = collectAttachments(mdTree);
  for (const attachment of attachments) {
    try {
      const attachmentData = await space.readAttachment(attachment);
      console.log("Writing", attachment);
      await fs.writeFile(attachment, attachmentData);
    } catch (e: any) {
      console.error("Error reading attachment", attachment, e.message);
    }
  }
  // Write .md file
  await fs.writeFile(mdPath, new TextEncoder().encode(publishMd));
  // Write .html file
  await fs.writeFile(
    htmlPath,
    new TextEncoder().encode(template({
      pageName,
      config: publishConfig,
      isIndex: pageName === publishConfig.indexPage,
      body: renderMarkdownToHtml(await parseMarkdown(publishMd), {
        smartHardBreak: true,
        attachmentUrlPrefix: "/",
      }),
    })),
  );
}

export async function publishAll() {
  let publishConfig = defaultPublishConfig;
  try {
    const loadedPublishConfig: PublishConfig = await readSetting("publish", {});
    publishConfig = {
      ...defaultPublishConfig,
      ...loadedPublishConfig,
    };
    try {
      const publishSecrets = await readSecret("publish");
      publishConfig.publishToken = publishSecrets.token;
    } catch (e) {
      console.error("No publish secret found", e);
    }
  } catch (e: any) {
    console.warn("No SETTINGS page found, using defaults", e.message);
  }
  const destPrefix = publishConfig.destPrefix!;

  if (publishConfig.publishServer && !publishConfig.publishToken) {
    throw new Error(
      "publishServer specified, but no matching 'token' under 'publish' found in SECRETS",
    );
  }

  const fs = publishConfig.publishServer
    ? new HttpFilesystem(
      publishConfig.publishServer,
      publishConfig.publishToken!,
    )
    : new SpaceFilesystem(destPrefix);

  console.log("Publishing to", fs);
  let allPages = await space.listPages();
  const allPageMap: Map<string, any> = new Map(
    allPages.map((pm) => [pm.name, pm]),
  );

  console.log("Cleaning up destination directory");
  for (const existingFile of await fs.listFiles()) {
    await fs.deleteFile(existingFile.name);
  }

  allPages = [...allPageMap.values()];
  let publishedPages = new Set<string>();
  if (publishConfig.publishAll) {
    publishedPages = new Set(allPages.map((p) => p.name));
  } else {
    for (const page of allPages) {
      if (publishConfig.tags && page.tags) {
        for (const tag of page.tags) {
          if (publishConfig.tags.includes(tag)) {
            publishedPages.add(page.name);
          }
        }
      }
      // Some sanity checking
      if (typeof page.name !== "string") {
        continue;
      }
      if (publishConfig.prefixes) {
        for (const prefix of publishConfig.prefixes) {
          if (page.name.startsWith(prefix)) {
            publishedPages.add(page.name);
          }
        }
      }

      if (page.$share) {
        if (!Array.isArray(page.$share)) {
          page.$share = [page.$share];
        }
        if (page.$share.includes("pub")) {
          publishedPages.add(page.name);
        }
      }
    }
  }
  console.log("Publishing", [...publishedPages]);

  const pageTemplate = await readCodeBlockPage(publishConfig.template!);
  const template = Handlebars.compile(pageTemplate);

  const publishedPagesArray = [...publishedPages];
  for (const page of publishedPagesArray) {
    await generatePage(
      fs,
      page,
      `${page}/index.html`,
      `${page}.md`,
      publishedPagesArray,
      publishConfig,
      template,
    );
  }

  if (publishConfig.indexPage) {
    console.log("Writing", publishConfig.indexPage);
    await generatePage(
      fs,
      publishConfig.indexPage,
      `index.html`,
      `index.md`,
      publishedPagesArray,
      publishConfig,
      template,
    );
  }

  console.log("Writing", `index.json`);
  const publishedFiles: FileMeta[] = [];
  for (
    const { name, size, contentType, lastModified } of await space
      .listAttachments()
  ) {
    if (name.startsWith(destPrefix)) {
      if (contentType === "text/html") {
        // Skip the generated HTML files
        continue;
      }
      publishedFiles.push({
        name: name.slice(destPrefix.length),
        size,
        contentType,
        lastModified,
        perm: "ro",
      });
    }
  }
  await fs.writeFile(
    `index.json`,
    new TextEncoder().encode(
      JSON.stringify(publishedFiles, null, 2),
    ),
  );
}

export async function publishAllCommand() {
  await editor.flashNotification("Publishing...");
  await publishAll();
  await sync.scheduleSpaceSync();
  await editor.flashNotification("Done!");
}

function collectAttachments(tree: ParseTree) {
  const attachments: string[] = [];
  collectNodesOfType(tree, "URL").forEach((node) => {
    const url = node.children![0].text!;
    if (url.indexOf("://") === -1) {
      attachments.push(url);
    }
  });
  return attachments;
}

function cleanMarkdown(
  mdTree: ParseTree,
  publishConfig: PublishConfig,
  validPages: string[],
): string {
  replaceNodesMatching(mdTree, (n) => {
    if (n.type === "WikiLink") {
      let page = n.children![1].children![0].text!;
      if (page.includes("@")) {
        page = page.split("@")[0];
      }
      if (page.startsWith("!")) {
        const lastBit = page.split("/").pop();
        return {
          text: `[${lastBit}](https://${page.slice(1)})`,
        };
      }
      if (!validPages.includes(page) && !page.startsWith("!")) {
        // Replace with just page text
        return {
          text: `_${page}_`,
        };
      }
    }
    // Simply get rid of these
    if (n.type === "CommentBlock" || n.type === "Comment") {
      return null;
    }
    if (n.type === "Hashtag") {
      if (publishConfig.removeHashtags) {
        return null;
      }
    }
  });
  return renderToText(mdTree).trim();
}
