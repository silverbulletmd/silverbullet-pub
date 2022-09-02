import { writeFile } from "@plugos/plugos-syscall/fs";
import { invokeFunction } from "@silverbulletmd/plugos-silverbullet-syscall/system";
import { queryPrefix } from "@silverbulletmd/plugos-silverbullet-syscall";
import { flashNotification } from "@silverbulletmd/plugos-silverbullet-syscall/editor";
import {
  listPages,
  readPage,
} from "@silverbulletmd/plugos-silverbullet-syscall/space";
import { readYamlPage } from "@silverbulletmd/plugs/lib/yaml_page";

import MarkdownIt from "markdown-it";
import Handlebars from "handlebars";

var taskLists = require("markdown-it-task-lists");

// @ts-ignore
import pageTemplate from "./page.hbs";
// @ts-ignore
import pageCSS from "./style.css";
import { parseMarkdown } from "@silverbulletmd/plugos-silverbullet-syscall/markdown";

import {
  findNodeOfType,
  renderToText,
  replaceNodesMatching,
} from "@silverbulletmd/common/tree";

type PublishConfig = {
  destDir?: string;
  title?: string;
  indexPage?: string;
  removeHashtags?: boolean;
  removeUnpublishedLinks?: boolean;
  tags?: string[];
  prefixes?: string[];
};

const md = new MarkdownIt({
  linkify: true,
  html: false,
  typographer: true,
}).use(taskLists);

async function generatePage(
  pageName: string,
  htmlPath: string,
  mdPath: string,
  publishedPages: string[],
  publishConfig: PublishConfig
) {
  let { text } = await readPage(pageName);
  let renderPage = Handlebars.compile(pageTemplate);
  console.log("Writing", pageName);
  const publishMd = await cleanMarkdown(
    text,
    publishConfig,
    publishedPages,
    false
  );
  const htmlMd = await cleanMarkdown(text, publishConfig, publishedPages, true);
  // Write .md file
  await writeFile(mdPath, publishMd);
  // Write .html file
  await writeFile(
    htmlPath,
    renderPage({
      pageName,
      config: publishConfig,
      css: pageCSS,
      body: md.render(htmlMd),
    })
  );
}

export async function publishAll(destDir?: string) {
  let publishConfig: PublishConfig = await readYamlPage("PUBLISH");
  destDir = destDir || publishConfig.destDir || ".";
  console.log("Publishing to", destDir);
  let allPages: any[] = await listPages();
  let allPageMap: Map<string, any> = new Map(
    allPages.map((pm) => [pm.name, pm])
  );
  for (let { page, value } of await queryPrefix("meta:")) {
    let p = allPageMap.get(page);
    if (p) {
      for (let [k, v] of Object.entries(value)) {
        p[k] = v;
      }
    }
  }

  allPages = [...allPageMap.values()];
  let publishedPages = new Set<string>();
  for (let page of allPages) {
    if (publishConfig.tags && page.tags) {
      for (let tag of page.tags) {
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
      for (let prefix of publishConfig.prefixes) {
        if (page.name.startsWith(prefix)) {
          publishedPages.add(page.name);
        }
      }
    }
  }
  console.log("Starting this thing", [...publishedPages]);
  const publishedPagesArray = [...publishedPages];
  for (let page of publishedPagesArray) {
    await generatePage(
      page,
      `${destDir}/${page.replaceAll(" ", "_")}/index.html`,
      `${destDir}/${page}.md`,
      publishedPagesArray,
      publishConfig
    );
  }

  if (publishConfig.indexPage) {
    console.log("Writing", publishConfig.indexPage);
    await generatePage(
      publishConfig.indexPage,
      `${destDir}/index.html`,
      `${destDir}/index.md`,
      publishedPagesArray,
      publishConfig
    );
  }
}

export async function publishAllCommand() {
  await flashNotification("Publishing...");
  await await invokeFunction("server", "publishAll");
  await flashNotification("Done!");
}

export function encodePageUrl(name: string): string {
  return name.replaceAll(" ", "_");
}

export async function cleanMarkdown(
  text: string,
  publishConfig: PublishConfig,
  validPages: string[],
  translatePageReferences = true
): Promise<string> {
  let mdTree = await parseMarkdown(text);
  replaceNodesMatching(mdTree, (n) => {
    if (n.type === "WikiLink") {
      const page = n.children![1].children![0].text!;
      if (!validPages.includes(page)) {
        if (!publishConfig.removeUnpublishedLinks) {
          // Replace with just page text
          return {
            text: `_${page}_`,
          };
        } else {
          return null;
        }
      } else if (translatePageReferences) {
        return {
          text: `[${page}](/${encodePageUrl(page)})`,
        };
      }
    }
    // Simply get rid of these
    if (n.type === "CommentBlock" || n.type === "Comment") {
      return null;
    }
    if (n.type === "Hashtag") {
      if (!publishConfig.removeHashtags) {
        return {
          text: `__${n.children![0].text}__`,
        };
      } else {
        return null;
      }
    }
    if (n.type === "FencedCode") {
      let codeInfoNode = findNodeOfType(n, "CodeInfo");
      if (!codeInfoNode) {
        return;
      }
      if (codeInfoNode.children![0].text === "meta") {
        return null;
      }
    }
  });
  return renderToText(mdTree).trim();
}
