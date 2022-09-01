import { writeFile } from "@plugos/plugos-syscall/fs";
import { invokeFunction } from "@silverbulletmd/plugos-silverbullet-syscall/system";
import { queryPrefix } from "@silverbulletmd/plugos-silverbullet-syscall";
import {
  listPages,
  readPage,
} from "@silverbulletmd/plugos-silverbullet-syscall/space";
import { readYamlPage } from "@silverbulletmd/plugs/lib/yaml_page";

import MarkdownIt from "markdown-it";
import Handlebars from "handlebars";
import { cleanMarkdown } from "@silverbulletmd/plugs/markdown/util";

var taskLists = require("markdown-it-task-lists");

// @ts-ignore
import pageTemplate from "./page.hbs";
// @ts-ignore
import pageCSS from "./style.css";

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
  const cleanMd = await cleanMarkdown(text, publishedPages);
  // Write .md file
  await writeFile(mdPath, cleanMd);
  // Write .html file
  await writeFile(
    htmlPath,
    renderPage({
      pageName,
      config: publishConfig,
      css: pageCSS,
      body: md.render(cleanMd),
    })
  );
}

type PublishConfig = {
  destDir?: string;
  title?: string;
  indexPage?: string;
  tags?: string[];
  prefixes?: string[];
};

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
  await invokeFunction("server", "publishAll");
}
