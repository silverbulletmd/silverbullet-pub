# Silver Bullet Publish

A simple tool to export a subset of your [SilverBullet](https://silverbullet.md)
space as a static website.

**Note:** this is highly experimental and not necessarily production ready code,
use at your own risk.

silverbullet-publish currentenly publishes a subset of a space in two formats:

- Markdown (.md files) (and an associated `index.json` file for SilverBullet to
  read)
- HTML (.html files based on currently hardcoded templates (see `page.hbs` and
  `style.css`)

The tool can be run in two ways:

1. As a Silver Bullet plug (via the `Publish: Publish All` command)
2. As a stand-alone CLI tool (via `silverbullet plug:run`)

The latter allows for automatic deployments to e.g. environments like Netlify.

## Installation

Run the {[Plugs: Add]} command and add the following plug:

```yaml
- github:silverbulletmd/silverbullet-publish/publish.plug.js
```

## Configuration

SilverBullet Publish is configured via the `PUBLISH` page with the following
properties:

```yaml
# Index page to use for public version
indexPage: Public
title: Name of the space
removeHashtags: true
removeUnpublishedLinks: false
# Publish all pages with specific tag
tags:
- "#pub"
# Publish all pages with a specifix prefix
prefixes:
- /public
```

## Running from the CLI

First make sure you have the `silverbullet-publish` plug installed into your
space. Then, from the command line run:

```bash
silverbullet plug:run <<path-to-your-space>> publish.publishAll
```
