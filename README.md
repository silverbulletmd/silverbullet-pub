# Silver Bullet Pub
SilverBullet Pub is a simple tool to publish a a subset of your
[SilverBullet](https://silverbullet.md) space as a static website.

**Note:** this is still experimental, use at your own risk.

SilverBullet Pub publishes a subset of a space in two formats:

- HTML (.html files based on a handlebars template that you can override, see [[template/page|the template used for this site]] and configuration part of [[SETTINGS]]).
- Markdown (.md files) (and an associated `index.json` file for SilverBullet to read via [Federation](https://silverbullet.md/Federation)).

The tool can be run in two ways:

1. From the SB UI, via the (via the {[Pub: Publish All]} command)
2. As a stand-alone CLI tool (see below)

After running the _Publish All_ command (from SB, or via the CLI as described below) the resulting website is written into your space folder under `_public` by default (but this is configurable). Note that because SilverBullet does not list pages starting with `_`, this folder will not be visible in the SilverBullet page picker, it’s only visible on disk.

After this, it’s up to you to deploy these files to any host capable of statically serving files. This repository itself is published to [pub.silverbullet.md](https://pub.silverbullet.md) using _Pub_ combined with [Netlify](https://netlify.com/). [Check the repo](https://github.com/silverbulletmd/silverbullet-pub/blob/main/netlify.toml) to see how this works.

## Installation
Run the {[Plugs: Add]} command and add the following plug:

```yaml
- github:silverbulletmd/silverbullet-pub/pub.plug.js
```

## Configuration
SilverBullet Pub is configured through [[SETTINGS]].

## Running from the CLI
First make sure you have the plug installed into your space. Then, from the command line run:

```bash
SB_DB_BACKEND=memory silverbullet plug:run <<path-to-your-space>> pub.publishAll
```

## Site map
* [[README]]
* [[SETTINGS]]
* [[index]]
* [[template/page]]