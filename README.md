# Silver Bullet Publish
SilverBullet is a simple tool to publish a a subset of your [SilverBullet](https://silverbullet.md) space as a static website.

**Note:** this is still experimental, use at your own risk.

SilverBullet Publish publishes a subset of a space in two formats:

- HTML (.html files based on a handlebars template that you can override, see [[template/page|the template used for this site]] and the [[PUBLISH|configuration]])
- Markdown (.md files) (and an associated `index.json` file for SilverBullet to read via [[!silverbullet.md/Federation]]).

The tool can be run in two ways:

1. From the SB UI, via the (via the {[Publish: Publish All]} command)
2. As a stand-alone CLI tool (see below)

The latter allows for automatic deployments to e.g. environments like Netlify.

## Installation

Run the {[Plugs: Add]} command and add the following plug:

```yaml
- github:silverbulletmd/silverbullet-publish/publish.plug.js
```

## Configuration

SilverBullet Publish is configured by creating a [[PUBLISH]] page.

## Running from the CLI

First make sure you have the `silverbullet-publish` plug installed into your space. Then, from the command line run:

```bash
silverbullet plug:run <<path-to-your-space>> publish.publishAll
```
