# Silver Bullet Pub
SilverBullet Pub is a simple tool to _publish_ a a subset of your [SilverBullet](https://silverbullet.md) space as a static website. This repository itself is published to [pub.silverbullet.md](https://publish.silverbullet.md) using _Pub_ combined with [Netlify](https://netlify.com/).

**Note:** this is still experimental, use at your own risk.

SilverBullet Pub publishes a subset of a space in two formats:

- HTML (.html files based on a handlebars template that you can override, see [[template/page|the template used for this site]] and configuration part of [[SETTINGS]]).
- Markdown (.md files) (and an associated `index.json` file for SilverBullet to read via [[!silverbullet.md/Federation]]).

The tool can be run in two ways:

1. From the SB UI, via the (via the {[Pub: Publish All]} command)
2. As a stand-alone CLI tool (see below)

The latter allows for automatic deployments to e.g. environments like Netlify.

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
silverbullet plug:run <<path-to-your-space>> pub.publishAll
```

## Deploying with Netlify
Check the [Github repo](https://github.com/silverbulletmd/silverbullet-pub) for this project for an example (see the `netlify.toml` file as a starting point)