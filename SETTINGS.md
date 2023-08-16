This page contains settings for configuring SilverBullet and its plugs. Any
changes outside of the yaml block will be overwritten.

```yaml
indexPage: README
publish:
  indexPage: README
  title: SilverBullet Publish
  destPrefix: _public/
  removeHashtags: true
  removeUnpublishedLinks: false
  generateIndexJson: true
  publishAll: true # Defaults to false
  template: template/page # Defaults to "!publish.silverbullet.md/template/page"
  ## Publish all pages with a specifix prefix
  #prefixes:
  #- /public
  ## Publish all pages with specific tag
  #tags:
  #- pub
```
