
```yaml
indexPage: README
publish:
  # indexPage specific to the published site
  indexPage: README
  # Site title
  title: SilverBullet Publish
  # publishServer: https://zef-pub.deno.dev
  # Page containing the handlebars template to use to render pages
  # defaults to "!pub.silverbullet.md/template/page"
  template: template/page
  # Destination prefix for where to write the files to (has to be inside the space), defaults to public/
  destPrefix: _public/
  # Remove hashtags from the output
  removeHashtags: true
  # Entirely remove page links to pages that are not published 
  removeUnpublishedLinks: false
  # Publish ALL pages in this space (defaults to false)
  publishAll: true
  # Publish all pages with a specifix prefix only (assuming publishAll is off)
  #prefixes:
  #- /public
  # Publish all pages with specific tag only (assuming publishAll is off)
  tags:
  - pub
```
