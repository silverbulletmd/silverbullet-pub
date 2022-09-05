#!/bin/bash

rm -rf node_modules/@silverbulletmd/{common,plugs,server,web,plugos-silverbullet-syscall}
for MODULE in common plugs server web plugos-silverbullet-syscall; do
  ln -s $(PWD)/../../silverbullet/packages/$MODULE $(PWD)/node_modules/@silverbulletmd/$MODULE
done

rm -rf node_modules/@plugos/{plugos,plugos-syscall}
for MODULE in plugos plugos-syscall; do
  ln -s $(PWD)/../../silverbullet/packages/$MODULE $(PWD)/node_modules/@plugos/$MODULE
done
