# Calltree

Author: **Eric Biazo**

Calltree generator for function

## Description:

Generates call tree. Alternative view for callgraph.

## Releases

* 2.1 -- Bug Fix
* 2.0 -- Multiview Support
* 1.2 -- Bug Fixes
* 1.1 -- Refactoring
* 1.0 -- Public Release
* 0.0 -- Beta Release

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * 2966

## License

This plugin is released under an [MIT license](./LICENSE).

## Caution

When working with really big binaries with alot of xrefs, you would want to change recursive depth to smaller number or else Binary Ninja might hang.
## Description

Calltree is a plugin that generates call tree for a function. It is an alternative view for callgraph. It is a multiview plugin, so you can have multiple calltree views open at the same time.

### Default View

![](images/2023-03-06-23-31-27.png)

### Expand and Collapse tree

**Expand**

![](images/2023-03-06-23-44-02.png)

**Collapse**

![](images/2023-03-06-23-44-24.png)

**Search**

![](images/2022-02-09-16-53-33.png)

### Recursion Depth

**Show Only Root Level**

![](images/2022-02-09-16-57-21.png)

**Default Recursion Depth in Setting**

![](images/2022-02-09-16-59-03.png)

### Pinning and Removing Calltree View

**Pinning Calltree View**

![](images/2023-03-06-23-40-42.png)

**Pinned Calltree Name Max Length**

![](images/2023-03-06-23-46-04.png)


## Contributors

Thanks everyone that have contributed to calltree!

* galenbwill
* droogie
* bambu
* crimsonskylark
