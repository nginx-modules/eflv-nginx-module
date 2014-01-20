Name
====

ngx_eflv - pseudo-streaming server-side support for Flash Video (FLV) files.

*This module is not distributed with the Nginx source.* See [the installation instructions](#installation).


Table of Contents
=================

* [Example Configuration](#example)
* [Directives](#directives)
* [Installation](#installation)


Example Configuration
=====================
```Example
  location ~ \.flv$ {
    tflv;
  }

  location ~ \.flv$ {
    sflv;
  }
```


Directives
==========


Example Configuration
=====================
