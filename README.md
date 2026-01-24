oauthindie plugin for DokuWiki

IndieAuth extension for oAuth plugin in Dokuwiki

All documentation for this plugin can be found at
https://www.dokuwiki.org/plugin:oauthindie

If you install this plugin manually, make sure it is installed in
lib/plugins/oauthindie/ - if the folder is called different it
will not work!

Please refer to http://www.dokuwiki.org/extensions for additional info
on how to install extensions in DokuWiki.

Quick test
--------

1. Install the plugin folder under your DokuWiki instance:

```bash
cp -r /path/to/oauthindie lib/plugins/oauthindie
```

2. Ensure the DokuWiki `oauth` plugin is available (declared as a dependency).

3. Open the example sign-in form in your browser (replace `BASEURL` with your wiki URL):

```
https://BASEURL/lib/plugins/oauthindie/examples/signin.html
```

The form POSTS to `?oauthindie=start`, initiates the IndieAuth flow (prefilled with https://orwell.fun for testing), and redirects back to `?oauthindie=callback` where the plugin scaffold will populate the DokuWiki session when successful.

4. For debugging enable DokuWiki debug and check your PHP error log for traces from `oauthindie`.


----
Copyright (C) Tassoman <tassoman@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

See the LICENSING file for details
