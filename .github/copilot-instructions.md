# Copilot instructions — oauthindie (DokuWiki plugin)

Purpose
- Help contributors implement and extend the `oauthindie` DokuWiki auth plugin.

Big picture
- This is a DokuWiki authentication plugin: the main class is `auth_plugin_oauthindie` in `auth.php` which extends DokuWiki's `AuthPlugin` API.
- The plugin implements external auth flows (IndieAuth/OAuth) and integrates with DokuWiki via globals and session entries (see `trustExternal` skeleton in `auth.php`).

Key files
- `auth.php`: core plugin class and the methods you will implement (`trustExternal`, `checkPass`, `getUserData`, etc.).
- `conf/default.php` and `conf/metadata.php`: plugin configuration defaults and metadata options.
- `lang/en/lang.php`: i18n strings.
- `README`: installation notes (must be placed under `lib/plugins/oauthindie/`).

Important patterns & conventions (project-specific)
- DokuWiki auth contract: implement `trustExternal()` to populate the global `$USERINFO` and session: set `$_SESSION[DOKU_COOKIE]['auth']['user']`, `['pass']`, `['info']` and `$_SERVER['REMOTE_USER']` when authentication succeeds.
- Use `$this->cando[...]` in the constructor to declare capabilities (addUser, delUser, external, logout, etc.). The template currently leaves these commented; update as you implement features.
- `isCaseSensitive()`, `cleanUser()` and `cleanGroup()` are intentionally simple — follow those conventions unless the provider requires normalization.
- Keep side-effects minimal in `getUserData()` — return an array with keys `name`, `mail`, and `grps` when available, otherwise return `false`.

Workflow / testing notes
- There are no unit tests in this repo. To test locally, install the plugin into a DokuWiki instance at `lib/plugins/oauthindie/` and exercise login flows in the running wiki.
- Troubleshooting: enable PHP/DokuWiki debug logging and use `error_log()` for short traces. Use the commented example in `auth.php` as a quick manual test to set `$USERINFO` and session entries.

Integration points & expectations
- External auth: IndieAuth/OAuth endpoints are handled by the plugin; the plugin must map external identity to DokuWiki users (or create/trust them depending on `cando`).
- Sessions: DokuWiki stores auth info in `$_SESSION[DOKU_COOKIE]['auth']` — maintain this format to remain compatible.

Examples (from repo)
- Set authenticated user info (adapt the commented skeleton in `auth.php`):

```php
$USERINFO['name'] = 'Example User';
$USERINFO['mail'] = 'user@example.org';
$USERINFO['grps'] = ['user'];
$_SERVER['REMOTE_USER'] = $user;
$_SESSION[DOKU_COOKIE]['auth']['user'] = $user;
$_SESSION[DOKU_COOKIE]['auth']['pass'] = $pass;
$_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
return true;
```

When in doubt
- Ask what DokuWiki version to support and whether automatic user creation is desired.
- Confirm desired behavior for group mapping and persistent sessions.

References
- See `README` and DokuWiki extension docs for packaging and installation details.

If anything above is unclear or you want more detailed templates (e.g., user-creation, group-sync, or an IndieAuth client flow), tell me which area to expand.

IndieAuth integration (actionable checklist)
- Follow Aaron Parecki's IndieAuth flow: show sign-in form, discover `authorization_endpoint`, redirect with PKCE+state, handle redirect with `code`+`state`, exchange code for profile, validate returned `me` URL by re-discovery.
 - This plugin expects DokuWiki's `oauth` plugin to be available. Declare it as a dependency in `plugin.info.txt` (the repo now includes `depends oauth`). If you extend/bridge with that plugin, prefer calling into its helper functions rather than duplicating endpoint discovery logic.
- Map to this plugin:
	- Use the commented `trustExternal()`/`auth.php` skeleton to complete the final step: when a profile is validated, populate `$USERINFO` and `$_SESSION[DOKU_COOKIE]['auth']` and set `$_SERVER['REMOTE_USER']`.
	- Store `state` and `code_verifier` in session before redirect (e.g. `$_SESSION[DOKU_COOKIE]['oauthindie'] = ['state'=>$s,'verifier'=>$v];`).
- PHP implementation hints:
	- HTTP fetch & HTML parsing: use `curl` or `Guzzle` and `DOMDocument` / `DOMXPath` to find `<link rel>` tags for `authorization_endpoint` and `token_endpoint`.
	- PKCE (code_challenge) example:

```php
$verifier = bin2hex(random_bytes(32));
$hash = hash('sha256', $verifier, true);
$challenge = rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
// store $verifier in session and send $challenge as code_challenge
```

	- Exchange the code with a POST to the discovered token endpoint with `grant_type=authorization_code`, `code`, `client_id`, `redirect_uri`, and `code_verifier`.
	- After token/profile response, re-discover the `authorization_endpoint` for the returned `me` URL and confirm it matches the endpoint used initially.

Testing tips
- Use public IndieAuth providers for testing: `micro.blog`, WordPress with the IndieAuth plugin, `selfauth` (single-file PHP server), and `indieauth.rocks` test tools.
- Add verbose `error_log()` traces during development and enable DokuWiki debug for session/auth troubleshooting.

Next steps
- If you want, I can: implement a `/start` and `/callback` route scaffold, add PKCE/session helpers, or implement `trustExternal()` to complete the flow. Tell me which to do first.
