# MISP Web UI – Admin Settings and Pages Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Setting – invalid value for a list setting](#admin-setting-invalid-option) | |
| 2 | [Setting – text with emoji](#admin-setting-emoji) | |
| 3 | [Diagnostics page](#admin-diagnostics) | |
| 4 | [Admin pages load](#admin-pages) | |

---


# E2E Tests

### Setting – invalid value for a list setting
<a id="admin-setting-invalid-option"></a>

A setting with a fixed list of values refuses another value

1. Log in to MISP as `site-admin`.
2. Go to `/servers/serverSettings`.
3. Find `MISP.default_event_distribution` and set it to `9` (e.g. through the API `POST /servers/serverSettingsEdit/MISP.default_event_distribution` with `{"value": "9"}`).
4. Set it back to `1`.

**Expected:** `9` is refused because the only allowed values are `0` to `4`.

**Seeded data:** Through the API, `9` was accepted ("Field updated") and written to `config.php`; it was set back to `1` (the misp-docker default) right after.

### Setting – text with emoji
<a id="admin-setting-emoji"></a>

A text setting with an emoji is saved and shown

1. Log in to MISP as `site-admin`.
2. Go to `/servers/serverSettings`.
3. Set `MISP.welcome_text_top` to `QA welcome 🚀`.
4. Log out and look at the login page.
5. Log back in and set `MISP.welcome_text_top` back to empty.

**Expected:** the login page shows `QA welcome 🚀`; the setting can be emptied again from the settings page.

**Seeded data:** Through the API the emoji text was saved; setting it back to an empty value was refused (HTTP 403) and needed `cake Admin setSetting "MISP.welcome_text_top" "" -f`.

### Diagnostics page
<a id="admin-diagnostics"></a>

The diagnostics page loads and lists the state of the instance

1. Log in to MISP as `site-admin`.
2. Go to `/servers/serverSettings/diagnostics`.
3. Wait for the page to load and read the sections.

**Expected:** the page loads in less than 5 seconds and shows the versions, the workers and the database checks without error.

**Seeded data:** Through the API, `/servers/serverSettings/diagnostics` answers in about 2.9 s.

### Admin pages load
<a id="admin-pages"></a>

The main administration pages open without error

1. Log in to MISP as `site-admin`.
2. Go to `/servers/serverSettings`.
3. Open `/jobs/index`, `/feeds/index`, `/workflows/index`, `/admin/logs/index` and `/servers/index` one after the other.

**Expected:** each page opens in less than 2 seconds without error.

**Seeded data:** Through the API each of these pages answers HTTP 200 in about 0.2 s.
