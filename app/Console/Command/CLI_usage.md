# MISP Interactive CLI Shell

An interactive REPL for browsing and managing MISP data from the terminal.

## Getting Started

```bash
cd /var/www/MISP
app/Console/cake CLI <user_id>
```

The shell runs as the MISP user whose ID you pass: that account's ACL applies to every read and write, and audit-log entries are written in its name. **This is impersonation, not authentication** — no password or auth key is checked. Read [Security model](#security-model) before exposing the command to anyone.

The prompt displays the current user, organisation, and navigation context:

```
MISP [admin@ORGNAME] >
MISP [admin@ORGNAME] event:8 >
```

## Commands

### Browsing

| Command | Description |
|---|---|
| `list <entity> [filters]` | Paginated listing with optional filters |
| `view <entity> <id>` | Detailed view of a single record |
| `search <entity> [filters]` | Alias for `list` |
| `next` / `prev` | Navigate between pages |

### Write Operations

| Command | Description |
|---|---|
| `add event` | Interactive guided event creation |
| `add attribute` | Add attribute (uses event context or prompts for event ID) |
| `add object` | Add object from a template (prompts for template name) |
| `edit event <id>` | Edit event fields interactively |
| `edit attribute <id>` | Edit attribute fields interactively |
| `edit object <id>` | Edit object metadata (comment, distribution) |
| `delete event <id>` | Hard-delete an event (with confirmation) |
| `delete attribute <id>` | Soft-delete an attribute (with confirmation) |
| `delete object <id>` | Soft-delete an object and its attributes (with confirmation) |

### Navigation

| Command | Description |
|---|---|
| `use <entity> <id>` | Set navigation context (e.g. `use event 8`) |
| `context` | Show current context |
| `clear` | Clear navigation context |
| `help [topic]` | Show help (`help filters` for filter syntax) |
| `exit` / `quit` | Exit the shell |

## Entities

| Entity | Aliases | Admin Only |
|---|---|---|
| `event` | `events` | No |
| `attribute` | `attributes` | No |
| `object` | `objects` | No |
| `tag` | `tags` | No |
| `organisation` | `organisations`, `org`, `orgs` | No |
| `feed` | `feeds` | No |
| `sharing_group` | `sharing_groups`, `sharinggroup`, `sharinggroups` | No |
| `galaxy` | `galaxies` | No |
| `taxonomy` | `taxonomies` | No |
| `warninglist` | `warninglists` | No |
| `user` | `users` | Yes |
| `server` | `servers` | Yes |
| `role` | `roles` | Yes |

## Filter Syntax

Filters are passed as `key=value` pairs after the entity name:

```
list event published=1 threat_level_id=1
list attribute type=ip-dst to_ids=1
search event tag=tlp:white last=7d
```

| Syntax | Meaning |
|---|---|
| `key=value` | Exact match |
| `key=a,b,c` | OR (any of the values) |
| `key=!value` | NOT (exclude) |
| `tag=X,Y` | Tag OR |
| `tag+=X` | Tag AND (must have) |
| `tag=!X` | Tag NOT |
| `from=YYYY-MM-DD` | Date range start |
| `to=YYYY-MM-DD` | Date range end |
| `last=7d` | Relative time (d/h/m) |
| `searchall=text` | Wildcard search across fields |
| `value=%text%` | LIKE match |

## Interactive Browse Mode

When running in a TTY, `list` and `search` enter an interactive browse mode with column headers and highlighted row selection:

| Key | Action |
|---|---|
| Up / `k` | Move selection up |
| Down / `j` | Move selection down |
| Enter | View the selected record |
| `n` | Next page |
| `p` | Previous page |
| `f` | Open filter bar |
| `s` | Toggle sort order (ASC/DESC) |
| `q` / Escape | Exit browse mode |

### Column Headers

List views display human-readable column headers (e.g. "Published" instead of "published", "Threat Level" instead of "threat_level_id").

### Foreign Key Resolution

ID columns that reference other entities are displayed as `[id] name` for readability:

- `org_id` / `orgc_id` → `[1] ORGNAME`
- `event_id` → `[42] Event title`
- `role_id` → `[3] Role name`
- `sharing_group_id` → `[5] Sharing group name`

This applies to both list views and detail views.

### Filter Bar

Press `f` in browse mode to open the filter bar:

- Type `key=value` to add/replace a filter
- Type `-key` to remove a filter
- Type `--` to clear all filters
- Tab autocompletes filter keys and values (types, categories, tags, orgs)
- Enter with empty input closes the filter bar

## Detail View

Viewing a record (`view <entity> <id>` or pressing Enter in a list) opens an interactive detail view with scrollable fields:

| Key | Action |
|---|---|
| Up / `k` | Move selection up |
| Down / `j` | Move selection down |
| Enter / `e` | Edit the selected field (if editable, marked with a pencil icon) |
| `1`, `2`, `3` | Navigate to child entities (shown in footer) |
| `q` | Back to previous view |

### Child Entity Navigation

Some entities have child entities accessible via number keys in the detail view:

| Parent | Children |
|---|---|
| Event | `[1]` Attributes, `[2]` Objects, `[3]` Tags |
| Object | `[1]` Attributes |
| Organisation | `[1]` Users, `[2]` Events |
| Role | `[1]` Users |

Pressing a child shortcut opens a full browse list scoped to the parent record. Press `q` to return to the parent detail view.

### Inline Object Attributes

Object detail views show their attributes inline under an `[Attributes]` section, displaying each attribute as `object_relation: value [IDS]`. This gives a quick overview without needing to navigate to the full attribute list.

## ACL and Permissions

### Security model

The shell does not authenticate the user it runs as. `cake CLI <user_id>` selects the account; nothing verifies that the person at the keyboard is that user. This is the convention every MISP console shell follows — `cake Event`, `cake Admin` and `cake Server` all take a user ID the same way.

It is safe only because running `app/Console/cake` at all requires reading `app/Config/database.php`, so anyone who can launch the shell already holds the database credentials and could promote any account directly. The ACL checks inside the shell scope what a session sees and changes; they are **not a privilege boundary**.

Consequently, **do not expose the shell to anyone who must not have site-admin-equivalent access** — not through a `sudoers` rule that pins the user ID, not through a forced SSH command, and not through an automation bridge. Whoever can run the command can pass any ID, including a site admin's.

### Audit trail

Every write the shell performs is logged in the impersonated user's name, in whichever audit engine the instance runs, and marked as made from the CLI:

- With `MISP.log_new_audit` on, `audit_logs` rows carry the user's id and organisation with `request_type = CLI` - the terminal icon in the audit log index - exactly as rows written by `cake Event`, `cake Server` and the background workers do.
- With the default engine, `logs` rows carry the user's id, e-mail and organisation and the description ends `by User "<email>" (<id>) via CLI`, so a shell write never reads as that user's own web activity. The legacy `logs` table has no request-type column, so the sentence is the marker; it travels with the row to syslog and ECS.
- User edits, disables and deletions write the same explicit row the web's user administration writes.

The identity in these rows is the id given on the command line. Nothing verifies that the person at the keyboard is that user (see above), so an audit row saying a user made a change from the CLI means an operator with shell access did so in that user's name.

### General

- All read and write operations are scoped to the impersonated user's ACL (see [Security model](#security-model)), through the same model accessors the web uses — `Event::fetchEvent`, `MispAttribute::fetchAttributes`, `MispObject::fetchObjects`, `SharingGroup::checkIfAuthorised`, `Organisation::canSee` — rather than any ACL logic of the shell's own.
- `user`, `server`, and `role` entities require site admin access.
- `feed` reads require host-org membership, matching the web; `Feed.headers` (feed credentials) and `Server.authkey` are never shown, and `feed`/`server`/`organisation`/`user` detail views never fetch credential columns.
- Event, attribute and object writes require modify rights on the parent event:
  - Site admins can modify any event.
  - Org admins can modify events from their organisation.
  - Regular users can modify events they created.
  - The inline field editor in the detail browser enforces the same check as the `edit` command — there is no unguarded write path.
- `tag` writes follow the web tag policy: adding needs `perm_tag_editor`; editing and deleting are site-admin only.
- `organisation` reads honour `Security.hide_organisation_index_from_users`, so `list`/`view organisation` and tab-completion never reveal an org the user could not otherwise see. Tag tab-completion likewise omits hidden tags.

### List View ACL

Attribute and object listings go through the model's authorized fetch path, so both halves of the visibility rule apply — the parent event **and** the attribute or object:

- The parent event must be visible to the user (owned by their org, or at a community/sharing-group distribution they are authorised for, plus published when `MISP.unpublishedprivate` is set), **and**
- the attribute/object must itself be visible (distribution 1-3 or 5, or a sharing group the user is authorised for; distribution 0 only when their org owns the event).

An event the user cannot see hides its attributes and objects even in listings, exactly as `view event` does.

### Pagination limits

`limit` is clamped to 1-1000 (a missing, zero, negative or non-numeric value falls back to the default page size of 20), and `page` to at least 1, so a listing can never be coerced into loading a whole table into memory. Filter keys an entity does not implement are reported rather than silently ignored.

### Terminal safety

Every value the shell prints is database content and may be attacker-supplied. Control bytes are neutralised before display: ANSI/OSC escape sequences and other C0/C1 controls are shown in `cat -v` caret notation, tabs and newlines become spaces, and Unicode bidirectional overrides are spelled out — so a crafted attribute value cannot forge output, retitle the window, or make one indicator read as another in the analyst's terminal.

## Navigation Context

Setting a context scopes subsequent operations. For example:

```
MISP [admin@ORGNAME] > use event 8
Context set to event:8

MISP [admin@ORGNAME] event:8 > list attribute
  (lists only attributes belonging to event 8)

MISP [admin@ORGNAME] event:8 > add attribute
  (adds the attribute to event 8 without prompting for event ID)

MISP [admin@ORGNAME] event:8 > list tag
  (lists only tags attached to event 8)

MISP [admin@ORGNAME] event:8 > clear
Context cleared.
```

## Write Operation Examples

### Creating an Event

```
MISP [admin@ORGNAME] > add event

Add Event - fill in fields (* = required):

  info (Event description/title) *: Phishing campaign targeting finance sector
  date (Event date (YYYY-MM-DD)) [2026-03-27]:
  distribution (Distribution level):
    [0] Your organisation only <-- default
    [1] This community only
    [2] Connected communities
    [3] All communities
    [4] Sharing group
  Enter choice [0]:
  threat_level_id (Threat level):
    [1] High
    [2] Medium
    [3] Low
    [4] Undefined <-- default
  Enter choice [4]: 2
  analysis (Analysis state):
    [0] Initial <-- default
    [1] Ongoing
    [2] Completed
  Enter choice [0]:
Create event? [y/N]: y
Event #42 created successfully.
```

### Adding an Attribute to an Event

```
MISP [admin@ORGNAME] > use event 42
Context set to event:42

MISP [admin@ORGNAME] event:42 > add attribute

Add Attribute - fill in fields (* = required):

  type (Attribute type (e.g. ip-dst, domain, md5)) *: ip-dst
  category (Attribute category): Network activity
  value (Attribute value) *: 203.0.113.50
  to_ids (IDS flag (0/1)) (0/1) [1]:
  comment (Comment): C2 server
  distribution (Distribution level):
    ...
  Enter choice [5]:
Create attribute in event #42? [y/N]: y
Attribute #187 created successfully.
```

### Adding an Object

```
MISP [admin@ORGNAME] event:42 > add object
Enter object template name (e.g. file, ip-port, domain-ip):
> file

Template: file v24
File object describing a file with meta-information.

Fill in object attributes (Enter to skip optional fields):

  filename [text] *: malware.exe
  size-in-bytes [size-in-bytes]: 45056
  md5 [md5] *: d41d8cd98f00b204e9800998ecf8427e
  sha1 [sha1]:
  sha256 [sha256]:
  ...

Object will contain 3 attribute(s).
Create object in event #42? [y/N]: y
Object #89 created successfully.
```

### Editing an Attribute

```
MISP [admin@ORGNAME] event:42 > edit attribute 187

Edit Attribute - fill in fields (Enter to keep current value):

  category (Attribute category) [Network activity]:
  type (Attribute type) [ip-dst]:
  value (Attribute value) [203.0.113.50]: 198.51.100.23
  to_ids (IDS flag (0/1)) (0/1) [1]:
  comment (Comment) [C2 server]: Updated C2 server
  ...
Save changes to attribute #187? [y/N]: y
Attribute #187 updated successfully.
```

### Deleting

```
MISP [admin@ORGNAME] > delete event 42
Delete event #42 'Phishing campaign targeting finance sector'? This cannot be undone. [y/N]: y
Event #42 deleted successfully.
Context cleared.
```

Attributes and objects are soft-deleted (marked as deleted but retained in the database).

### Deleting a User

Users support disable (recommended) and hard-delete options:

```
MISP [admin@ORGNAME] > delete user 5

User: analyst@example.org
Recommended: disable instead of delete to preserve audit trails.
  [d] Disable user
  [D] Hard-delete user (irreversible)
  [c] Cancel
  Choice: d
User #5 disabled.
```

## Non-TTY / Piped Mode

When stdin is not a TTY (e.g. piped input), the shell:

- Renders static tables instead of interactive browse mode
- Reads commands line by line from stdin
- Works with scripted input:

```bash
echo -e "list event published=1\nexit" | app/Console/cake CLI 1
```
