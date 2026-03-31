# MISP Interactive CLI Shell

An interactive REPL for browsing and managing MISP data from the terminal.

## Getting Started

```bash
cd /var/www/MISP
app/Console/cake CLI <user_id>
```

All operations are ACL-scoped to the specified user. The prompt displays the current user, organisation, and navigation context:

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

### General

- All operations respect the authenticated user's ACL
- `user`, `server`, and `role` entities require site admin access
- Write operations (add/edit/delete) require event modify permissions:
  - Site admins can modify any event
  - Org admins can modify events from their organisation
  - Regular users can modify events they created

### List View ACL

Attribute and object list queries enforce distribution-based ACL for non-admin users:

- Attributes/objects with distribution 0 (org only) are only visible if the user's organisation owns the parent event
- Attributes/objects with distribution 4 (sharing group) are only visible if the user is authorised for that sharing group
- All other distribution levels (1-3, 5) are visible to all users

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
