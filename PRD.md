# PRD: MISP Interactive CLI Shell (`CLIShell.php`)

## 1. Overview

### 1.1 Purpose
Provide MISP operators with an interactive REPL (Read-Eval-Print Loop) shell for browsing and managing MISP data from the command line. Unlike existing one-shot CakePHP shells (`cake Event import`, `cake User list`), this shell maintains a persistent session with user context, navigation state, and paginated output.

### 1.2 Launch Syntax
```
cake CLI <user_id>
```
The shell authenticates via `User::getAuthUser($userId, true)` and all subsequent operations are ACL-scoped to that user.

### 1.3 Design Principles
- **Reuse existing model methods** (`fetchEvent`, `fetchAttributes`, etc.) -- no raw SQL.
- **ACL always enforced** -- the `$user` array from `getAuthUser()` is passed to every model method.
- **Follow existing shell conventions** -- extend `AppShell`, use `$this->out()` for output, stdin for input (pattern from `TrainingShell`).
- **Singular entity names** in commands (`event`, `attribute`, `object`), with plurals accepted as aliases.

---

## 2. Architecture

### 2.1 File
`/var/www/MISP7/app/Console/Command/CLIShell.php`

### 2.2 Class Structure

```php
class CLIShell extends AppShell
```

**Key properties:**
- `public $uses` -- `Event`, `MispAttribute`, `MispObject`, `Tag`, `EventTag`, `AttributeTag`, `Organisation`, `User`, `Server`, `Feed`, `SharingGroup`, `Galaxy`, `Taxonomy`, `Warninglist`, `GalaxyCluster`
- `private $__user` -- authenticated user array
- `private $__context` -- navigation context: `['entity' => null, 'id' => null]`
- `private $__page` -- current pagination page (default 1)
- `private $__perPage` -- items per page (default 20)
- `private $__lastQuery` -- cached last query params for `next`/`prev`
- `private $__stdin` -- file handle for `php://stdin`

### 2.3 Entity Registry

A private static array mapping entity names to configuration:

```php
private $__entityConfig = [
    'event' => [
        'model' => 'Event',
        'aliases' => ['events'],
        'listFields' => ['id', 'date', 'info', 'Orgc.name', 'threat_level_id', 'analysis', 'published'],
        'editableFields' => ['info', 'date', 'distribution', 'threat_level_id', 'analysis', 'sharing_group_id'],
        // ... methods, etc.
    ],
    'attribute' => [
        'model' => 'MispAttribute',
        'aliases' => ['attributes'],
        'listFields' => ['id', 'event_id', 'type', 'category', 'value', 'to_ids', 'comment'],
        'editableFields' => MispAttribute::EDITABLE_FIELDS,
        // ...
    ],
    // ... other entities
];
```

This registry-driven approach avoids a massive switch statement and makes adding new entity types trivial.

### 2.4 Command Grammar

```
<command> [<entity>] [<id_or_query>] [<key=value> ...]
```

| Command | Syntax | Description |
|---------|--------|-------------|
| `list` | `list <entity> [key=value ...]` | Paginated list with optional filters |
| `view` | `view <entity> <id>` | Detailed view of single record |
| `add` | `add <entity>` | Interactive guided creation |
| `edit` | `edit <entity> <id>` | Interactive field-by-field editing |
| `delete` | `delete <entity> <id>` | Delete with confirmation |
| `search` | `search <entity> [filters]` | Search with restSearch-compatible filters |
| `next` | `next` | Next page (also `n` in browse mode) |
| `prev` | `prev` | Previous page (also `p` in browse mode) |
| `use` | `use <entity> <id>` | Set navigation context |
| `context` | `context` | Show current context |
| `clear` | `clear` | Clear navigation context |
| `tag` | `tag <entity> <id> <tag_name>` | Attach tag |
| `untag` | `untag <entity> <id> <tag_name>` | Detach tag |
| `publish` | `publish event <id>` | Publish an event |
| `help` | `help [command]` | Show help |
| `exit`/`quit` | `exit` | Exit REPL |

### 2.5 Prompt Format

```
MISP [admin@ORGNAME] > list events
MISP [admin@ORGNAME] event:5 > list attributes
```

When context is set, the prompt shows the entity:id. Username (email prefix) and org name are always shown.

### 2.6 Context-Aware Navigation

When context is set (e.g., `use event 5` or after `view event 5`):
- `list attributes` auto-filters to `event_id=5`
- `list objects` auto-filters to `event_id=5`
- `list tags` shows tags for that event
- `add attribute` pre-fills `event_id=5`

### 2.7 Search & Filter System

The filter system mirrors the full power of MISP's restSearch API but with a CLI-native interface. Filters apply to `list` and `search` commands for events, attributes, and objects.

#### 2.7.1 Inline Filter Syntax

Filters are passed as `key=value` pairs on the command line. The syntax supports the same operators as restSearch but in a CLI-friendly form:

```
search <entity> <key>=<value> [<key>=<value> ...]
list <entity> <key>=<value> [<key>=<value> ...]
```

**Simple filters:**
```
search events type=ip-dst published=1 threat_level_id=1
search attributes type=md5 to_ids=1 category="Payload delivery"
search objects object_name=file
```

**Negation** (prefix value with `!`):
```
search attributes type=!ip-src                    # exclude ip-src
search events org=!CIRCL                          # exclude org
```

**Multiple values** (comma-separated, OR logic):
```
search attributes type=ip-dst,ip-src,domain       # any of these types
search events threat_level_id=1,2                  # high or medium
```

**Combined OR + NOT in same filter:**
```
search attributes type=ip-dst,ip-src,!ip-src-port  # ip-dst OR ip-src, NOT ip-src-port
```

**Tag filtering** (supports AND/OR/NOT):
```
search events tag=tlp:white                        # events with this tag (OR)
search events tag=tlp:white,misp-galaxy:*          # events with either tag
search events tag=!tlp:red                         # exclude events with tag
search events tag=tlp:white tag+=malware           # tag= is OR, tag+= is AND (must have both)
```

Tag operators:
- `tag=X,Y` -- event/attribute has tag X **OR** tag Y
- `tag+=X` -- **AND** -- must have this tag (combine multiples: `tag+=X tag+=Y`)
- `tag=!X` -- **NOT** -- must not have this tag

**Date/time ranges:**
```
search events from=2026-01-01 to=2026-03-01       # date range
search events last=7d                              # last 7 days
search events last=2h                              # last 2 hours
search attributes timestamp=1d                     # modified in last day
search events publish_timestamp=30d                # published in last 30 days
```

**Wildcard search** (searches across event info, attribute values, comments, tag names):
```
search events searchall=phishing
search attributes value=%bank%                     # LIKE match with wildcards
```

**Value search for attributes:**
```
search attributes value=198.51.100.23              # exact match
search attributes value=%evil%                     # LIKE match
search attributes value=198.51.100.0/24            # CIDR notation (if supported by type)
```

**Pagination/ordering:**
```
search events limit=50 page=2 order=date
list attributes limit=100
```

#### 2.7.2 Full Parameter List by Scope

**Events** (most common parameters):
| Parameter | Description | Accepts |
|-----------|-------------|---------|
| `value` | Filter by attribute value within events | string, wildcards, OR/NOT |
| `type` | Filter by attribute type | string list, OR/NOT |
| `category` | Filter by attribute category | string list, OR/NOT |
| `org` | Filter by owner org name | string list, OR/NOT |
| `orgc_id` | Filter by creator org ID | int list, OR/NOT |
| `tag` / `tag+` | Tag OR / AND filters | string list, OR/NOT |
| `searchall` | Wildcard across info, values, comments, tags | string |
| `from` | Event date >= | YYYY-MM-DD |
| `to` | Event date <= | YYYY-MM-DD |
| `last` | Events published since | time delta (Nd/Nh/Nm) |
| `eventid` | Specific event IDs | int list, OR/NOT |
| `uuid` | Event UUIDs | string list |
| `published` | Published status | 0/1 |
| `threat_level_id` | Threat level | 1-4, list |
| `analysis` | Analysis state | 0-2, list |
| `timestamp` | Event modification time | time delta or range |
| `publish_timestamp` | Publication time | time delta or range |
| `limit` | Results per page | int |
| `page` | Page number | int |
| `order` | Sort field | field name |

**Attributes** (extends Events, adds):
| Parameter | Description | Accepts |
|-----------|-------------|---------|
| `to_ids` | IDS flag | 0/1 |
| `object_relation` | Relation within object | string list, OR/NOT |
| `first_seen` | First seen timestamp | time delta or range |
| `last_seen` | Last seen timestamp | time delta or range |
| `deleted` | Include soft-deleted | 0/1/2 |
| `includeCorrelations` | Include correlation data | 0/1 |

**Objects** (extends Events, adds):
| Parameter | Description | Accepts |
|-----------|-------------|---------|
| `object_name` | Object template name | string list, OR/NOT |
| `object_template_uuid` | Template UUID | string list |
| `object_template_version` | Template version | int |

#### 2.7.3 Interactive Filter Builder (Browse Mode)

When in browse mode (navigating a list), pressing `f` opens the **filter bar** -- an interactive filter editor at the bottom of the screen:

```
 ID    | Type        | Category            | Value                          | IDS
───────┼─────────────┼─────────────────────┼────────────────────────────────┼─────
 ██101 | ip-dst      | Network activity    | 198.51.100.23                  | Yes ██
   102 | ip-dst      | Network activity    | 203.0.113.45                   | Yes
   103 | domain      | Network activity    | evil-phishing-domain.com       | Yes
   ...

 Active filters: type=ip-dst,domain  to_ids=1  tag=!tlp:red
 ▸ Filter: tag+=tlp:amber█
 [Enter] Apply  [Tab] Autocomplete  [Ctrl+U] Clear line  [Esc] Cancel
```

The filter builder:
1. Shows current active filters in a header line above the input
2. Accepts one `key=value` filter per entry, pressing Enter applies it and the results refresh immediately
3. **Tab-completion** for:
   - Filter keys (`type`, `category`, `tag`, `org`, etc.)
   - Type values (`ip-dst`, `md5`, `sha256`, etc. from `MispAttribute::typeDefinitions`)
   - Category values (`Payload delivery`, `Network activity`, etc. from `MispAttribute::categoryDefinitions`)
   - Tag names (queried from Tag model)
   - Organisation names (queried from Organisation model)
4. Enter with empty input closes the filter bar
5. Typing `-<key>` removes that filter (e.g., `-type` removes the type filter)
6. Typing `--` clears all filters

Filters persist across page navigation (`n`/`p`) and are shown in the browse mode header.

#### 2.7.4 Filter-to-Model Translation

Internally, filters are collected into a `$filters` array matching the restSearch parameter format, then passed to the appropriate model method:

```php
// For events
$this->Event->filterEventIds($this->__user, $filters);
$this->Event->fetchEvent($this->__user, $filters);

// For attributes
$this->MispAttribute->restSearch($this->__user, 'json', $filters);

// For objects
$this->MispObject->restSearch($this->__user, 'json', $filters);
```

The CLI filter parser (`__parseFilters`) converts the CLI syntax to the restSearch format:
- `type=ip-dst,ip-src` → `['type' => ['OR' => ['ip-dst', 'ip-src']]]`
- `type=!ip-src-port` → `['type' => ['NOT' => ['ip-src-port']]]`
- `tag=tlp:white tag+=malware` → `['tags' => ['OR' => ['tlp:white'], 'AND' => ['malware']]]`
- `from=2026-01-01` → `['from' => '2026-01-01']`
- `last=7d` → `['last' => '7d']`

This translation reuses the existing `convert_filters()` and `dissectArgs()` methods in the model layer, so all the SQL generation, subquery logic, and ACL enforcement happens through the same code path as the REST API.

#### 2.7.5 Saved Searches

Frequently used filter combinations can be saved and recalled:

```
MISP [admin@CIRCL] > save-search active-c2 type=ip-dst,domain to_ids=1 last=7d tag=!false-positive
MISP [admin@CIRCL] > search attributes @active-c2
MISP [admin@CIRCL] > list-searches
  active-c2:   type=ip-dst,domain to_ids=1 last=7d tag=!false-positive
  recent-iocs: to_ids=1 last=24h published=1
```

Saved searches are stored in the user's MISP settings or a local config file (`~/.misp_cli_searches.json`).

### 2.8 Terminal Control Layer

The shell uses two terminal modes:

**Normal mode** -- standard line-buffered input for the command prompt and interactive field prompting (add/edit). Uses `readline()` for input with line editing support.

**Browse mode** -- raw terminal input for interactive list navigation. Entered automatically when a `list` or `search` command produces results. Implementation:

1. **Enter raw mode**: `shell_exec('stty -icanon -echo')` to disable line buffering and echo
2. **Render the table** with one row highlighted (inverse video via `\033[7m`)
3. **Read keystrokes** character by character from stdin:
   - Arrow Up (`\033[A`) / `k`: move highlight up
   - Arrow Down (`\033[B`) / `j`: move highlight down
   - Enter: execute `view` on the highlighted row, return to normal mode
   - `n`: next page (re-render with new data)
   - `p`: previous page
   - `e`: edit highlighted item
   - `d`: delete highlighted item (with confirmation in normal mode)
   - `q` / Escape: exit browse mode, return to command prompt
   - `/`: enter search filter (switches to normal mode briefly for input)
4. **Screen redraw**: use `\033[H` (cursor home) + `\033[J` (clear below) to redraw the table region on each keystroke. Only redraw changed rows for efficiency.
5. **Restore terminal**: `shell_exec('stty icanon echo')` on exit from browse mode (also registered as a shutdown function to handle unexpected exits)

**Terminal size detection**: Use `$this->__getTerminalSize()` which calls `stty size` or falls back to 80x24. Used to:
- Calculate column widths and truncation
- Determine how many rows fit in the viewport (terminal height - 3 for header/footer/status)

**Key properties for browse mode:**
- `private $__selectedIndex` -- currently highlighted row (0-based)
- `private $__viewportOffset` -- for scrolling when results exceed screen height
- `private $__browseData` -- current page of results for the active list

### 2.8 Output Formatting

**Interactive table** (`__renderBrowsableTable`):
- Header row with column names and separator line
- Data rows with the selected row in inverse video (`\033[7m...\033[0m`)
- Auto-calculated column widths, long values truncated with `..`
- Footer: `[↑/↓] Navigate  [Enter] View  [e] Edit  [d] Delete  [q] Back  [n/p] Page    Page 1/5 (50 results)`
- Scrolling: if results exceed viewport, the table scrolls to keep the selected row visible

**Detail output** (`__renderDetail`):
- Key-value pairs, one per line, with aligned values
- Nested data (tags, attributes in events) with indentation
- Displayed in normal mode (static, scrollable via terminal's own scroll)

**Color scheme** (ANSI, TTY-detected via `posix_isatty(STDOUT)`):
- Header/borders: default
- Selected row: inverse video (`\033[7m`)
- Published events: green (`\033[32m`)
- Unpublished events: yellow (`\033[33m`)
- High threat level: red (`\033[31m`)
- IDS-flagged attributes: bold (`\033[1m`)
- Error messages: red (`\033[31m`)

### 2.8 REPL Loop (`main()`)

1. Validate `$this->args[0]` as user ID via `User::getAuthUser()`
2. Store in `$this->__user`
3. Open stdin, print welcome banner
4. Loop: print prompt -> read line -> parse -> dispatch -> catch exceptions -> continue
5. Handle EOF for piped input (non-interactive mode)

### 2.9 Model Method Mapping

| Entity | List | View | Add | Edit | Delete |
|--------|------|------|-----|------|--------|
| event | `Event::find('all', ...)` + ACL conditions | `Event::fetchEvent($user, ['eventid'=>$id])` | `Event::save()` | `Event::save()` | `Event::quickDelete()` |
| attribute | `MispAttribute::fetchAttributes($user, ...)` | `MispAttribute::fetchAttributes($user, ['conditions'=>...])` | `MispAttribute::save()` | `MispAttribute::editAttribute()` | `MispAttribute::deleteAttribute()` |
| object | `MispObject::fetchObjects($user, ...)` | `MispObject::fetchObjectSimple($user, ...)` | `MispObject::save()` | `MispObject::editObject()` | `MispObject::deleteObject()` |
| tag | `Tag::find('all', ...)` | `Tag::find('first', ...)` | `Tag::captureTag()` | `Tag::save()` | `Tag::softDelete()` |
| user | `User::find('all', ...)` | `User::getAuthUser($id)` | `User::save()` | `User::save()` | disable via `save(['disabled'=>1])` |
| organisation | `Organisation::find('all', ...)` | `Organisation::find('first', ...)` | `Organisation::save()` | `Organisation::save()` | N/A |
| server | `Server::find('all', ...)` | `Server::find('first', ...)` | `Server::save()` | `Server::save()` | `Server::delete()` |
| feed | `Feed::find('all', ...)` | `Feed::find('first', ...)` | `Feed::save()` | `Feed::save()` | `Feed::delete()` |
| sharing_group | `SharingGroup::fetchAllAuthorised()` | `SharingGroup::find('first', ...)` | `SharingGroup::save()` | `SharingGroup::save()` | `SharingGroup::delete()` |
| galaxy | `Galaxy::find('all', ...)` | `Galaxy::find('first', ...)` | N/A | N/A | N/A |
| taxonomy | `Taxonomy::find('all', ...)` | `Taxonomy::find('first', ...)` | N/A | enable/disable | N/A |
| warninglist | `Warninglist::find('all', ...)` | `Warninglist::find('first', ...)` | N/A | enable/disable | N/A |

### 2.10 ACL Enforcement

- `$this->__user` is passed to all `fetch*()` methods (which already enforce ACL).
- Write operations check ownership: event edits require `orgc_id` match or site_admin.
- Admin-only entities (users, servers) check `$this->__user['Role']['perm_admin']` or `perm_site_admin`.

### 2.11 Error Handling

- Validation errors: display `$model->validationErrors` as readable list
- ACL failures: "Permission denied: you do not have access to this <entity>"
- Not found: "<Entity> with ID <id> not found"
- All errors via `$this->err()`, REPL continues

---

## 3. Implementation Phases

### Phase 1: Skeleton + Read Operations (Events & Attributes)

**Goal:** Working REPL with interactive browsable lists and detail views for events and attributes.

1. Create `CLIShell.php` skeleton extending `AppShell`
   - `$uses` array with core models
   - `getOptionParser()` with `user_id` argument
   - Private properties for state (user, context, page, selectedIndex, browseData, etc.)
2. Implement `main()` -- REPL entry point
   - User validation, stdin setup, welcome banner, main loop
   - Terminal restore on shutdown (`register_shutdown_function`)
3. Implement command parser (`__parseCommand()`)
   - Tokenize, resolve aliases, extract command/entity/id/filters
4. Implement terminal control helpers
   - `__getTerminalSize()` -- via `stty size`, fallback 80x24
   - `__enterRawMode()` / `__exitRawMode()` -- stty raw/cooked toggle
   - `__readKeypress()` -- read single char or escape sequence from stdin
   - TTY detection via `posix_isatty(STDOUT)`
5. Implement `__renderBrowsableTable()` -- interactive table with:
   - Column width calculation and value truncation
   - Highlighted selected row (inverse video)
   - Scrolling when results exceed viewport
   - Footer with keybinding hints and page info
6. Implement browse mode loop (`__browseLoop()`)
   - Enter raw mode, render table, handle keystrokes
   - Arrow keys / j/k to move selection
   - Enter to view, e to edit, d to delete, n/p for pages, q to exit
   - Restore terminal on exit
7. Implement `__renderDetail()` -- key-value detail output with color
8. Implement `list events` -- paginated event listing with ACL, enters browse mode
9. Implement `view event <id>` -- full event detail, auto-set context
10. Implement `list attributes` -- context-aware (filters by event if context set), browse mode
11. Implement `view attribute <id>` -- single attribute detail
12. Implement filter parser (`__parseFilters()`)
    - Parse `key=value` pairs from command args
    - Handle negation (`!` prefix), comma-separated OR, `tag+=` AND syntax
    - Date/time delta parsing (`7d`, `2h`, `YYYY-MM-DD`)
    - Translate to restSearch-compatible `$filters` array
13. Implement `search events [filters]` and `search attributes [filters]`
    - Pass translated filters to `Event::filterEventIds()` / `MispAttribute::restSearch()`
    - Results enter browse mode
14. Implement `list events [filters]` -- same as search but default unfiltered
15. Implement filter bar in browse mode (`f` key)
    - Show active filters in header
    - Single-line input for adding/removing filters
    - Tab-completion for keys and common values (types, categories)
    - Results refresh on Enter
    - `-key` to remove, `--` to clear all
16. Implement `help`, `exit`/`quit`, `context`, `clear`, `use`

**Deliverable:** Operator can launch `cake CLI 1`, browse events with interactive navigation, apply restSearch-compatible filters inline or via the filter bar, drill into events/attributes, and paginate.

**Tests:** Shell lifecycle, event/attribute list/view/search, filter system, context navigation, error handling.

**Docs:** Getting Started, Browse Mode, Event/Attribute listing/viewing, Filter Syntax Reference, Context Navigation.

### Phase 2: Extended Read Operations (All Entities)

**Goal:** Add `list`/`view` for all remaining entity types.

1. Objects -- `list objects`, `view object <id>`
2. Tags -- `list tags`, `view tag <id>`
3. Users (admin-only) -- `list users`, `view user <id>`
4. Organisations -- `list organisations`, `view organisation <id>`
5. Servers (admin-only) -- `list servers`, `view server <id>`
6. Feeds -- `list feeds`, `view feed <id>`
7. Sharing groups -- `list sharing_groups`, `view sharing_group <id>`
8. Galaxies -- `list galaxies`, `view galaxy <id>`
9. Taxonomies -- `list taxonomies`, `view taxonomy <id>`
10. Warninglists -- `list warninglists`, `view warninglist <id>`
11. Refactor to fully use entity registry pattern

**Deliverable:** Complete read coverage across all entity types.

**Tests:** All entity type list/view tests.

**Docs:** Entity Reference section for all types.

### Phase 3: Write Operations (Events & Attributes)

**Goal:** Add `add`, `edit`, `delete` for events and attributes.

1. ~~Implement interactive field prompting (`__promptForField()`)~~ **DONE**
   - ~~Show field name, current value, accepted values, validate input~~
2. `add event` -- prompt for info, date, distribution, threat_level, analysis
3. `edit event <id>` -- fetch, prompt for each editable field, save changes
4. `delete event <id>` -- show summary, confirm, delete
5. `add attribute` -- requires event context; prompt for type, value, to_ids, comment, distribution
6. `edit attribute <id>` -- prompt for EDITABLE_FIELDS
7. `delete attribute <id>` -- confirm, soft-delete

**Deliverable:** Full CRUD for events and attributes.

**Tests:** Event/attribute add/edit/delete tests, delete cancellation, publish.

**Docs:** Managing Data section (adding, editing, deleting events and attributes).

### Phase 4: Write Operations (Remaining Entities + Tags)

**Goal:** Write operations for objects, tags, users, orgs, servers, feeds.

1. Tag/untag commands for events and attributes
2. `add`/`edit`/`delete` for objects
3. User CRUD (site_admin only)
4. Organisation CRUD (admin only)
5. Server CRUD (site_admin only)
6. Feed CRUD
7. Enable/disable for taxonomies and warninglists
8. `publish event <id>`

**Deliverable:** Full write coverage for all entity types.

**Tests:** Tag/untag, object CRUD, user/org/server CRUD, admin-only permission checks.

**Docs:** Tagging, publishing, remaining write operations, admin-only entity docs.

### Phase 5: Polish & Advanced Features

1. Command history persistence (save/load readline history to `~/.misp_cli_history`)
2. Output format toggle: `set format json|table` (json bypasses browse mode)
3. Batch operations with confirmation
4. Server sync: `pull server <id>`, `push server <id>`
5. Export: `export event <id> <format>`
6. Correlation view: `correlations attribute <id>`
7. Column sorting: `s` in browse mode to cycle sort column
8. Saved searches: `save-search <name> [filters]`, `search <entity> @<name>`, `list-searches`
9. Full tab-completion for filter values: tag names, org names queried from DB
10. Filter bar autocomplete for type/category from `MispAttribute::typeDefinitions` / `categoryDefinitions`

---

## 4. Key Design Decisions

### Context Navigation
`use event 5` sets context, shown in prompt, auto-filters subsequent list commands. This is the most important UX feature -- it mimics directory navigation for efficient drilling into data.

### Entity Registry
Config-driven dispatch avoids a massive switch statement. Adding a new entity type = adding an entry to the array.

### Two Terminal Modes
The shell alternates between **normal mode** (line-buffered, for the command prompt and field input) and **browse mode** (raw, for interactive list navigation). This separation keeps the architecture clean -- browse mode is a self-contained loop that returns control to the REPL when the user presses `q` or Enter.

### Pagination via Stored State
Store last query params + page number. `n`/`p` in browse mode changes page and re-renders. Total count fetched on first query and cached.

### Interactive Field Prompting
For `add`/`edit`, each field prompted one at a time with validation in normal mode. Safer than free-form JSON input for operators.

### Terminal Safety
Always restore terminal state (`stty icanon echo`) via both explicit cleanup and `register_shutdown_function`. A broken terminal from an unclean exit is the worst possible UX failure.

### Non-interactive Fallback
When stdin is not a TTY (piped input), skip browse mode entirely and output static tables. This allows scripted usage: `echo "list events" | cake CLI 1`.

---

## 5. Test Suite

### 5.1 Overview

File: `/var/www/MISP7/tests/test_cli_shell.py`

A Python test suite using `unittest` (matching the existing test conventions in `testlive_comprehensive_local.py`) that tests the CLI shell by invoking it via `subprocess` with piped stdin/stdout. Since the interactive browse mode requires a TTY, tests use a **non-interactive piped mode** where commands are sent via stdin and output is captured as static text.

### 5.2 Test Configuration

Uses the same environment variable pattern as existing tests:
```python
url = "http://" + os.environ["HOST"]
key = os.environ["AUTH"]
```

The test suite needs a valid `user_id` for the `cake CLI <user_id>` invocation. During `setUpClass`, it creates a test org and test user via PyMISP (same pattern as `testlive_comprehensive_local.py`), then uses that user's ID for all CLI invocations.

### 5.3 CLI Invocation Helper

```python
def run_cli(self, commands, user_id=None, timeout=30):
    """Send commands to the CLI shell via piped stdin, return stdout."""
    if user_id is None:
        user_id = self.test_user_id
    input_text = "\n".join(commands + ["exit"]) + "\n"
    result = subprocess.run(
        ["php", self.cake_path, "CLI", str(user_id)],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=self.app_path
    )
    return result.stdout, result.stderr, result.returncode
```

Since stdin is not a TTY in subprocess, the shell should detect this and:
- Skip browse mode (output static tables instead)
- Skip interactive prompts for add/edit (accept pre-formatted input lines)
- Output in a parseable format (consistent column delimiters)

### 5.4 Test Data Setup/Teardown

`setUpClass` creates test fixtures via PyMISP:
- Test organisation
- Test user (org admin) + site admin user
- 3-5 test events with varied threat levels, distributions, published states
- Attributes of various types (ip-dst, domain, md5, url, email-src) across the events
- Objects (file object with attributes)
- Tags attached to events and attributes
- Test feeds, sharing groups (if admin)

`tearDownClass` cleans up all test data via PyMISP.

### 5.5 Test Cases

#### 5.5.1 Shell Lifecycle
| Test | Description |
|------|-------------|
| `test_shell_launches` | Shell starts with valid user_id, prints welcome banner with username and org |
| `test_shell_invalid_user` | Shell exits with error for non-existent user_id |
| `test_shell_exit` | `exit` command terminates cleanly with return code 0 |
| `test_shell_quit` | `quit` command terminates cleanly |
| `test_shell_eof` | Shell exits cleanly when stdin reaches EOF |
| `test_shell_unknown_command` | Unknown command prints error, shell continues |

#### 5.5.2 Event Operations
| Test | Description |
|------|-------------|
| `test_list_events` | `list events` returns table with test events, correct columns (id, date, info, org, threat, published) |
| `test_list_events_pagination` | `list events limit=2` then `next` returns different results |
| `test_view_event` | `view event <id>` shows full event detail with correct fields |
| `test_view_event_not_found` | `view event 999999` shows "not found" error |
| `test_view_event_sets_context` | After `view event <id>`, prompt shows `event:<id>` context |
| `test_search_events_by_info` | `search events searchall=<test_string>` finds matching events |
| `test_search_events_by_type` | `search events type=ip-dst` finds events containing ip-dst attributes |
| `test_search_events_by_tag` | `search events tag=<test_tag>` finds tagged events |
| `test_search_events_by_tag_negation` | `search events tag=!<test_tag>` excludes tagged events |
| `test_search_events_by_date_range` | `search events from=<date> to=<date>` filters correctly |
| `test_search_events_by_threat_level` | `search events threat_level_id=1` returns only high threat events |
| `test_search_events_by_published` | `search events published=1` vs `published=0` return correct sets |
| `test_search_events_combined_filters` | `search events type=ip-dst published=1 threat_level_id=1` combines filters with AND |
| `test_add_event` | `add event` with piped field inputs creates event, verify via PyMISP |
| `test_edit_event` | `edit event <id>` with piped field inputs modifies event, verify via PyMISP |
| `test_delete_event` | `delete event <id>` with `y` confirmation deletes event, verify via PyMISP |
| `test_delete_event_cancelled` | `delete event <id>` with `n` does not delete |
| `test_publish_event` | `publish event <id>` publishes, verify via PyMISP |

#### 5.5.3 Attribute Operations
| Test | Description |
|------|-------------|
| `test_list_attributes` | `list attributes` returns table with attributes |
| `test_list_attributes_in_context` | After `use event <id>`, `list attributes` shows only that event's attributes |
| `test_view_attribute` | `view attribute <id>` shows full attribute detail |
| `test_search_attributes_by_type` | `search attributes type=ip-dst` filters by type |
| `test_search_attributes_by_value` | `search attributes value=198.51.100.23` finds exact match |
| `test_search_attributes_by_value_wildcard` | `search attributes value=%198.51%` finds LIKE match |
| `test_search_attributes_by_category` | `search attributes category="Network activity"` filters by category |
| `test_search_attributes_by_to_ids` | `search attributes to_ids=1` returns only IDS-flagged |
| `test_search_attributes_multi_type` | `search attributes type=ip-dst,ip-src,domain` OR logic |
| `test_search_attributes_type_negation` | `search attributes type=!comment` excludes comment type |
| `test_search_attributes_tag_and` | `search attributes tag=<tag1> tag+=<tag2>` AND logic |
| `test_search_attributes_timestamp` | `search attributes timestamp=1d` finds recently modified |
| `test_add_attribute` | `add attribute` within event context creates attribute, verify via PyMISP |
| `test_add_attribute_no_context` | `add attribute` without event context prompts for event_id or errors clearly |
| `test_edit_attribute` | `edit attribute <id>` modifies attribute, verify via PyMISP |
| `test_delete_attribute` | `delete attribute <id>` soft-deletes attribute, verify via PyMISP |

#### 5.5.4 Object Operations
| Test | Description |
|------|-------------|
| `test_list_objects` | `list objects` returns objects table |
| `test_list_objects_in_context` | After `use event <id>`, shows only that event's objects |
| `test_view_object` | `view object <id>` shows object with its attributes |
| `test_search_objects_by_name` | `search objects object_name=file` filters by template name |

#### 5.5.5 Tag Operations
| Test | Description |
|------|-------------|
| `test_list_tags` | `list tags` returns tags table |
| `test_view_tag` | `view tag <id>` shows tag detail |
| `test_tag_event` | `tag event <id> <tag_name>` attaches tag, verify via PyMISP |
| `test_untag_event` | `untag event <id> <tag_name>` detaches tag, verify via PyMISP |
| `test_tag_attribute` | `tag attribute <id> <tag_name>` attaches tag |

#### 5.5.6 Context Navigation
| Test | Description |
|------|-------------|
| `test_use_sets_context` | `use event <id>` sets context, reflected in prompt |
| `test_context_shows_current` | `context` command displays current context |
| `test_clear_resets_context` | `clear` removes context |
| `test_view_auto_sets_context` | `view event <id>` sets context to that event |
| `test_context_filters_attributes` | In event context, `list attributes` is scoped to event |
| `test_context_filters_objects` | In event context, `list objects` is scoped to event |
| `test_context_filters_tags` | In event context, `list tags` shows event's tags |

#### 5.5.7 Admin-Only Operations
| Test | Description |
|------|-------------|
| `test_list_users_as_admin` | Site admin can `list users` |
| `test_list_users_as_non_admin` | Non-admin gets "Permission denied" for `list users` |
| `test_list_servers_as_admin` | Site admin can `list servers` |
| `test_list_servers_as_non_admin` | Non-admin gets "Permission denied" |
| `test_view_user` | `view user <id>` shows user detail (admin) |

#### 5.5.8 Other Entity Types
| Test | Description |
|------|-------------|
| `test_list_organisations` | `list organisations` returns orgs |
| `test_view_organisation` | `view organisation <id>` shows detail |
| `test_list_galaxies` | `list galaxies` returns galaxies |
| `test_list_taxonomies` | `list taxonomies` returns taxonomies |
| `test_list_warninglists` | `list warninglists` returns warninglists |
| `test_list_sharing_groups` | `list sharing_groups` returns sharing groups |
| `test_list_feeds` | `list feeds` returns feeds |

#### 5.5.9 Filter System
| Test | Description |
|------|-------------|
| `test_filter_or_logic` | `type=ip-dst,domain` returns both types |
| `test_filter_not_logic` | `type=!comment` excludes comment |
| `test_filter_combined_or_not` | `type=ip-dst,ip-src,!ip-src-port` mixed |
| `test_filter_tag_or` | `tag=tlp:white,tlp:green` either tag |
| `test_filter_tag_and` | `tag+=tag1 tag+=tag2` must have both |
| `test_filter_tag_not` | `tag=!false-positive` excludes tag |
| `test_filter_date_from_to` | `from=YYYY-MM-DD to=YYYY-MM-DD` range |
| `test_filter_last` | `last=7d` relative time |
| `test_filter_searchall` | `searchall=phishing` across all fields |
| `test_filter_value_wildcard` | `value=%partial%` LIKE match |
| `test_filter_empty_results` | Filters that match nothing return "No results" message |
| `test_filter_persistence_across_pages` | Filters applied, `next` keeps same filters |

#### 5.5.10 Error Handling
| Test | Description |
|------|-------------|
| `test_invalid_entity` | `list foobar` shows "Unknown entity" error |
| `test_missing_entity` | `list` without entity shows usage hint |
| `test_missing_id_for_view` | `view event` without ID shows usage hint |
| `test_invalid_id` | `view event abc` shows "Invalid ID" error |
| `test_acl_denied_event` | Viewing another org's private event shows "not found" or "permission denied" |
| `test_edit_without_permission` | Editing another org's event shows permission error |

#### 5.5.11 Help System
| Test | Description |
|------|-------------|
| `test_help` | `help` shows command list |
| `test_help_specific_command` | `help list` shows list command details |
| `test_help_filter_syntax` | `help filters` shows filter syntax reference |

### 5.6 Test Execution

```bash
cd /var/www/MISP7/tests
HOST=localhost AUTH=<admin_auth_key> python -m unittest test_cli_shell -v
```

Or individual test classes:
```bash
HOST=localhost AUTH=<admin_auth_key> python -m unittest test_cli_shell.TestCLIShellEvents -v
```

### 5.7 Test Implementation Phases

Tests should be implemented in parallel with the corresponding CLIShell phase:
- **Phase 1 tests**: Shell lifecycle, event list/view/search, attribute list/view/search, filter system, context navigation
- **Phase 2 tests**: All remaining entity type list/view
- **Phase 3 tests**: Event/attribute add/edit/delete
- **Phase 4 tests**: Tag/untag, object CRUD, user/org/server CRUD, admin-only checks
- **Phase 5 tests**: Help system completeness, edge cases

---

## 6. Documentation

### 6.1 Overview

File: `/var/www/MISP7/docs/CLI.md`

A comprehensive user guide for the interactive CLI shell, following the existing mkdocs Markdown format used in the `docs/` directory. Added to the mkdocs navigation in `mkdocs.yml`.

### 6.2 Document Structure

```markdown
# MISP Interactive CLI Shell

## Getting Started
### Launching the Shell
### Authentication and User Context
### The Prompt
### Exiting

## Browsing Data
### Listing Records
### Interactive Navigation (Browse Mode)
#### Keyboard Shortcuts
### Viewing Record Details
### Context Navigation
#### Setting Context
#### How Context Affects Commands
#### Clearing Context

## Searching and Filtering
### Inline Filters
### Filter Syntax Reference
#### Simple Filters
#### OR Filters (Comma-Separated Values)
#### NOT Filters (! Prefix)
#### AND Filters for Tags (tag+=)
#### Date and Time Filters
#### Wildcard Search (searchall)
#### Value Wildcards
### Interactive Filter Bar
### Supported Parameters
#### Event Parameters
#### Attribute Parameters
#### Object Parameters
### Examples
#### Common Search Patterns
#### Combining Filters

## Managing Data
### Adding Records
#### Adding Events
#### Adding Attributes
#### Adding Objects
### Editing Records
### Deleting Records
### Tagging and Untagging
### Publishing Events

## Entity Reference
### Events
### Attributes
### Objects
### Tags
### Users (Admin Only)
### Organisations
### Servers (Admin Only)
### Feeds
### Sharing Groups
### Galaxies
### Taxonomies
### Warninglists

## Non-Interactive Mode
### Piping Commands
### Scripting Examples

## Troubleshooting
### Terminal Issues
### Permission Errors
### Common Errors
```

### 6.3 Key Documentation Sections

#### Getting Started

Covers launch syntax, what user_id means, how ACL scoping works, and the welcome banner. Includes a quick walkthrough:

```
$ cd /var/www/MISP && app/Console/cake CLI 1

Welcome to MISP Interactive CLI Shell v1.0
Logged in as: admin@admin.test (ORGNAME) [Site Admin]
Type 'help' for available commands.

MISP [admin@ORGNAME] > list events
```

#### Browse Mode Reference

Visual guide showing the interactive table with keybinding reference:

```
 ID  | Date       | Info                              | Org   | Threat | Pub
─────┼────────────┼───────────────────────────────────┼───────┼────────┼─────
 ██5 | 2026-03-25 | Phishing campaign targeting fi..  | CIRCL | High   | Yes ██
   4 | 2026-03-22 | Ransomware distribution via ma..  | CERT  | High   | Yes
   3 | 2026-03-20 | Suspicious DNS queries to DGA ..  | CIRCL | Medium | No

 [↑/↓/j/k] Navigate  [Enter] View  [e] Edit  [d] Delete
 [f] Filter  [n/p] Page  [q] Back              Page 1/3 (45 results)
```

Keybinding table:
| Key | Action |
|-----|--------|
| ↑ / k | Move selection up |
| ↓ / j | Move selection down |
| Enter | View selected record in detail |
| e | Edit selected record |
| d | Delete selected record (with confirmation) |
| f | Open filter bar |
| n | Next page |
| p | Previous page |
| q / Escape | Exit browse mode, return to prompt |

#### Filter Syntax Reference

Comprehensive reference with examples for every filter type, organized as a quick-reference table + detailed examples:

| Syntax | Meaning | Example |
|--------|---------|---------|
| `key=value` | Exact match | `type=ip-dst` |
| `key=a,b,c` | OR (any of) | `type=ip-dst,domain,url` |
| `key=!value` | NOT (exclude) | `type=!comment` |
| `key=a,!b` | OR + NOT | `type=ip-dst,!ip-src-port` |
| `tag=X` | Tag OR | `tag=tlp:white` |
| `tag+=X` | Tag AND (must have) | `tag+=tlp:white tag+=malware` |
| `tag=!X` | Tag NOT (must not have) | `tag=!false-positive` |
| `from=DATE` | Date >= | `from=2026-01-01` |
| `to=DATE` | Date <= | `to=2026-03-31` |
| `last=DELTA` | Since time delta | `last=7d`, `last=2h` |
| `searchall=TEXT` | Wildcard across all fields | `searchall=phishing` |
| `value=%TEXT%` | LIKE match | `value=%bank%` |

#### Workflow Examples

Real-world usage scenarios:

```
# Investigate recent high-threat events
MISP [analyst@CIRCL] > search events threat_level_id=1 last=30d published=1

# Drill into a suspicious event
(select event 42 in browse mode, press Enter)

# List its network indicators
MISP [analyst@CIRCL] event:42 > list attributes type=ip-dst,domain,url to_ids=1

# Search for a specific IOC across all events
MISP [analyst@CIRCL] > clear
MISP [analyst@CIRCL] > search attributes value=198.51.100.23

# Find all events tagged with a specific threat actor, excluding false positives
MISP [analyst@CIRCL] > search events tag=misp-galaxy:threat-actor="APT28" tag=!false-positive
```

### 6.4 mkdocs Integration

Add the new doc to `mkdocs.yml` navigation:

```yaml
nav:
    - Home: 'index.md'
    - 'CLI Shell': 'CLI.md'      # <-- new entry
    - Install Guides:
      ...
```

### 6.5 Documentation Phases

- **Phase 1**: Getting Started, Browse Mode, Event/Attribute listing/viewing, Filter Syntax, Context Navigation
- **Phase 2**: Entity Reference for all types
- **Phase 3**: Managing Data (add/edit/delete) for events and attributes
- **Phase 4**: Remaining write operations, tagging, publishing
- **Phase 5**: Non-interactive mode, scripting, saved searches, troubleshooting

---

## 7. Risk Areas

1. **Model method inconsistency** -- not all models have uniform `fetch*()` methods. Some entities (galaxies, taxonomies) are managed via JSON updates, not direct CRUD. Shell should indicate "not supported" where appropriate.
2. **Large result sets** -- `fetchEvent()` with all includes can be slow. List views should use minimal fields (`recursive => -1`). Detail views can afford full fetch.
3. **Transaction safety** -- use existing validated methods (`editAttribute()`, `_edit()`) rather than raw `save()` where possible.
4. **Signal handling** -- REPL should handle Ctrl+C gracefully (continue loop, not exit). Use `pcntl_signal()` if available.
5. **Testing browse mode** -- the interactive browse mode requires a TTY and cannot be tested via subprocess with piped stdin. Tests validate the non-interactive (piped) output path. Manual testing is needed for browse mode keyboard navigation. Consider using `pexpect` (Python) for TTY-emulated testing if full browse mode coverage is needed.
6. **Test isolation** -- tests create and destroy test data, but failures mid-test can leave orphaned records. `tearDownClass` should be robust and clean up even after partial failures.
