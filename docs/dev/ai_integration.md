# AI integration (`ai_connector`)

MISP can hand an event or an event report to an AI module and take back a
summary or a list of tag suggestions. The module is `ai_connector`, a
misp-module maintained in its own repository; MISP hard-wires its name and
speaks one small contract to it. This document is the developer reference:
what MISP sends and expects, where the actions live, who may use them, and
how to test without an LLM.

---

## 1. The three actions

| Action | Input sent | `use_case` | Result | Trigger points |
|---|---|---|---|---|
| **Summarise event** (A2) | the full event, REST shape without correlations | `summarization_on_event` | one **new** event report on the event | side menu *AI actions* chooser; button next to *Generate report from Event* in the event reports section |
| **Summarise report** (A1) | one event report + its event | `summarization_on_eventReport` | the report's content **overwritten** with the summary block on top | robot icon in the report row; *AI → Summarise report* in the report page menu; the workflow action node |
| **Recommend tags** (A3) | the full event | `tag_suggest` | tags the user accepts are attached (created when missing) | *AI actions* chooser; robot button in the event's tag element |

A1 and A2 run as background jobs (`ai_summarize_event` / `ai_summarize_report`
on the default queue, `cake Event aiSummarize <user_id> <event|report> <id>
[job_id]`) and synchronously when `MISP.background_jobs` is off. A3 runs
inline: the suggestions are previewed in a modal and nothing is saved until
the user accepts a selection.

Every surface is hidden while `Plugin.AI_services_enable` is off, and the
actions answer `405` then.

---

## 2. Module family `AI`

`ai_connector` is discovered like any misp-module, through a new family:

- `Module::VALID_TYPES['AI'] = ['ai']`, `Module::TYPE_TO_FAMILY['AI'] = 'AI'`,
  `Module::AI_MODULE_NAME = 'ai_connector'`.
- The module declares `"module-type": ["ai"]` in its `meta`; misp-modules
  does not validate that list, so no misp-modules change is needed whichever
  directory the module sits in.
- The family is deliberately **not** routed through `/modules` discovery for
  its settings (`Server::getCurrentServerSettings()`): the AI settings are
  static `Plugin.AI_*` entries with one family switch, not per-module
  `_enabled`/`_restrict` toggles.

`Module::queryAI($useCase, array $data, $timeout = null)` builds the request,
posts it to `<AI_services_url>:<AI_services_port>/query` and returns the
module's `results`; it throws on a disabled family, a transport error, a
non-JSON answer or an `error` key. `Module::aiStatus()` backs the status card
of the settings tab.

---

## 3. The contract

### 3.1 Request — `POST /query`

```json
{
  "module":   "ai_connector",
  "use_case": "summarization_on_event | summarization_on_eventReport | tag_suggest",
  "data":     {"Event": {...}}  or  {"EventReport": {...}, "Event": {...}},
  "params":   {"openai_api_base": "...", "api_key": "...", "model_id": "...", "temperature": 0.2,
               "request_timeout": 120, "suggest_limit": 5, "suggest_min_score": 0.0},
  "timeout":  300
}
```

- `params` are the MISP settings of §4, keyed by the module's own config
  names (`Module::AI_PARAM_SETTINGS`, the setting name without `AI_`); the
  module treats them as overrides of its `.env`. Unset (`null`/`''`) settings
  are left out, `0` is sent. The endpoint and key come from MISP.
- `timeout` is `Plugin.AI_timeout`; misp-modules honours it per request.
- The event is `Event::fetchEventForAi()`: `fetchEvent` + `JSONConverterTool`,
  all tags, no correlations.

### 3.2 Response — only what was produced, or an error, never partial

```json
{"results": {"EventReport": {"name": "...", "content": "..."}}}   // both summaries
{"results": {"Tag": [{"name": "tlp:amber"}, {"name": "misp-galaxy:threat-actor=\"APT1\""}]}}   // tag_suggest
{"error": "..."}
```

### 3.3 The AI summary block (A1)

The module answers with the **full revised report**: on top a `# AI summary`
heading, the summary, a blank line, a delineator line of equals signs
(`==================`), a blank line, then the report. The block is plain
Markdown and visible in every renderer.

```
# AI summary
- what happened, in three bullets

==================

# Incident notes
...the analyst's text...
```

MISP keys on the pair *heading on top + delineator*
(`EventReport::AI_SUMMARY_BLOCK_REGEX`): `EventReport::stripAiSummary()`
removes an existing block before the report is sent, so the module always
sees the original text, and `EventReport::mergeAiSummary()` lays the block
out again on every merge (the blank line before the delineator keeps
Markdown from reading the equals line as a setext heading). A report that
merely contains an equals line somewhere is never touched; a re-run replaces
the block instead of stacking a second one. A block-only or bare-text answer
is put on top of the original, so a run can never lose the analyst's text.

---

## 4. Settings — the *AI* tab of the server settings

All under `Plugin.AI_*`, lifted to their own tab (`ServerSettingGroups`,
groups *Connection* / *Model* / *Tag recommendation*). The tab also carries a
status card (family on/off, module server reachable, `ai_connector` listed
with its version), a dry run (event id + use-case → the answer is shown, the
event untouched; site admin, `POST /servers/aiDryRun`) and a greyed *Test
LLM* button reserved for a `ping` use-case the module may offer later.

| Setting | Type | Default | Sent as `params` |
|---|---|---|---|
| `AI_services_enable` | boolean | `false` | family switch |
| `AI_services_url` | string | `http://127.0.0.1` | |
| `AI_services_port` | numeric | `6666` | |
| `AI_timeout` | numeric | `300` | request `timeout` |
| `AI_ssl_verify_peer` / `AI_ssl_verify_host` | boolean | `true` | |
| `AI_ssl_allow_self_signed` | boolean | `false` | |
| `AI_ssl_cafile` | string | `''` | |
| `AI_openai_api_base` | string | `http://127.0.0.1:11434/v1` | `openai_api_base` |
| `AI_api_key` | string, redacted | `''` | `api_key` |
| `AI_model_id` | string | `gemma4:12b` | `model_id` |
| `AI_temperature` | float (0..2) | `0` | `temperature` |
| `AI_request_timeout` | numeric | `120` | `request_timeout` |
| `AI_suggest_limit` | numeric (1..10) | `5` | `suggest_limit` |
| `AI_suggest_min_score` | float (0..1) | `0` | `suggest_min_score` |

`float` is a new server-setting type (`Server::normaliseSettingValue()`,
`floatInRange()`/`integerInRange()` validators, `type=number step=any` in
both edit views). `AI_api_key` is `redacted` and `SystemSetting::isSensitive()`
covers `api_key` names, so it is encrypted at rest when a key is configured
and never shown.

---

## 5. Permissions

- **`perm_ai_tools`** ("AI tools"): a role flag added by migration **160**
  (`roles.perm_ai_tools`, granted to roles with `perm_site_admin` at
  migration time; other roles get it from the role editor). Required by all
  three actions and the two *AI actions* surfaces; buttons are hidden without
  it (`ACLComponent`: `events.aiActions/aiSummarize/aiRecommendTags`,
  `eventReports.aiSummarize`). Requires a logout to take effect, like the
  other role flags.
- **A1, A2:** `perm_ai_tools` + edit rights on the event
  (`ACLComponent::canModifyEvent`, mirrored for workers by
  `Event::userCanModifyEvent()`). The worker re-applies both checks at write
  time as the requesting user (`SysLogLogableBehavior::setShellUser()` so the
  audit row names that user).
- **A3:** `perm_ai_tools` + `canModifyTag` semantics: edit rights attach
  **global** tags; a host-org tagger without edit rights may still accept
  suggestions, attached as **local** tags. Creating a tag unknown to the
  instance needs `perm_tag_editor`; without it those rows are shown disabled
  and refused on accept.
- Settings tab and dry run: site admin.
- The workflow node runs under the workflow's executing user like every other
  action node, no extra gate.

---

## 6. A3 in detail — `EventsController::aiRecommendTags($id)`

- `GET` queries the module synchronously and answers the classified list
  (JSON for REST, the checkbox modal for the browser):
  `{event_id, local, Tag: [{name, colour, exists, is_galaxy, cluster_id,
  tag_id, status, selectable, reason}]}`.
- `POST {"tags": [names]}` attaches the accepted names and answers
  `{saved, success, message, check_publish, attached, created, skipped,
  failed, errors: {name: reason}, local}`. The names are classified again
  server-side, so the client is bound by the same rules it was shown.

Statuses (`Event::AI_TAG_*`, `Event::classifyAiTagSuggestions()`):

| status | meaning | selectable |
|---|---|---|
| `ok` | attachable | yes |
| `present` | already on the event (global or local) | no, counted as skipped |
| `needs_tag_editor` | unknown tag and the user lacks `perm_tag_editor` | no |
| `unknown_cluster` | `misp-galaxy:` name with neither a cluster nor a tag row | no |
| `restricted` | tag reserved for another organisation or user | no |
| `local_only` | tag (or galaxy) may only be attached locally, attach is global | no |
| `exclusive` | refused by taxonomy exclusivity against the event's tags | no |

Galaxy-cluster names are resolved through `GalaxyCluster.tag_name` and
attached with `Galaxy::attachCluster()` (which creates the tag row from the
cluster); plain names go through `Tag::quickAdd()` + `EventTag::attachTagToEvent()`
with a `logs` row like `addTag`. A global attach unpublishes the event once;
a local attach does not touch it. Exclusivity is re-checked as accepted tags
accumulate, so two exclusive tags accepted together yield one refusal.

---

## 7. Workflow action node

`Module_ai_summarize_report` (**id kept:** `send-report-to-cti-info-extractor`,
name *Summarise report with AI*, version 0.2) is the reworked successor of the
CTIInfoExtractor node: stored nodes keep working, their old parameters are
ignored. It sends every matching event report (whole event, or the reports a
filter selects) through the A1 path and **skips reports that already carry an
AI summary** — the engine has no re-entrancy guard and `event-report-after-save`
is a non-blocking trigger, so a workflow on that trigger holding this node
would otherwise feed its own edit back forever. A replace is done from the
report page.

---

## 8. Testing without an LLM

- **`tests/ai_fake_module_server.py`** — a standard-library fake of the module
  (`/modules`, `/query` per use-case with deterministic answers, `/last` for
  what MISP sent, `/health`; `--fail`, `--delay`, `params.model_id =
  fake:error`). Point the instance at it:
  `Plugin.AI_services_enable = true`, `AI_services_url = http://127.0.0.1`,
  `AI_services_port = <port>`.
- **`tests/testlive_ai_ux.py`** — the end-to-end suite (run in CI after
  `testlive_security.py`): starts the fake itself, exercises settings, dry
  run, A1, A2, A3 with three roles (org tagger without tag editor, host-org
  tag editor without edit rights, reader without `perm_ai_tools`), the
  refusals, the ACL codes and the workflow node, then restores every setting
  and removes its fixtures. `HOST=127.0.0.1:5007 AUTH=<key> python3
  tests/testlive_ai_ux.py -v`.
- **PHPUnit** (`app/Test/`): `ModuleAiRequestTest` (envelope, params),
  `ServerSettingFloatTypeTest`, `EventReportAiSummaryTest` (strip/merge),
  `EventAiTagSuggestionTest` (classification, result message).

---

## 9. File map

| Area | Files |
|---|---|
| Family + request | `app/Model/Module.php` |
| Settings, float type | `app/Model/Server.php`, `app/Model/SystemSetting.php`, `app/Lib/Tools/ServerSettingGroups.php`, `app/Console/Command/AdminShell.php`, `app/View/Servers/*`, `app/View/Elements/healthElements/ai_*.ctp`, `app/View/Themed/Overmind/Elements/healthElementsBS5/ai_*.ctp`, `ServersController::aiDryRun` |
| Role flag | `app/Model/Role.php`, `app/Model/AppModel.php` (case 160), `db_schema.json` |
| A2 | `EventsController::aiActions/aiSummarize`, `Event::aiSummarizeRouter/aiSummarize/fetchEventForAi`, `EventShell::aiSummarize`, `Events/ajax/aiActions.ctp`, `Events/ajax/aiSummarizeConfirmationForm.ctp` (+ Overmind twins), side menu / `event_actions.ctp`, `EventReports/ajax/indexForEvent.ctp`, Overmind `Elements/EventReports/index.ctp` |
| A1 | `EventReportsController::aiSummarize`, `EventReport::stripAiSummary/mergeAiSummary/aiSummarize/aiSummarizeRouter`, `EventReports/ajax/aiSummarizeConfirmationForm.ctp` (+ twin), report row + page menu (`event-report.js`, `reportEditor.ctp`, Overmind `eventReport_content.ctp`), `WorkflowModules/action/Module_ai_summarize_report.php` |
| A3 | `EventsController::aiRecommendTags`, `Event::classifyAiTagSuggestions/aiClassifyTagNames/aiRecommendTags/aiAttachTags/aiTagResultMessage`, `Events/ajax/aiRecommendTags.ctp` (+ twin), `Elements/ajaxTags.ctp`, Overmind `Elements/Events/View/event_tags.ctp` |
| Tests | `tests/ai_fake_module_server.py`, `tests/testlive_ai_ux.py`, `app/Test/*Ai*Test.php`, `app/Test/ServerSettingFloatTypeTest.php` |
