# AI integration (`ai_connector`)

MISP can hand an event or an event report to an AI module and take back a
summary, a list of tag suggestions, or the indicators it read out of the
event's reports. The module is `ai_connector`, a
misp-module maintained in its own repository; MISP hard-wires its name and
speaks one small contract to it. This document is the developer reference:
what MISP sends and expects, where the actions live, who may use them, and
how to test without an LLM.

---

## 1. The four actions

| Action | Input sent | `use_case` | Result | Trigger points |
|---|---|---|---|---|
| **Summarise event** (A2) | the full event, REST shape without correlations | `summarization_on_event` | one **new** event report on the event; the event tagged `ai-computer-assisted` | side menu *AI actions* chooser; button next to *Generate report from Event* in the event reports section |
| **Summarise report** (A1) | one event report + its event | `summarization_on_eventReport` | the report's content **overwritten** with the summary block on top; the event tagged | robot icon in the report row; *AI → Summarise report* in the report page menu; the workflow action node |
| **Recommend tags** (A3) | the full event | `tag_suggest` | tags the user accepts are attached (created when missing); the event tagged when at least one is | *AI actions* chooser; robot button in the event's tag element |
| **Extract indicators** (A4) | the full event, reports included | `infoextraction` | the module's new attributes and `file` / `vulnerability` objects added to the event, each tagged `ai-computer-assisted` with the source report in its comment | *AI actions* chooser; button next to *Summarise with AI* in the event reports section; *AI → Extract indicators* in the report page menu (that report only); the workflow action node; REST |

Plus **Test LLM** on the AI settings tab: `use_case` `ping`, no data — the
module checks that the LLM endpoint is reachable and serves the configured
model (§4).

A1 and A2 run as background jobs (`ai_summarize_event` / `ai_summarize_report`
on the default queue, `cake Event aiSummarize <user_id> <event|report|extract> <id>
[job_id]`) and synchronously when `MISP.background_jobs` is off. A3 runs
inline: the suggestions are previewed in a modal and nothing is saved until
the user accepts a selection. A4 has two modes (§6b): in the browser the
module is queried synchronously and its answer is **reviewed** on the screen
import modules use before anything is saved; over REST and from the workflow
node the extraction is **applied directly** (a job when background jobs are
on).

Everything the module produces carries the two `ai-computer-assisted`
provenance tags (§3.4).

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

`Module::queryAI($useCase, array $data, $timeout = null, &$metadata = null)`
builds the request, posts it to `<AI_services_url>:<AI_services_port>/query`
and returns the module's `results` (its `metadata` block through the by-ref
argument when asked); it throws on a disabled family, a transport error, a
non-JSON answer or an `error` key. `Module::AI_USE_CASES` lists the five
use-cases, `Module::AI_DATALESS_USE_CASES` the one without `data` (`ping`),
`Module::AI_PROVENANCE_TAGS` the two provenance names. `Module::aiStatus()`
backs the status card of the settings tab.

---

## 3. The contract

### 3.1 Request — `POST /query`

```json
{
  "module":   "ai_connector",
  "use_case": "summarization_on_event | summarization_on_eventReport | tag_suggest | infoextraction | ping",
  "data":     {"Event": {...}}  or  {"EventReport": {...}, "Event": {...}},   // no data key at all for ping
  "params":   {"openai_api_base": "...", "api_key": "...", "model_id": "...", "temperature": 0.2,
               "request_timeout": 120, "suggest_limit": 5, "suggest_min_score": 0.0, "min_confidence": 0.9},
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
{"results": {"EventReport": {"name": "...", "content": "..."},
             "Tag": [{"name": "ai-computer-assisted:assistance-level=\"ai-generated\""}, {"name": "ai-computer-assisted:review-level=\"unreviewed\""}]}}   // both summaries
{"results": {"Tag": [{"name": "tlp:amber"}, {"name": "misp-galaxy:threat-actor=\"APT1\""}, {"name": "ai-computer-assisted:..."}, {"name": "ai-computer-assisted:..."}]}}   // tag_suggest: the two AI names follow a non-empty answer
{"results": {"Attribute": [{"uuid", "type", "category", "value", "to_ids", "comment": "extracted by ai_connector from EventReport <uuid>", "Tag": [{"name": "ai-computer-assisted:..."}, ...]}],
             "Object": [{"uuid", "name": "file", "template_uuid", "template_version", "meta-category", "comment", "Attribute": [...]}],
             "Event": {"Event": {...}}},                                         // infoextraction: only what this run added; results.Event is ignored
 "metadata": {"added": 3, "objects": 1, "rejected": [{"type": "url", "value": "...", "reason": "not-in-source"}], "model": {...}}}
{"results": {"ok": true, "endpoint": "http://127.0.0.1:11434/v1", "model": {"name": "gemma4:12b", "server": "ollama 0.33.2", "digest": "...", "quantization": "Q4_K_M"},
             "latency_ms": 4, "models_listed": 18, "tag_suggest": {"url": "http://127.0.0.1:8000", "reachable": true}}}   // ping
{"error": "..."}
```

The extraction answer is MISP core format: it is normalised by
`Event::handleMispFormatFromModuleResult()` like any `misp_standard` import
module's, so the module's `comment`, `to_ids` and per-element `Tag[]` are
kept and category / distribution filled when absent. The module deduplicates
against the event it was sent, so a re-run adds nothing. A `ping` against a
dead endpoint fails only after the module's own `request_timeout`.

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

### 3.4 Provenance — the `ai-computer-assisted` tags

The module's rule: nothing machine-made may land looking like analyst work.
It puts two entries of the `ai-computer-assisted` taxonomy, verbatim, on
everything it produces —
`ai-computer-assisted:assistance-level="ai-generated"` and
`ai-computer-assisted:review-level="unreviewed"` — and MISP honours them:

- **Summaries (A1, A2):** after the report save, `Event::aiAttachResultTags()`
  attaches every `results.Tag` name to the **event** (reports have no tags).
- **Tag recommendation (A3):** the two names the module appends are reported
  apart (`provenance`), never offered as rows; once at least one suggestion is
  attached, they go on with the same locality as the suggestions. Accepting
  nothing marks nothing.
- **Extraction (A4):** every attribute and object attribute carries them; the
  review screens show them read-only.
- **The rows are guaranteed.** `Tag::captureAiProvenanceTags()` runs before
  every AI write: a name the taxonomy knows is enabled through the Taxonomy
  model (`Taxonomy::addTags()`, taxonomy colour, the taxonomy itself left as
  it is), a name it does not know is created as a plain tag. No
  `perm_tag_editor` is needed for these two names — without this, the tag
  capture path silently drops unknown tags for everyone else, and the
  taxonomy is not enabled by default.
- **Exclusive predicates.** Both predicates are exclusive in the taxonomy. A
  fresh AI write makes the event's AI content unreviewed again, so a sibling
  value already on the event (an analyst's
  `review-level="human-reviewed"`) is **replaced** by the module's value, with
  a log row, rather than refused — refusing would leave the event marked
  reviewed while carrying new unreviewed machine content. Same locality only.
  Any other tag name in a module answer keeps the usual rules (creation needs
  `perm_tag_editor`, exclusivity refuses).
- Flipping the review level afterwards (`human-reviewed`, …) is the
  analyst's "I reviewed this" act; the taxonomy carries the values.

---

## 4. Settings — the *AI* tab of the server settings

All under `Plugin.AI_*`, lifted to their own tab (`ServerSettingGroups`,
groups *Connection* / *Model* / *Tag recommendation* / *Indicator
extraction*). The tab also carries a status card (family on/off, module server
reachable, `ai_connector` listed with its version, and the **Test LLM**
button: `POST /servers/aiDryRun {"use_case": "ping"}`, no event — endpoint,
model with server / digest / quantisation, latency, models listed and the
tag-suggestion service's reachability, or the module's error; click-only,
never run when the tab loads, since a dead endpoint costs the module's
`request_timeout` before it fails) and a dry run (event id + use-case → the
answer is shown, the event untouched; site admin, `POST /servers/aiDryRun`;
the `tag_suggest` listing flags the provenance names).

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
| `AI_min_confidence` | float (0..1) | `0.9` | `min_confidence` (A4: candidates below it are dropped by the module) |

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
  four actions and the two *AI actions* surfaces; buttons are hidden without
  it (`ACLComponent`: `events.aiActions/aiSummarize/aiRecommendTags/aiExtractIndicators`,
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
- **A4:** `perm_ai_tools` + edit rights on the event; the review's save goes
  through `handleModuleResults` (edit rights again). The provenance rows need
  no `perm_tag_editor` (§3.4).
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
  failed, errors: {name: reason}, local, provenance: {attached, replaced,
  skipped, failed}}`. The names are classified again server-side, so the
  client is bound by the same rules it was shown; the two provenance names
  are never suggestions (a client cannot pick them) and go on once
  `attached > 0`. The `GET` answer lists them apart as `provenance: [names]`.

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

## 6b. A4 in detail — `EventsController::aiExtractIndicators($id)`

- **Browser, review mode.** `GET` renders the confirmation (report count,
  confidence threshold, the wait). Its `POST` queries the module while the
  browser waits (`set_time_limit(AI_timeout + 30)`; the module needs seconds
  to a minute per report) and renders `resolved_misp_format` — the review
  screen import modules use: a page in the legacy theme (native form post),
  the modal body in Overmind (posted by fetch from the confirmation, swapped
  into the same modal). The module's rejected candidates are listed on top;
  the user unticks / removes what is wrong and submits to
  `POST /events/handleModuleResults/<id>`, unchanged: the save runs as a prio
  job when background jobs are on, tags per element, one unpublish. Nothing
  new: a flash (legacy) or the message in the modal (Overmind).
- **REST, direct apply.** `POST /events/aiExtractIndicators/<id>` answers
  `{saved, success, message, job_id}` when background jobs are on
  (`ai_extract_indicators` on the default queue, `cake Event aiSummarize
  <user> extract <id> [job]`, applied as the requesting user), or
  `{saved, success, message, attributes, objects, rejected}` when it ran
  inline. An event without a readable, non-deleted report is refused before
  the module is called.
- **One report.** `EventReportsController::aiExtractIndicators($reportId)` is the
  same action scoped to the report of the page (*AI → Extract indicators* in
  the report page menu, both themes): only that report is sent
  (`$onlyReportUuids`), the review and the save are the event's. Over REST it
  applies directly through `EventReport::aiExtractIndicatorsRouter()`
  (`cake Event aiSummarize <user> extractReport <report> [job]`). A deleted
  report is refused with `405` before the module is called.
- **Model:** `Event::aiExtractIndicators($user, $eventId, $onlyReportUuids = null)`
  (query + normalise + provenance rows, nothing written; `rejected` and
  `metadata` from the module), `Event::aiApplyExtraction()` (the
  module-result saver), `Event::aiExtractAndApply()`,
  `Event::aiExtractIndicatorsRouter()`, `Event::aiExtractionCounts()` /
  `aiExtractionMessage()`.
- Elements the module answers that already exist on the event are recovered
  by the saver (tags attached to the existing row, no duplicate); an object
  whose attributes match an existing object of the same template is merged
  into it. Distribution is `MISP.default_attribute_distribution` unless the
  review changed it.

---

## 7. Workflow action nodes

`Module_ai_summarize_report` (**id kept:** `send-report-to-cti-info-extractor`,
name *Summarise report with AI*, version 0.2) is the reworked successor of the
CTIInfoExtractor node: stored nodes keep working, their old parameters are
ignored. It sends every matching event report (whole event, or the reports a
filter selects) through the A1 path and **skips reports that already carry an
AI summary** — the engine has no re-entrancy guard and `event-report-after-save`
is a non-blocking trigger, so a workflow on that trigger holding this node
would otherwise feed its own edit back forever. A replace is done from the
report page.

`Module_ai_extract_indicators` (id `ai-extract-indicators`, name *Extract
indicators with AI*, version 0.1) sends the matching reports (whole event, or
the reports a filter selects) through the A4 direct-apply path as the
workflow's user. Loop guard: a report an attribute comment of the event
already cites (`extracted by ai_connector from EventReport <uuid>`,
`Event::aiExtractedReportUuids()`) is not sent again, and nothing left means
no module call — the module's own de-duplication would only save the write,
not the LLM call. Like every new workflow module it starts **disabled**:
enable it on the workflow modules page (`toggleModule/ai-extract-indicators/1`).

---

## 8. Testing without an LLM

- **`tests/ai_fake_module_server.py`** — a standard-library fake of the module
  (`/modules`, `/query` per use-case with deterministic answers — summaries
  and tag suggestions with the provenance tags, an extraction of fixed
  candidates gated by `min_confidence` and deduplicated against the event,
  `ping` — `/last` for what MISP sent, `/health`; `--fail`, `--delay`,
  `params.model_id = fake:error`, `fake:unlisted` for the model-not-served
  error). Point the instance at it: `Plugin.AI_services_enable = true`,
  `AI_services_url = http://127.0.0.1`, `AI_services_port = <port>`. A
  long-running copy must be restarted after the file changes.
- **`tests/testlive_ai_ux.py`** — the end-to-end suite (run in CI after
  `testlive_security.py`): starts the fake itself, exercises settings, dry
  run, ping, A1, A2, A3, A4 with three roles (org tagger without tag editor,
  host-org tag editor without edit rights, reader without `perm_ai_tools`),
  the provenance tags (created for a user without `perm_tag_editor` with the
  taxonomy disabled, replaced on an exclusive sibling, local for a local
  accept), the refusals, the ACL codes and both workflow nodes (the
  extraction node applied once and skipped the second time), then restores
  every setting and removes its fixtures — the provenance rows it created
  included. `HOST=127.0.0.1:5007 AUTH=<key> python3 tests/testlive_ai_ux.py -v`.
- **PHPUnit** (`app/Test/`): `ModuleAiRequestTest` (envelope, params,
  metadata), `ServerSettingFloatTypeTest`, `EventReportAiSummaryTest`
  (strip/merge), `EventAiTagSuggestionTest` (classification, result message,
  the provenance split), `TagAiProvenanceTest` (the guaranteed rows against
  the real `captureTag()`), `EventAiExtractionTest` (counts, messages, the
  cited report uuids).

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
| A4 | `EventsController::aiExtractIndicators`, `EventReportsController::aiExtractIndicators`, `Event::aiExtractIndicators/aiApplyExtraction/aiExtractAndApply/aiExtractIndicatorsRouter/aiExtractionCounts/aiExtractionMessage/aiExtractedReportUuids`, `EventReport::aiExtractIndicatorsRouter`, `EventShell::aiSummarize` (`extract`, `extractReport`), `Events/ajax/aiExtractIndicatorsConfirmationForm.ctp` + `EventReports/ajax/aiExtractIndicatorsConfirmationForm.ctp` (+ Overmind twins, sharing `genericElementsBS5/Modals/ai_extract_submit_script.ctp`), `Events/resolved_misp_format.ctp` (+ twin, `$type = 'AI'`), report page menus (`event-report.js`, `EventReports/view.ctp`, `reportEditor.ctp`, Overmind `eventReport_content.ctp`), `WorkflowModules/action/Module_ai_extract_indicators.php` |
| Provenance | `Tag::captureAiProvenanceTags`, `Event::splitAiTagNames/aiTagPredicatePrefix/aiAttachResultTags/aiTagsNote`, `Module::AI_PROVENANCE_TAGS` |
| Test LLM | `ServersController::aiDryRun` (`use_case=ping`), `healthElements/ai_status.ctp`, `healthElementsBS5/ai_status.ctp` |
| Tests | `tests/ai_fake_module_server.py`, `tests/testlive_ai_ux.py`, `app/Test/*Ai*Test.php`, `app/Test/ServerSettingFloatTypeTest.php` |
