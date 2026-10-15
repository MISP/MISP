<?php
App::uses('AppModel', 'Model');
App::uses('Value', 'Model');
App::uses('ValueStatsTool', 'Tools/ValueIntelligence');
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');
App::uses('ValueExclusionTool', 'Tools/ValueIntelligence');
App::uses('ValueRelationTool', 'Tools/ValueIntelligence');
App::uses('ValueFacetTool', 'Tools');
App::uses('ValueInputTool', 'Tools/ValueIntelligence');
App::uses('Correlation', 'Model');
App::uses('RedisTool', 'Tools');
App::uses('ValueWarninglistTool', 'Tools/ValueIntelligence');
App::uses('ValueTrustTool', 'Tools/ValueIntelligence');
App::uses('ValueStatementTool', 'Tools/ValueIntelligence');
App::uses('ValueEnrichmentTool', 'Tools/ValueIntelligence');
App::uses('ValueTypeGuessTool', 'Tools/ValueIntelligence');
App::uses('ValueRendererTool', 'Tools/ValueIntelligence');
App::uses('ValueSignalLoader', 'Tools/ValueIntelligence');
App::uses('ValueEnrichmentRun', 'Model');
App::uses('ValueVerdictTool', 'Tools/ValueIntelligence');
App::uses('ValueSummaryTool', 'Tools/ValueIntelligence');
App::uses('ValueContestedTool', 'Tools/ValueIntelligence');
App::uses('ValueFactsTool', 'Tools/ValueIntelligence');
App::uses('ValueContextTool', 'Tools/ValueIntelligence');
App::uses('ModuleLocality', 'Tools');
App::uses('ModuleRole', 'Tools');
App::uses('WarninglistCategory', 'Tools');
App::uses('GalaxyCategory', 'Tools');
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
App::uses('DomainPermutationTool', 'Tools/ValueIntelligence');
App::uses('AuditActionMeta', 'Tools/ValueIntelligence');
App::uses('ValueIntelligenceBuckets', 'Tools/ValueIntelligence');
App::uses('ValueHoverTool', 'Tools/ValueIntelligence');
App::uses('JsonTool', 'Tools');
App::uses('EventMatrixTool', 'Tools/EventOverview');
/*
 * For `NON_CORRELATING_TYPES` — the constant, not the model, so the
 * class has to be loaded rather than instantiated through `model()`.
 */
App::uses('MispAttribute', 'Model');

/**
 * The Value Intelligence page's per-panel facade.
 *
 * One public method per panel, each returning the array shape that
 * panel's template already reads. `useTable = false`: this model owns no
 * data of its own, it assembles other models' answers into a panel.
 *
 * **Why this is per panel and not per page.**
 * `ValuesController::profileFor()` builds every tab's data and hands the
 * whole array to whichever endpoint asked for it. That would be nine
 * tabs of queries per panel request and twenty-odd panel requests per
 * tab visit.
 *
 * **Why this is not one big `Value` model.** §4 of the page's PRD
 * refused to build this feature inside `AttributesController` because
 * ~3,800 lines across 40+ actions is not somewhere to add a feature. A
 * single model carrying nine tabs of panel assembly reaches the same
 * size by the same route. `Value` owns the value's identity and its
 * ACL'd occurrence set and is deliberately kept small; this owns
 * assembly and knows what a panel looks like.
 *
 * **What it must not do**, per §14.2: issue its own SQL against
 * attribute value storage. `Value` is the only file in this feature that
 * knows how a value resolves to rows.
 */
class ValueIntelligence extends AppModel
{
    public $useTable = false;

    /**
     * The most occurrence rows one panel request will load.
     *
     * A cap on the *result size*, not on the query count — the six
     * queries behind the occurrence table are constant in the number of
     * occurrences. On a real instance a value like `443` resolves to
     * tens of thousands of occurrences as the port half of
     * `ip-dst|port`, and fetching those with their events, objects,
     * sharing groups and tags is not a slow page but a page that does
     * not arrive.
     *
     * **300.** Two things bound it, and neither is the query — nothing
     * here scales with occurrence count.
     *
     * The page control renders one button per page inline, so the button
     * count is rows ÷ page size and it shares the panel header with the
     * subtitle. Measured at a 1500px viewport: twelve buttons leave the
     * subtitle readable on two lines, twenty squeeze it to a 16px column,
     * twenty-five push the panel into horizontal overflow. At the default
     * page size of 60 this cap is five pages, which is seven buttons; at
     * the smallest the reader can pick, 25, it is twelve.
     *
     * The other bound is the fragment. A row costs roughly 5.7 KB of
     * markup, so 300 rows is about 1.7 MB — against the 5.9 MB that
     * 1,000 rows of `443` produced when this was first written, which is
     * a fragment that does not arrive. Raising it further is now a
     * question about weight rather than about the pager, which is the
     * more honest place for the limit to sit.
     *
     * When the cap bites, the panel says so — §14.6 keeps cap notices,
     * because a cap is not a permission.
     */
    const OCCURRENCE_CAP = 300;

    /**
     * CIDR containment's read: occurrences of the blocks or addresses it
     * found, newest first, and how many addresses a block's page shows.
     */
    const CIDR_ROWS = 2000;
    const CIDR_SHOWN = 100;

    /**
     * The same, for the Overview's card rather than the tab's table.
     *
     * **8, because the two caps are set by different things.** The
     * table's 300 is set by the page control it carries: buttons are
     * rows ÷ page size, and past about twenty of them the panel header
     * overflows. This card has no page control, no sort and no facet
     * rail — it is a sample with a link to the real table under it — so
     * nothing here argues for a larger number, and every row costs the
     * reader vertical space on the tab they landed on.
     *
     * **It was 25 until phase 31**, which is a quarter of the tab's
     * rows drawn in a card with none of the tab's controls: 792px of an
     * Overview whose whole left column measured 1531px, clipped at
     * `70vh` so the sample scrolled *inside* the card a reader had not
     * asked to scroll. Eight rows fill the card without taking the
     * page, and the space that buys is spent on the two questions the
     * twenty-five rows were being read for rather than on more of them
     * — `forReporting` is where that went.
     *
     * The *total* it prints is `occurrenceCountFor` and not this, so
     * the cap narrows what is shown and never what is claimed.
     */
    const OVERVIEW_OCCURRENCE_CAP = 8;

    /**
     * The most organisations the Overview's reporting card will name.
     *
     * A bound on the *drawing* and not on the query: `orgStanceFor` is
     * grouped by organisation, so it answers a handful of rows whether
     * the value occurs 26 times or 48,255, and the total is the row
     * count rather than this. Six fills the split's half of the card at
     * col-lg-9 and covers every value on the verification instance —
     * the widest is `443` at twelve — with *and N more* under it where
     * it does not.
     */
    const REPORTING_ORG_CAP = 6;

    /**
     * The most labels the Overview's context card will draw.
     *
     * **60, and the bound is the panel rather than the query.** One
     * aggregate answers whatever the cap is; what does not survive is
     * the rendering — `443` carries 3,860 distinct tags and drawing
     * them cost a 2.9 MB fragment, on a card whose subject is *what
     * the community has labelled this value* rather than *every label
     * anybody applied*. Sixty fills the card on the widest value the
     * instance has and leaves every ordinary one — `8.8.8.8` reaches
     * 55 once its events' labels are folded in — untouched by it.
     *
     * **It bounds each scope's read and then their union**, which is
     * not the same as bounding each: two reads of 60 can fold to 120
     * distinct labels, so the merged list is cut to the same 60 after
     * the fold and a cap in either read shows up as a merged list over
     * the bound.
     *
     * A capped read changes two things the card says, and both are said
     * rather than assumed: the tag list carries *the most-carried 60 of
     * N*, and no ordinal scale is drawn at all, since exclusivity
     * cannot be judged from a truncated list.
     */
    const CONTEXT_TAG_CAP = 60;

    /**
     * The same, for the galaxy clusters beside them.
     *
     * **Its own cap, because its own read.** Galaxy tags are a small
     * set even where plain tags are not — the widest value on the
     * verification instance carries 3,858 of one and **two** of the
     * other — so this bound is a guard rather than a working limit, and
     * the list it protects is complete on every value the instance has.
     * `CONTEXT_TAG_CAP` covering both is what let a reader who could
     * see less of a value be shown more of its clusters.
     */
    const CONTEXT_GALAXY_CAP = 40;

    /**
     * The matrix card's guard: ATT&CK alone holds some 800 techniques, so
     * the context card's cap would cut a well-labelled value short.
     */
    const MATRIX_GALAXY_CAP = 1000;

    /**
     * Most recent first. A value's newest occurrence is the one a
     * reader opening this tab is looking for, and it is also what makes
     * the cap's own wording true.
     */
    const OCCURRENCE_ORDER = 'Attribute.timestamp DESC';

    /**
     * How many values `/values/index` carries over from last time.
     *
     * Ten, which is a line of chips rather than a panel — the block is
     * a way back to what the reader was just doing, not an inventory
     * of what they have looked at. The number is also the privacy
     * argument's other half: a list that forgets is a list an
     * administrator who reads the row learns little from.
     */
    const RECENT_CAP = 10;

    /**
     * The `user_settings` key the carried-over list lives under.
     *
     * `internal`, following `onboarding_pending`: it is plumbing a
     * feature writes rather than a preference a reader sets, so it is
     * kept out of the user's own settings list and out of the audit
     * log. `UserSetting::VALID_SETTINGS` is where that is declared and
     * this is only the name.
     */
    const RECENT_SETTING = 'value_intelligence_recent';

    /**
     * What a ledger row means by *recent* when it counts sightings.
     *
     * Not a profile setting, deliberately: it is the denominator in a sentence
     * — *"12 sightings in the last 30 days"* — rather than a judgement about
     * what evidence is worth. A signal that wants to weight recency does it
     * with points (`sightings.volume_recency`'s `stale_days`), which is where
     * the analyst's opinion belongs.
     */
    const VERDICT_RECENT_DAYS = 30;

    /**
     * How many days the Verdict tab's rail chart covers.
     *
     * `value_verdict_curves.ctp` computes its labels from the point
     * count on the assumption that a series spans 90 days, so this is
     * the constant the grid follows rather than a window anyone picked
     * per value.
     */
    const VERDICT_CURVE_DAYS = 90;

    /**
     * The keys the verdict templates read that nothing yet produces.
     *
     * `prd/analyst-profile/10-wiring.md` §2.2 is the census: the fifteen
     * `value_verdict*.ctp` files read 25 keys off the verdict array,
     * `ValueVerdictTool` emits 23, and the two sets overlap in twelve.
     * The thirteen below are the difference.
     *
     * **They are defaulted here rather than guarded there** because
     * three of them — `summary`, `orgs`, `cases` — are read with no
     * `??` at all, so their absence is a notice rather than an empty
     * card. The value with nothing to assess fails first: the Overview
     * card reads `summary` only where there is no ledger to list, which
     * is exactly what `ValueVerdictTool::nothingToAssess()` returns.
     *
     * A default is a promise that the key exists, not that it is
     * answered. `null` and `array()` both render as a card that stays
     * dark, which is the honest reading of *nothing computes this yet*.
     *
     * **Eleven of the thirteen are answered now**, by
     * `verdictPanels()` — `orgs`, `warninglist`, the three `curves*`
     * keys, and since phase 9's hero and contested passes `summary`,
     * `cases`, `conflicts`, `ambiguities`, `opinions` and
     * `composition_note`. They keep their entries here rather than
     * losing them, because each has a real *nothing to show* case: a
     * value nobody has reported has no organisations, most values hit
     * no warninglist, a value with no datable evidence has no runway to
     * plot, and a lean nothing contradicts has no cases.
     *
     * `resolutions` is the one that stays empty for good. It drives
     * *Resolve it*, whose every control is disabled because this page
     * does not write — `01-profile.md` §7 — so an empty list is its
     * finished state until `value-intelligence-writes.md` lands.
     */
    const VERDICT_UNPRODUCED = array(
        'summary' => null,
        'orgs' => array(),
        'cases' => array(),
        'conflicts' => array(),
        'ambiguities' => array(),
        'warninglist' => null,
        'curves' => array(),
        'curves_span' => null,
        'curves_note' => null,
        'composition_note' => null,
        'changer_actions' => array(),
        'opinions' => null,
        'resolutions' => array(),
    );

    /**
     * How many of the value's events the co-occurrence section will
     * even look at before it starts choosing.
     *
     * A first bound, and the cheap one. `443` sits in 1,844 events on
     * the verification instance; asking the database how big each of
     * them is took 519 ms over all 1,844 and 44 ms over the most recent
     * 200. Nothing below this line is affected by how many events were
     * discarded here, because the budget below discards far more.
     */
    const RELATION_EVENT_CAP = 200;

    /**
     * An event this size has no co-occurrence signal in it.
     *
     * The largest event on the verification instance holds 843,976
     * attributes and the largest one `8.8.8.8` appears in holds
     * 369,822. In an event that size *every* value co-occurs with every
     * other, so a neighbour list drawn from it says nothing about this
     * value — and reading it costs 4.8 seconds against 0.19 for the
     * other eighteen events put together.
     *
     * This is an editorial line and not only a performance one, which
     * is why the panel states it in words rather than quietly applying
     * it. `24-relationships.md` §4.2.
     */
    const RELATION_EVENT_SIZE_CAP = 10000;

    /**
     * The most attribute rows one co-occurrence request will read.
     *
     * The one number that bounds this section's cost on any instance,
     * whatever shape its events are. Events are taken newest-first
     * until adding the next one would exceed it. Measured: 20,000 rows
     * is 914 ms of fetch on `443` including its tag join, and 379 ms on
     * `8.8.8.8`'s 10,168.
     */
    const RELATION_SCAN_BUDGET = 20000;

    /**
     * Listed neighbour values, and listed object roll-up rows.
     *
     * The counts above them stay exact at any cardinality because they
     * are folded from the whole scope; this bounds only what is drawn.
     *
     * **100, and the pager is what sets it.** `value_pager` pages
     * client-side at `RELATION_PAGE_SIZE`, and phase 22 measured where
     * that control breaks: twelve buttons leave the panel subtitle
     * readable, twenty squeeze it to a 16px column, twenty-five push
     * the header into horizontal overflow. 100 rows at 8 a page is
     * thirteen. 200 was tried first and is 25 buttons — and, on
     * `8.8.8.8`, a 1.05 MB fragment, because this panel ships all
     * three roll-ups at once so the reader can switch between them
     * without a request.
     */
    const RELATION_ROW_CAP = 100;

    /**
     * Candidate rows the ssdeep engine fetches before de-duplicating.
     *
     * A ceiling rather than a working limit. This instance holds 1,399
     * `ssdeep` attributes and 1,260 distinct values, so nothing here
     * binds and the engine compares the whole visible population; the
     * number exists so an instance with a hundred thousand hashes
     * fetches a bounded set rather than all of them. **When it does
     * bind the panel says so** — which is the half §4.2 found missing,
     * and the reason the old `RELATION_ROW_CAP` was the wrong constant
     * as well as the wrong size: a row cap bounds what is shown, and
     * this bounds what is compared, so it changes the verdict.
     */
    const SSDEEP_CANDIDATE_CAP = 10000;

    /**
     * Occurrences the typosquat engine fetches for its candidate set.
     *
     * A *fetch* cap, not a compare cap — the distinction §4.2 found
     * the ssdeep engine getting wrong. Every candidate is always
     * checked, because the check is one `IN` over the whole set; this
     * bounds how many occurrences of the hits come back, and the panel
     * reports it when it binds rather than quietly showing fewer
     * look-alikes than exist.
     */
    const TYPOSQUAT_FETCH_CAP = 200;

    /** Rows per page in the co-occurrence and sibling lists. */
    const RELATION_PAGE_SIZE = 8;

    /**
     * Named threats the neighbourhood card shows before folding.
     *
     * Measured over every value on the development instance: of the
     * ~93,000 that have any named threat nearby, 93% have one, two or
     * three, and the cap binds on 1.7% of them. It binds hard when it
     * does — one value reaches 154 distinct clusters and another 102 —
     * so the rest are held rather than dropped, and the card expands
     * in place instead of sending the reader anywhere.
     */
    const THREAT_ROW_CAP = 8;

    /**
     * Seconds the Relationships scan's reads are held in Redis.
     *
     * Narrowing the co-occurrence table re-requests the panel, and each
     * request would otherwise repeat the whole scan to fold the same
     * rows differently. Cached, a session of narrowing costs one scan.
     *
     * **Five minutes, because the panel says how old the read is and
     * offers to redo it.** Nothing invalidates this entry — no
     * event-change hook reaches here — so without those two the only
     * bound on a stale neighbourhood would be the clock, and this would
     * have to stay at a minute. It still does not go higher: the reader
     * has a cue for *I* just added something, and none at all for
     * *somebody else* did.
     */
    const RELATION_SCAN_TTL = 300;

    /**
     * Seconds the occurrence tag read is held in Redis; the context and
     * matrix panels share it.
     */
    const OWN_TAGS_TTL = 300;

    /**
     * How long a computing request holds the right to compute.
     *
     * The lock exists to stop a stampede, not to serialise the page, so
     * the only thing this number has to beat is one scan on the worst
     * value an instance holds. It is deliberately far above that: the
     * key self-expires, so an interpreter killed mid-scan costs the
     * next reader a wait and never wedges the value.
     */
    const RELATION_LOCK_TTL = 120;

    /**
     * How long a waiting request waits before scanning itself.
     *
     * A waiter gives up early only when the lock has *gone* without the
     * cache being filled — the leader died — and this ceiling is the
     * backstop for the case where it neither finishes nor releases.
     * Above the leader's own cost, so the normal outcome of waiting is
     * the leader's answer rather than a second scan.
     */
    const RELATION_LOCK_WAIT = 45;

    /**
     * How often a waiter looks for the answer, in microseconds.
     *
     * 50 ms adds at most that to a warm read and costs ~90 `GET`s over
     * a 4.6 s scan, which is nothing next to the scan it replaces.
     */
    const RELATION_LOCK_POLL = 50000;

    /**
     * The shape of what the caches above hold. **Bump it in the same
     * commit as any change to the arrays they store.**
     *
     * A cached payload outlives the code that wrote it, so for one TTL
     * after a deploy the templates are new and the arrays they read are
     * old. A panel that reads a key the old fold did not write then
     * fatals for five minutes on every value someone had opened —
     * observed while building B4, which added `tokens` to the sibling
     * rows. Versioning the key retires those payloads at the deploy
     * rather than at the clock, and costs one cold read.
     *
     * `00-contract.md` §14.4 carries the rule; this is the second thing
     * a key here must capture, after the permission scope.
     */
    const CACHE_SHAPE = 13;

    /**
     * Objects the sibling join will read.
     *
     * `0.0.0.0` sits in 32,921 distinct objects here, one per row of a
     * flood capture. 500 objects is 5,500 sibling rows and 70 ms.
     */
    const SIBLING_OBJECT_CAP = 500;

    /**
     * How many of this value's own occurrences the reference reader
     * offers as reference targets.
     *
     * `object_references.referenced_id` is indexed, so the cost here is
     * the `IN` list rather than the scan. The claims section caps its
     * own UUID set at `CLAIM_OCCURRENCE_CAP` for the same reason.
     */
    const REFERENCE_OCCURRENCE_CAP = 300;

    /** Reference rows read before the panel says the cut bit. */
    const REFERENCE_ROW_CAP = 200;

    /** Identifying values carried per far object in a reference row. */
    const REFERENCE_FACE_CAP = 4;

    /**
     * Occurrence UUIDs the asserted section resolves claims against.
     *
     * The only cap on that section, and it is on the *lookup* rather
     * than on the claims: analyst relationships are written one at a
     * time by people, so the list itself is never truncated. A value
     * with more occurrences than this can carry a claim on one the
     * lookup did not reach, and the panel says so.
     */
    const CLAIM_OCCURRENCE_CAP = 300;

    /**
     * Characters of a target's own prose a claim's hover card carries.
     *
     * A galaxy cluster's description is the only free text that reaches
     * this section, and it runs to paragraphs. The card is a hover, not
     * a page — what it cannot hold is one click away on the target
     * itself, which the same card links to.
     */
    const CLAIM_PROSE_CAP = 180;

    /**
     * Remote events listed per external source.
     *
     * Measured over 4,798 cached values on a live instance: a median of
     * 2 remote events per hitting value, 4 at p95, 52 at the most
     * (`live/24-relationships.md` §17.4). Twenty-five covers everything
     * seen with room to spare, and a source past it says so — a cap is
     * not a permission, so that notice reads the same for every reader.
     */
    const EXTERNAL_EVENT_CAP = 25;

    /**
     * Event uuids per feed hit looked up for `feeds.reporters`. Twice
     * the 52 events the most-hit cached value carried above; past it a
     * feed is judged by the events read.
     */
    const FEED_PUBLISHER_UUID_CAP = 100;

    /**
     * Chronology rows one Timeline request renders.
     *
     * It is a cap on the *chronology* and on nothing else. The spine's
     * bars and the lanes' counts come from a grouped aggregate over the
     * whole scoped set, so a value whose entries run past this reads
     * *showing 1,000 of 174,299* rather than a chart of the last
     * fortnight labelled as a year.
     *
     * **It started at `OCCURRENCE_CAP`'s 300 and is no longer bound to
     * it.** That number is the occurrence table's pager talking — one
     * button per page, inline, collapsing past about twenty — and this
     * list has no pager: it shows a windowful and reveals the rest in
     * place. What bounded this one instead was that a reader who
     * brushed past the newest 300 got an empty chronology, and phase
     * 25's §18 fixed that properly by letting the brush ask for a
     * window. With the fetch in place the cap stopped deciding whether
     * the panel is honest and went back to deciding only how often a
     * reader has to brush, so it buys the wider one.
     *
     * The bound that remains is weight, and it is measured: a
     * chronology row is about 1.8 KB of markup, so this is roughly
     * 1.8 MB of HTML on a value that fills it — against 550 KB at 300.
     * Nginx serves the fragment gzipped, which is where most of that
     * goes. Raising it again is that measurement's question and no
     * longer the pager's.
     */
    const TIMELINE_ROW_CAP = 1000;

    /**
     * Ids per *statement* when the audit reader scopes by `model_id`.
     *
     * Per statement, and never OR-ed into one — which is the whole
     * point of the number and was measured the hard way. `audit_logs`
     * carries two indexes, `model_id` and `event_id`, and none on
     * `model`. A single scope with a flat `IN` list plans well:
     * MariaDB materialises the list and does a `ref` join on
     * `model_id`, one row per lookup. **Three scopes OR-ed into one
     * `WHERE` plan as `type = ALL`, `key = NULL`, over 8,558,097
     * rows** — an `OR` across two different columns makes the
     * optimizer abandon both indexes and scan the table. On `443` that
     * was 54,501 ms for the aggregate against 1,420 ms for the same
     * three scopes read as three statements.
     *
     * So chunking here bounds statement *size* and nothing else, and a
     * chunk is its own query whose grouped result is merged in PHP.
     * 25,000 rather than something larger because `443` — 48,255
     * occurrences, the heaviest value on the instance — then takes two
     * chunks, so the merge path is the path the phase's own worst case
     * runs rather than a branch nothing reaches until an instance
     * bigger than this one meets it.
     */
    const AUDIT_ID_CHUNK = 25000;

    /**
     * How many days of audit log the History tab lands on.
     *
     * A date rather than a count, which is the whole difference between
     * this bound and a row cap: the reader is asking what has happened
     * lately, and a ceiling of two hundred entries answers a question
     * about the log's volume instead — worse, it answers it differently
     * on a quiet value and a busy one.
     */
    const HISTORY_WINDOW_DAYS = 30;

    /**
     * The second bound, and the reason the first is not enough.
     *
     * A window is a date and a value can have a bad day: `443` took
     * 411,840 audit rows in 2026-09 alone, so a thirty-day window over
     * that month is not a small read. The cap is applied by the
     * database on an `id DESC` read, per scope, and the merge takes the
     * newest of what came back — so what a reader gets is the newest
     * cap-many *inside the window they asked for*, and the header's
     * `Showing <shown> of <all>` is where a capped read says so.
     */
    const HISTORY_ROW_CAP = 500;

    /**
     * Bar widths for the History tab's activity chart.
     *
     * The rule is about how wide a bar reads rather than anything about
     * audit logs: 45 days of daily bars and 200 of weekly ones both
     * fit, where 437 daily bars would be 0.68px each.
     */
    const HISTORY_CHART_RULE = array(
        array('days' => 45, 'unit' => ValueIntelligenceBuckets::DAY),
        array('days' => 200, 'unit' => ValueIntelligenceBuckets::WEEK),
        array('days' => null, 'unit' => ValueIntelligenceBuckets::MONTH),
    );

    /**
     * Bars the seen-span lane draws before it states a remainder.
     *
     * The lane merges nothing, so a value with 24 spans draws 24 bars
     * and one with 179,878 would draw a solid block. The bound is the
     * lane's height rather than the query's cost — the spans are already
     * on the occurrence rows — and 25 is what fits a 38px lane at a
     * width a reader can still pick one bar out of.
     *
     * A cap is not a permission, so the lane says so for every reader,
     * in the wording phase 22 settled for the siblings section.
     */
    const TIMELINE_SPAN_CAP = 25;

    /**
     * `datetime` attributes the object-date lane reads before it stops.
     *
     * Bounded on the query and not on the lane's height, which is the
     * difference from `TIMELINE_SPAN_CAP` above: these rows are a fetch
     * of their own rather than columns already in hand, and `0.0.0.0`
     * offers **32,893** of them across the 32,922 objects it sits in.
     * The lane's own counts come from an aggregate over all of them, so
     * what this bounds is the chronology and the bars, never the spine.
     *
     * 1,000 rather than the chronology's own cap for no cleverer reason
     * than that they are the same number: a lane that handed up more
     * would be building rows for `timelineCap` to throw away.
     */
    const TIMELINE_OBJECT_DATE_CAP = 1000;

    /**
     * Object-template relations that are the two ends of one interval.
     *
     * A pair draws one bar; every other `datetime` field draws an
     * instant. Three pairs and not a guess at more: a relation named
     * `first-*` is not reliably half of anything —
     * `compilation-timestamp`, `last-submission` and `time_generated`
     * are all single dates, and `last-submission` in particular would
     * be read as the far end of a submission window that MISP does not
     * record the near end of.
     */
    const TIMELINE_DATE_PAIRS = array(
        'time_first' => 'time_last',
        'first-seen' => 'last-seen',
        'validity-not-before' => 'validity-not-after',
    );

    /**
     * Sources whose dates describe the world, not this instance.
     *
     * Every other source on this tab is a trace the instance left: an
     * audit row, a publish stamp, a note's `created`. These three are
     * something an analyst or a feed *said* — `first_seen` is a claim
     * about when a threat was seen in the wild, and an object's
     * `datetime` field is whatever its template chose to record. A
     * `passive-dns` object filed in 2022 can carry a `time_first` of
     * 2013, and reading that as the record's age is the panel asserting
     * something nobody recorded.
     *
     * So they are on the axis, in the lanes and in the chronology like
     * everything else — they are dated facts about the value and this
     * tab exists to draw those — and they are excluded from exactly one
     * question: how long the value has been *here*.
     */
    const TIMELINE_CLAIM_SOURCES = array('seen', 'seen_object', 'objdate');

    /**
     * Chips one undated kind lists before it states a remainder.
     *
     * `443` resolves to 3,858 distinct tags and `193.161.193.99` to 77.
     * The strip is a strip and not a tag
     * index; what it cannot hold is on the Occurrences tab, which is
     * what the count beside the chips is for.
     */
    const TIMELINE_CHIP_CAP = 12;

    /**
     * Occurrence UUIDs the analyst union looks notes and opinions up
     * against.
     *
     * `CLAIM_OCCURRENCE_CAP`'s argument, on a second consumer of the
     * same shape: notes and opinions are written one at a time by
     * people — 75 and 43 on the whole instance — so the list itself is
     * never truncated and it is the *lookup* that is bounded. The
     * value's events are not capped alongside it, because there are
     * always fewer of them than occurrences and they are where the
     * analyst data measured on a real instance actually is.
     *
     * A value with more occurrences than this can carry a note on one
     * the lookup did not reach. `443` is that value at 48,255, and it
     * is also a value nobody has written a note about.
     */
    const TIMELINE_ANALYST_CAP = 300;

    /**
     * Occurrence UUIDs the Analyst tab's own union looks up against.
     *
     * `TIMELINE_ANALYST_CAP`'s argument, on the tab that owns the
     * union rather than draws a lane of it. Kept the same number
     * deliberately: the Timeline's note lane and this tab read the
     * same rows, and two caps would let one of them show a note the
     * other had never heard of.
     */
    const ANALYST_OCCURRENCE_CAP = 300;

    /**
     * How many levels of reply the thread renders.
     *
     * Two, which is what MISP's own thread view returns, and the
     * template already prints *anything written below this one is
     * flagged but not fetched* at the bottom level. The reader below
     * the last rendered one is issued anyway — it is what makes that
     * sentence true rather than assumed — and its rows are counted and
     * discarded.
     */
    const ANALYST_THREAD_DEPTH = 2;

    /**
     * Galaxy tag names resolved to clusters for the union's fifth
     * anchor kind.
     *
     * A bound rather than a limit anybody is expected to hit: the cap
     * exists because the names come from every tag on every event the
     * value appears in, and `fetchGalaxyClusters` is an ACL'd read
     * whose cost is per row returned.
     */
    const ANALYST_GALAXY_TAG_CAP = 100;

    /**
     * Reports the narrative list draws before it states a remainder.
     *
     * A cap with a stated remainder rather than a page parameter: the
     * rows come from every event a value sits in, and `443` sits in
     * thousands. Phase 25's D2 pattern.
     */
    const ANALYST_REPORT_CAP = 50;

    /**
     * Characters of a report's body carried for its extract.
     *
     * `event_reports.content` is `mediumtext` and has no length limit
     * in practice, so a list of twenty reports could be a megabyte of
     * markdown fetched to render four lines of each.
     */
    const ANALYST_REPORT_HEAD = 600;

    /**
     * Distinct comment sentences the comment table draws before it
     * states a remainder.
     *
     * Fifty, the report list's number for the report list's reason: it
     * is a list of what was written rather than a table with a rail, so
     * it has nothing to narrow itself with and a stated remainder is
     * what an unbounded read would owe the reader anyway. The read is
     * grouped, so the cap counts *sentences* and never occurrences —
     * the instance's busiest value by commented rows, `94.98.224.81`,
     * is 1,459 occurrences of a single sentence and fills one row of
     * fifty. Its busiest by sentences, `193.161.193.99`, has 33.
     */
    const ANALYST_COMMENT_CAP = 50;

    /**
     * Standalone proposals the Occurrences tab draws before it states a
     * remainder.
     *
     * Fifty, the same number phase 26's report list settled on and for
     * the same reason: the block is a list of exceptions rather than a
     * table with a rail, so it has no filter to narrow itself with and
     * a stated remainder is what an unbounded fetch would owe the
     * reader anyway. The verification instance's largest count is six.
     */
    const STANDALONE_PROPOSAL_CAP = 50;

    /**
     * Items the Overview's preview card draws before it says how many
     * more there are.
     *
     * Four, which is what the card's slot on a three-panel column holds without
     * pushing the Verdict card below the fold. It is a preview and the tab is
     * one press away: the number that matters on this card is the total in its
     * subtitle, not how much of the thread it managed to fit.
     */
    const ANALYST_PREVIEW_CAP = 4;

    /**
     * Days the brush's default window covers.
     *
     * A recent slice of a wider chart, which is what makes the brush
     * worth having, chosen from the data.
     *
     * 30 because a month is the unit the spine bins in and a reader
     * reads back; and the window is clamped to the value's
     * range rather than to the calendar, so it is never empty and never
     * degenerate. Taking the *calendar month* of the newest entry was
     * the first rule tried and it gives `143.14.244.37` — whose newest
     * entry is 1 July — a one-day window with its 32 spans off the left
     * edge.
     */
    const TIMELINE_WINDOW_DAYS = 30;

    /**
     * Actions whose `model_title` is the thing acted on rather than the
     * thing acted upon.
     *
     * A tag or cluster action writes the tag's name into `model_title`
     * while `model`/`model_id` still name the attribute — see
     * `AuditLog::generateUserFriendlyTitle` (`:116`) — so for these the
     * title is a subject the row should say out loud, and for an `edit`
     * it is the occurrence's own name and saying it twice is how the
     * two come to disagree.
     */
    const AUDIT_SUBJECT = array(
        'tag',
        'tag_local',
        'remove_tag',
        'remove_local_tag',
        'galaxy',
        'galaxy_local',
        'remove_galaxy',
        'remove_local_galaxy',
    );

    /**
     * Actions whose `change` blob holds what was taken away rather than
     * what was put there — the same set `Elements/AuditLog/change.ctp`
     * keys its own arrow direction off.
     */
    const AUDIT_REMOVES = array(
        'delete',
        'remove_tag',
        'remove_local_tag',
        'remove_galaxy',
        'remove_local_galaxy',
    );

    /**
     * Fields a diff renders as a date rather than as the integer the
     * column holds.
     */
    const AUDIT_DATE_FIELDS = array(
        'expiration',
        'created',
        'date_created',
    );

    /**
     * @var array Lazily loaded models, by alias
     */
    private $models = array();

    /**
     * @var array|null The occurrence summary, once per request
     */
    private $summary = null;

    /**
     * @var array|null The co-occurrence fold, once per request
     */
    private $cooccurrence = null;

    /** The narrowing `$cooccurrence` was folded under. */
    private $cooccurrenceFilters = array();

    /**
     * The value the two memos above and below hold.
     *
     * A request serves one value, so this never changes inside the
     * application — but a memo that cannot say which value it holds
     * hands the wrong neighbourhood to the second caller in any loop,
     * silently and with no key to notice it by. A console shell walking
     * eight verification values is exactly that loop.
     *
     * @var string|null
     */
    private $memoValue = null;

    /**
     * @var array|null The object-reference read, once per request
     */
    private $references = null;

    /**
     * Drop every per-value memo the moment a different value is asked
     * for.
     *
     * @param string $value
     * @return void
     */
    private function forget($value)
    {
        if ($this->memoValue === $value) {
            return;
        }
        $this->memoValue = $value;
        $this->cooccurrence = null;
        $this->cooccurrenceFilters = array();
        $this->references = null;
        $this->summary = null;
    }

    /**
     * @param string $alias
     * @return Model
     */
    private function model($alias)
    {
        if (!isset($this->models[$alias])) {
            $this->models[$alias] = ClassRegistry::init($alias);
        }
        return $this->models[$alias];
    }

    /**
     * The numbers on the tab bar, corrected where the page frame and a
     * converted tab would otherwise contradict each other.
     *
     * Not a panel, and the only method here that is not. A badge and
     * the panel two inches under it must not state different numbers
     * for one value. `forFrame` calls it, so the frame is still one read
     * from the controller's side; what it keeps is the argument below
     * for which badges can be told truly.
     *
     * **Occurrences gets a real number.** One `COUNT`, and pointedly
     * the same call `forOccurrenceTable` makes for the total its own
     * header prints — not another aggregate that ought to agree with
     * it. Two counts that should match are two counts that can drift;
     * one call cannot disagree with itself.
     *
     * **Sightings had no number at all, and now has one.** The badge
     * was removed rather than zeroed because a sighting count has to be
     * the viewer's — `Sightings_policy` hides whole reports and two
     * readers would otherwise read two numbers off one tab bar — and
     * getting the viewer's count meant running the policy over fetched
     * rows, the panel's own 13 queries, on every page load of a tab
     * most readers never open. That note asked for *"`Sighting`
     * growing a counting method that applies the policy in SQL instead
     * of in PHP over fetched rows"*, and phase 29 built it:
     * `Sighting::visibilityConditions` is the policy as a predicate and
     * `Value::sightingCountsFor` is one indexed aggregate over it.
     *
     * **The caller passes it in rather than this method fetching it**,
     * because the fact strip needs the same number and the two must not
     * be two counts. `forFrame` makes the one call and hands the total
     * here — which is the rule the occurrence count below states the
     * other way round, and the reason both badges can be trusted.
     * Timeline and History still carry no badge.
     *
     * **Relationships gets a number that names its own unit.** Not a
     * *correlation* total: nothing on the tab computes one, because
     * co-occurrence there is an event join rather than correlation
     * output. The join's own total — `distinct_values` — is
     * still refused here for the sightings reason: it needs the panel's
     * whole scan, up to 20,000 attribute rows and about a second on the
     * heaviest value on the instance, on every page load.
     *
     * What is affordable is the notion the tab was re-founded on
     * (`24-relationships.md` §26). **How many objects this value sits
     * in** is one indexed aggregate — 0.3 ms on `8.8.8.8`, 84 ms on
     * `0.0.0.0` — and it is the same number the sibling panel's census
     * and the graph's object layer already print, because
     * `Value::objectCountFor` carries the conditions of the call that
     * fetches those rows.
     *
     * **It rides the badge pill, not the parenthesised count**, and the
     * distinction is the whole of why this one can be told. `(15)` on a
     * tab called Relationships reads as *fifteen relationships*, which
     * is the claim that got the correlation badge removed; the pill
     * takes a label, so the unit travels with the number. The tab bar
     * inherits the contents strip's rule that seven notions have seven
     * units and none of them is a total.
     *
     * **Zero shows nothing at all**, which is what keeps this honest
     * rather than merely cheap. A value can sit in no object and still
     * have an analyst claim, a near-match or a remote hit — near-matches
     * alone cannot be priced at page-load cost — so a badge reading
     * *0 objects* would answer *is this tab worth opening* wrongly, in
     * the one direction that costs a reader something. An absent pill
     * therefore keeps the meaning it has today, *no number can be told
     * truly*, and adding a probe can only turn silence into a true
     * badge, never into a false one.
     *
     * **Enrichment counts answers held, not modules eligible.** Phase
     * 28 dropped this tab's number and the reason it gave still holds:
     * the eligible-module count would make every page load on every
     * tab depend on an external HTTP service, and pay its timeout
     * whenever it is down. What the store made countable is a
     * different number — how many answers this organisation already
     * has about this value — and it asks nothing outside MISP:
     * `ValueEnrichmentRun::heldCountFor` is one index-only count over
     * the unique key's two leading columns.
     *
     * It is the viewer's, like the two beside it, because the store is
     * scoped by organisation. And zero shows nothing, by the rule
     * below: an instance that has never enriched anything has the tab
     * bar it had before this existed.
     *
     * **The warm-digest peek was the other candidate, and is refused.**
     * `relationDigest` is held in Redis per user and value, so a `GET`
     * here would hand over the exact join total for free once the tab
     * had been opened — `24-relationships.md` §15.1 item 1 built that
     * context. But a badge that appears only after the visit it exists
     * to inform has missed its one job, and an intermittent number
     * conflates *not read yet* with *nothing there*, which is the
     * conflation the contents strip's placeholder was built to prevent.
     *
     * @param array $user
     * @param string $value
     * @param array $counts The frame's counts
     * @return array The same, with the badges that can be told truly
     */
    public function forTabCounts(array $user, $value, array $counts)
    {
        $valueModel = $this->model('Value');
        $counts['occurrences'] = $valueModel
            ->occurrenceCountFor($user, $value);
        $counts['relationship_objects'] = $valueModel
            ->objectCountFor($user, $value);
        $counts['enrichment'] = $this->model('ValueEnrichmentRun')
            ->heldCountFor($user, $value);
        return $counts;
    }

    /**
     * How this instance spells the value the reader typed, if it holds
     * it at all — and the one neighbour worth offering if it does not.
     *
     * The resolver's whole read: is this here? It answers with the
     * stored spelling, not the reader's, since `/values/view` renders
     * the string in its URL. A value the reader may not see is absent
     * here exactly as a value nobody recorded is.
     *
     * The reader's own spelling wins; a spelling differing only in case
     * is where the reader is sent. Any other spelling of the value's
     * group, an accent variant above all, is only offered: MISP shows
     * them together, but an accent can make a different domain.
     *
     * @param array $user
     * @param string $value A value, already normalised
     * @param array $options As conditionsFor
     * @return array `value` as asked, `recorded`, `stored` — how the
     *               instance spells it, null when it does not hold it
     *               — and `suggestion`, another stored spelling of it
     */
    public function forResolve(array $user, $value,
        array $options = array()
    ) {
        $answer = array(
            'value' => $value,
            'recorded' => false,
            'stored' => null,
            'suggestion' => null,
        );
        $spellings = $this->model('Value')->spellingsFor(
            $user,
            array($value),
            $options
        );
        $stored = self::spellingOf($value, $spellings);
        if ($stored !== null) {
            $answer['recorded'] = true;
            $answer['stored'] = $stored;
        } elseif (!empty($spellings)) {
            $answer['suggestion'] = reset($spellings);
        }
        return $answer;
    }

    /**
     * Which of the spellings that came back is this value's: the
     * reader's own, else one differing from it only in case.
     *
     * @param string $value The value as asked about
     * @param array<string> $spellings What `spellingsFor` returned
     * @return string|null
     */
    private static function spellingOf($value, array $spellings)
    {
        if (in_array($value, $spellings, true)) {
            return $value;
        }
        $folded = mb_strtolower((string)$value, 'UTF-8');
        foreach ($spellings as $spelling) {
            if (mb_strtolower($spelling, 'UTF-8') === $folded) {
                return $spelling;
            }
        }
        return null;
    }

    /**
     * A pasted list, as the rows a worklist draws: every row linked to
     * the spelling the instance holds, and nothing else. A row saying
     * *not recorded* would look different for a value the reader may
     * not see.
     *
     * One dictionary read for the list finds the values stored in
     * another case; only those are asked about, each in one bounded
     * statement scoped to what the reader can see. Two spellings of one
     * value collapse into one row after that.
     *
     * @param array $user
     * @param array<string> $values Normalised, deduplicated, in the
     *                              order they were pasted
     * @param array $options As conditionsFor
     * @return array `rows` — `value`, the reader's own spelling, and
     *               `stored`, how the instance spells it or null —
     *               plus `recased` and `collapsed`, the counts the
     *               provenance line names
     */
    public function forTriage(array $user, array $values,
        array $options = array()
    ) {
        $valueModel = $this->model('Value');
        $values = array_map('strval', $values);
        $recasable = $this->storedInAnotherCase($values);
        $rows = array();
        $at = array();
        $recased = 0;
        $collapsed = 0;
        foreach ($values as $value) {
            $stored = empty($recasable[$value])
                ? $value
                : self::spellingOf($value, $valueModel->spellingsFor(
                    $user,
                    array($value),
                    $options
                ));
            $key = $stored === null ? $value : $stored;
            if (isset($at[$key])) {
                $collapsed++;
                continue;
            }
            if ($stored !== null && $stored !== $value) {
                $recased++;
            }
            $at[$key] = true;
            $rows[] = array('value' => $value, 'stored' => $stored);
        }
        return array(
            'rows' => $rows,
            'recased' => $recased,
            'collapsed' => $collapsed,
        );
    }

    /**
     * The stored values a search text matches that this reader can see
     * held, one page of them, as `Value::matchesFor` reads them. The text
     * is refanged first, as the box reads a lookup.
     *
     * @param array $user
     * @param string $raw What was typed
     * @param int $page
     * @param bool $anywhere Match inside words too (reads every value)
     * @return array As `Value::matchesFor`, plus `changed`, what the parse
     *               did to the text
     */
    public function forMatches(array $user, $raw, $page = 1, $anywhere = false)
    {
        $one = ValueInputTool::normalise($raw);
        $matches = $this->model('Value')->matchesFor(
            $user,
            $one['value'] === null ? '' : $one['value'],
            $page,
            Value::MATCH_PAGE,
            $anywhere
        );
        $matches['changed'] = $one['changed'];
        return $matches;
    }

    /**
     * The values the dictionary also holds in another case, whoever
     * can see them.
     *
     * @param array<string> $values
     * @return array<string, true>
     */
    private function storedInAnotherCase(array $values)
    {
        $dictionary = $this->model('AttributeValue');
        $groups = $dictionary->resolveCi($values);
        $ids = array();
        foreach ($groups as $members) {
            foreach ($members as $id) {
                $ids[(int)$id] = true;
            }
        }
        $texts = empty($ids)
            ? array()
            : $dictionary->fetchValues(array_keys($ids));
        $out = array();
        foreach ($groups as $value => $members) {
            $value = (string)$value;
            $folded = mb_strtolower($value, 'UTF-8');
            foreach ($members as $id) {
                $text = isset($texts[(int)$id]) ? $texts[(int)$id] : null;
                if ($text !== null && $text !== $value
                    && mb_strtolower($text, 'UTF-8') === $folded
                ) {
                    $out[$value] = true;
                    break;
                }
            }
        }
        return $out;
    }

    /**
     * The values this reader last opened, newest first.
     *
     * **The one block on `/values/index` whose rows are not the
     * reader's own paste**, and it can exist only because it reads a
     * table that is genuinely value-keyed: not `attributes` — where
     * *all values* is a `GROUP BY value1` no `LIMIT` bounds
     * (`value-index.md` §1.1) — but one `user_settings` row holding ten
     * strings this reader put there themselves.
     *
     * **Per-viewer and never shared.** D27 refuses to name who ran an
     * enrichment because naming the runner tells the organisation which
     * colleague is looking at which value; a shared recently-viewed is
     * that disclosure with a different label. The setting is keyed by
     * `user_id` and nothing reads another reader's.
     *
     * **No assessment.** Ten values is ten engine runs before the
     * reader has pasted anything, which is the page's whole load spent
     * on a block nobody asked a question of — so the chips carry the
     * value and the time, and the hover card supplies the assessment at
     * the moment a reader wants one (`02a-contract.md` §12.7). That is
     * also why the stored entry holds no lean: a frozen chip turns a
     * question about the database *now* into one about the database
     * *then*.
     *
     * Malformed rows are dropped rather than repaired. The value is
     * free text a past release wrote and a future one may reshape, and
     * a block that cannot draw an entry has nothing to say about it.
     *
     * @param array $user
     * @return array<array{value: string, at: int}> At most RECENT_CAP
     */
    public function forRecent(array $user)
    {
        if (empty($user['id'])) {
            return array();
        }
        $stored = $this->model('UserSetting')->getValueForUser(
            $user['id'],
            self::RECENT_SETTING
        );
        if (!is_array($stored)) {
            return array();
        }
        $entries = array();
        foreach ($stored as $entry) {
            if (!is_array($entry)
                || !isset($entry['value'], $entry['at'])
                || !is_string($entry['value'])
                || $entry['value'] === ''
            ) {
                continue;
            }
            $entries[] = array(
                'value' => $entry['value'],
                'at' => (int)$entry['at'],
            );
            if (count($entries) >= self::RECENT_CAP) {
                break;
            }
        }
        return $entries;
    }

    /**
     * Record that this reader opened a value's profile.
     *
     * One write on a page that already costs eight reads, and the only
     * write the Value Intelligence makes about the *reader* rather than
     * about a value.
     *
     * **Re-opening moves rather than duplicates**, so the list is ten
     * distinct values and not ten visits to one. The match is
     * byte-for-byte: the list records the strings the reader opened,
     * and deciding that `GOOGLE.COM` and `google.com` are one entry is
     * a question for the instance's collation that `forTriage` pays a
     * statement to ask — not something worth a statement here, where
     * the wrong answer costs one duplicate chip.
     *
     * **It never fails the page.** A profile that 500s because its
     * convenience list could not be written would be the tail wagging
     * the dog, so a failed write is dropped: the next open records
     * both.
     *
     * **Neither log records it.** The setting is `internal`, which is
     * what makes `setSettingInternal` pass `skipAuditLog`; the legacy
     * `SysLogLogable` engine is suppressed around the save because its
     * `change => full` configuration would otherwise write the whole
     * list into `logs` on every open — and `MISP.log_new_audit`
     * defaults off, so that is the default instance rather than an
     * exotic one. A per-viewer list that an administrator can read out
     * of the log is not per-viewer.
     *
     * @param array $user
     * @param string $value As the reader opened it
     * @return void
     */
    public function rememberViewed(array $user, $value)
    {
        $value = (string)$value;
        if (empty($user['id']) || $value === '') {
            return;
        }
        $entries = $this->forRecent($user);
        $kept = array(array('value' => $value, 'at' => time()));
        foreach ($entries as $entry) {
            if ($entry['value'] === $value) {
                continue;
            }
            $kept[] = $entry;
            if (count($kept) >= self::RECENT_CAP) {
                break;
            }
        }
        $userSetting = $this->model('UserSetting');
        $logged = $userSetting->Behaviors->enabled(
            'SysLogLogable.SysLogLogable'
        );
        $userSetting->Behaviors->disable('SysLogLogable.SysLogLogable');
        try {
            $userSetting->setSettingInternal(
                $user['id'],
                self::RECENT_SETTING,
                $kept
            );
        } catch (Exception $e) {
            CakeLog::write(
                'warning',
                'ValueIntelligence::rememberViewed — ' . $e->getMessage()
            );
        }
        if ($logged) {
            $userSetting->Behaviors->enable('SysLogLogable.SysLogLogable');
        }
    }

    /**
     * Which Analyst Profile is deciding this reader's assessments.
     *
     * An assessment is not a property of a value: it is what a set of
     * thresholds made of the record, and the thresholds resolve user →
     * org → instance default with the nearest owner winning. A reader
     * who does not know which of the three answered has no way to read
     * a band they disagree with, so the strip at the head of
     * `/values/index` says it before the box does anything
     * (`value-index.md` §7.5).
     *
     * **The scope is the half that can be acted on.** Under D3 the
     * name says which document and the scope says whose — whether
     * disagreeing with a weight means editing your own page's
     * thresholds, your colleagues' too, or the instance's.
     *
     * **`revision` tells a changed assessment from a changed value.**
     * It is the local edit counter `AnalystProfile::bumpRevision()`
     * moves, and the same number the profile's own page cites, so a
     * reader whose band moved overnight can tell which of the two
     * things under it moved.
     *
     * **`editable` is the editor's own predicate**, not a restatement
     * of it. `AnalystProfilesController::edit()` refuses with
     * `isEditableByCurrentUser()`, and a strip that decided
     * separately — by scope, say — would offer a site admin no link to
     * the default they may edit, and offer an ordinary reader on their
     * organisation's profile one that 403s. An edit link that 403s is
     * worse than no edit link (§7.5), and the only way to be sure it
     * does not is to ask the same question the action asks.
     *
     * **No profile in force is a real state.** `resolveFor()` returns
     * null when a site admin has disabled the default and the reader
     * owns nothing, and every assessment on the instance then carries
     * a lean and no signal strength — `ValueVerdictTool::signalStrengthBand()`
     * bands `none` when no signal can fire. That is worth a sentence, which
     * is the caller's to write; this returns null and says so.
     *
     * **It costs nothing on a page that assessed anything.**
     * `resolveFor()` memoises per request and `forTriage()`'s cards
     * have already asked, so the statement is paid only on the plain
     * load that has nothing else to pay for.
     *
     * @param array $user
     * @return array{id: int|null, name: string, scope: string,
     *               revision: int, editable: bool}|null
     */
    public function forProfileInForce(array $user)
    {
        $analystProfile = ClassRegistry::init('AnalystProfile');
        $row = $analystProfile->resolveFor($user);
        if (empty($row)) {
            return null;
        }
        return array(
            /*
             * Null rather than absent when the row carries no id: the
             * caller draws a link only where there is something to
             * link to, and a profile assembled in memory has no page
             * of its own.
             */
            'id' => isset($row['id']) ? (int)$row['id'] : null,
            'name' => isset($row['name']) ? (string)$row['name'] : '',
            'scope' => $analystProfile->scopeOf($row),
            'revision' => isset($row['revision'])
                ? (int)$row['revision']
                : 0,
            'editable' => $analystProfile->isEditableByCurrentUser(
                $user,
                $row
            ),
        );
    }

    /**
     * The enrichment store, in two numbers.
     *
     * The question the run store generates and nothing currently
     * answers (`value-index.md` §7.7, D25): why a value's Enrichment
     * tab replied instantly, and why pressing *run* on a fresh answer
     * changes nothing. Both have the same cause — this organisation
     * already has an answer, and it is younger than the reuse window —
     * and neither the tab nor anything else says the memory exists.
     *
     * **Two numbers, and deliberately two.** The survey proposed
     * *recently enriched values*; that is withdrawn, because a list of
     * what an organisation recently enriched is a list of what it is
     * currently investigating and D27 refuses exactly that disclosure
     * one level down. What survives cannot identify anything: a count
     * carries no value, no module and no date.
     *
     * **The window is the one the tab honours, not the default.**
     * `ValueEnrichmentTool::planFor()` over the profile
     * `resolveFor()` gives, which is the same pair of calls
     * `enrichmentCatalogue()` makes — so the strip cannot cite a
     * window the tab would not apply. A profile that declares no
     * window resolves to `DEFAULT_MAX_AGE_HOURS` there and therefore
     * here.
     *
     * **Cost: one statement on top of phase 7.** `resolveFor()`
     * memoises per request and the strip has already asked it, so the
     * profile is free here and only the `COUNT(*)` is new.
     *
     * @param array $user
     * @return array{count: int, max_age_hours: int}
     */
    public function forEnrichmentStore(array $user)
    {
        $plan = ValueEnrichmentTool::planFor(
            ClassRegistry::init('AnalystProfile')->resolveFor($user)
        );
        return array(
            'count' => $this->model('ValueEnrichmentRun')->countFor($user),
            'max_age_hours' => (int)$plan['max_age_hours'],
        );
    }

    /**
     * Everything the tile row above the box draws.
     *
     * Five standing facts about the reader's own situation, read once
     * on arrival: what weighs a record, where the bands sit, how many
     * lists a value is checked against, how many modules the profile
     * declares, and what the enrichment store already holds.
     *
     * **Four of the five cost nothing.** The Analyst Profile in force
     * is resolved once per request and memoised — phase 7's strip has
     * already asked for it by the time this runs — so the signal,
     * exclusion, conflict-rule, threshold and module counts are reads
     * of an array already in memory. The whole region is **two**
     * statements: the enrichment store's `COUNT(*)` and the
     * warninglist one.
     *
     * **What is not here, and why.** Nothing counts values or
     * attributes. `Value::$useTable` is false because the subject of
     * this feature is a string rather than a row, so an *instance
     * holds N values* tile is a `GROUP BY value1` over 3.9M rows that
     * no `LIMIT` bounds (§1.1). The cheap approximation is worse than
     * nothing rather than merely imprecise: `tableRows()` answered
     * 3,034,901 against a measured 3,915,429 on the development
     * instance — 23% low — and the honest `COUNT(*)` took 285 ms,
     * which is the whole page's budget spent on a figure nobody asked
     * for. Nothing here reports activity either: what an organisation
     * recently enriched or sighted is what it is currently
     * investigating, which is the disclosure D27 refuses.
     *
     * **Three of the tiles describe a profile, so they are null when
     * none is in force.** A site admin can disable the default, and a
     * *0 signals* tile beside a strip already saying assessments carry
     * no signal strength is a second, worse way of saying the same thing. The
     * template draws what it is given and omits what it is not — the
     * page's rule that a block with nothing to say is absent rather
     * than drawn empty.
     *
     * @param array $user
     * @return array{store: array, weighs: array|null, bands: array|null,
     *               modules: int|null, warninglists: int}
     */
    public function forTiles(array $user)
    {
        $profile = ClassRegistry::init('AnalystProfile')->resolveFor($user);
        $parameters = (!empty($profile) && isset($profile['parameters'])
            && is_array($profile['parameters']))
            ? $profile['parameters']
            : null;

        $weighs = null;
        $bands = null;
        $modules = null;
        if ($parameters !== null) {
            $weighs = array(
                'signals' => $this->tileCount($parameters, 'signals'),
                'exclusions' => $this->tileCount($parameters, 'exclusions'),
                'escalations' => $this->tileCount($parameters, 'escalations'),
            );
            $thresholds = isset($parameters['thresholds'])
                && is_array($parameters['thresholds'])
                ? $parameters['thresholds']
                : array();
            $declared = isset($thresholds['signal_strength_bands'])
                && is_array($thresholds['signal_strength_bands'])
                ? $thresholds['signal_strength_bands']
                : array();
            /*
             * The fallbacks are `ValueVerdictTool::signalStrengthBand()`'s
             * own, so a profile that declares no bands is described by
             * the numbers the engine would actually use rather than by
             * a blank.
             */
            $bands = array(
                'high' => isset($declared['high'])
                    ? (int)$declared['high']
                    : 60,
                'medium' => isset($declared['medium'])
                    ? (int)$declared['medium']
                    : 30,
                'min_signals' => isset(
                    $thresholds['signal_strength_high_min_signals']
                )
                    ? (int)$thresholds['signal_strength_high_min_signals']
                    : 4,
            );
            $plan = ValueEnrichmentTool::planFor($profile);
            $modules = count($plan['declared']);
        }

        return array(
            'store' => $this->forEnrichmentStore($user),
            'weighs' => $weighs,
            'bands' => $bands,
            'modules' => $modules,
            /*
             * Instance policy rather than anybody's activity, and the
             * set every value on this instance is checked against —
             * which is what makes the warninglist chip on a profile
             * mean something. One statement over 97 rows.
             */
            'warninglists' => (int)$this->model('Warninglist')->find(
                'count',
                array(
                    'recursive' => -1,
                    'conditions' => array('Warninglist.enabled' => 1),
                )
            ),
        );
    }

    /**
     * How many entries a profile section declares.
     *
     * @param array $parameters
     * @param string $section
     * @return int
     */
    private function tileCount(array $parameters, $section)
    {
        return isset($parameters[$section]) && is_array($parameters[$section])
            ? count($parameters[$section])
            : 0;
    }

    /**
     * The page frame: the banner, the fact strip and the tab badges.
     *
     * **The only synchronous read on this page**, and the reason this
     * is one method rather than the five calls it replaces. Every panel
     * is fetched after the page paints and pays for itself; the frame
     * is fetched with the page, so a query added here is a query on the
     * critical path of every load of every value. Collecting them in
     * one place is what makes the budget something a reviewer can see
     * (`29-overview.md` §4.1).
     *
     * Seven queries, all single-row aggregates or small group-bys:
     *
     *   1. `occurrenceSummaryFor` — the strip's five numbers and both
     *      its dates, in one aggregate measured at 4 ms on a value with
     *      48,255 occurrences
     *   2. `typesFor` — the banner's type chips, and the strip's
     *      *n types* sub-line for free
     *   3. `hitsFor` — the banner's warninglist chip
     *   4. `sightingCountsFor` — the strip's sightings cell **and** the
     *      Sightings tab's badge, which is one call rather than two
     *      because a badge and a cell reading one quantity twice is how
     *      they come to disagree
     *   5. `value2CountFor` — the note below the banner
     *   6, 7. `forTabCounts` — the occurrence and object badges
     *
     * The eighth read on a page load is the assessment behind the tab
     * pill, at 9 to 27, and it is not this method's: `ValuesController::
     * view()` asks for it separately because it is the one thing here
     * that can be told only by running the engine.
     *
     * **The warninglist chip takes the names and not the categories.**
     * The Lifecycle card resolves categories through the analyst's
     * override map, which costs the profile; the chip says only *this
     * value is on a list*, which the hits alone answer. Both call
     * `hitsFor` with the same pairs, so the two cannot disagree about
     * which lists matched — they are two readings of one answer rather
     * than two answers (§4.3, D8).
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array
     */
    public function forFrame(array $user, $value, array $options = array())
    {
        $valueModel = $this->model('Value');
        $summary = $valueModel->occurrenceSummaryFor($user, $value, $options);
        $types = $valueModel->typesFor($user, $value, $options);
        $pairs = array();
        foreach ($types as $type) {
            $pairs[] = array('type' => $type['type'], 'value' => $value);
        }
        $hits = ValueWarninglistTool::hitsFor(
            $this->model('Warninglist'),
            $pairs,
            false
        );
        $sightings = $valueModel->sightingCountsFor($user, $value, $options);
        return array(
            'value' => $value,
            'types' => $types,
            'warninglists' => isset($hits[$value]) ? $hits[$value] : array(),
            'value2_note' => ValueFactsTool::value2Note(
                $valueModel->value2CountFor($user, $value, $options)
            ),
            'facts' => ValueFactsTool::strip(
                $summary,
                $types,
                $sightings,
                null,
                $summary['occurrences'] === 0
                    ? $this->pendingAdditionsFor($user, $value, $options)
                    : null
            ),
            'counts' => $this->forTabCounts(
                $user,
                $value,
                // The same number the strip prints, from the same call
                // — and the type-0 one, for the reason given there.
                array('sightings' => $sightings['sighting'])
            ),
            'enrichment_panel' => $this->enrichmentPanelPossible(
                $user,
                $value,
                $types
            ),
        );
    }

    /**
     * The pending proposals that would add this value as a new
     * attribute, as a count and the span of their dates.
     *
     * Withdrawn proposals are left out: they no longer ask for anything.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array|null `count`, `oldest`, `newest`; null when none
     */
    private function pendingAdditionsFor(array $user, $value,
        array $options = array()
    ) {
        $stamps = array();
        $proposals = $this->model('Value')->proposalsFor(
            $user,
            $value,
            array_merge($options, array('reach' => array('proposed')))
        );
        foreach ($proposals as $proposal) {
            if ($proposal['old_id'] === 0 && empty($proposal['deleted'])) {
                $stamps[] = (int)$proposal['timestamp'];
            }
        }
        if (empty($stamps)) {
            return null;
        }
        return array(
            'count' => count($stamps),
            'oldest' => min($stamps),
            'newest' => max($stamps),
        );
    }

    /**
     * Whether the Overview should emit an enrichment container at all.
     *
     * The panel decides for itself whether it has anything to draw and
     * returns nothing when it has not — but a card the page emits and
     * the endpoint fills with nothing is still a skeleton that flashes
     * and an empty div that stays, on every value page of every
     * instance that has never enriched anything. So the frame asks
     * first, and a stock instance is exactly as it was: no container,
     * no request.
     *
     * **Cheap by construction.** Two reads and neither is new: the
     * profile, which `resolveFor` has cached by the time the page's
     * assessment has been computed, and one indexed lookup over the
     * store's leading key columns. `typesFor` is the frame's own, two
     * lines above.
     *
     * **Looser than the panel, never stricter.** `declaresAuto` knows
     * what the document says and not whether those modules are
     * enabled, which is a `GET /modules` the frame will not pay for.
     * A yes that the panel then contradicts costs one empty container;
     * a no would hide a panel that had something to say.
     *
     * @param array $user
     * @param string $value
     * @param array $types `typesFor` output
     * @return bool
     */
    private function enrichmentPanelPossible(array $user, $value,
        array $types
    ) {
        $plan = ValueEnrichmentTool::planFor(
            ClassRegistry::init('AnalystProfile')->resolveFor($user)
        );
        if (ValueEnrichmentTool::declaresAuto($plan, $types)
            && !empty($user['Role']['perm_add'])
            && ValueEnrichmentTool::gateAllows(
                Configure::read('Plugin.ValueIntelligence_enrichment_auto_run'),
                !empty($user['Role']['perm_site_admin'])
            )
        ) {
            return true;
        }
        return !empty(
            $this->model('ValueEnrichmentRun')->forValue($user, $value)
        );
    }

    /**
     * The Overview's occurrence card: a preview of the table one tab
     * over.
     *
     * `forOccurrenceTable` without the facets and at a fraction of the
     * cap, and deliberately the same four attachments in the same
     * order — a card and a table that resolve an organisation or a
     * distribution differently are two answers to one question on one
     * page.
     *
     * **`OVERVIEW_OCCURRENCE_CAP` is 8 and not 300.** The table's cap
     * is set by the page control it has and this card has none: there
     * is no pagination, no sort and no facet rail here, so a reader who
     * wants the rest is one *Open full table* away. What the card owes
     * is a fair sample and an honest total, and the total is the
     * uncapped `occurrenceCountFor` rather than the rows fetched.
     *
     * **`hidden` is not computed, and that is a rule rather than an
     * omission.** `ValueStatsTool::occurrenceStats` counts no
     * occurrences withheld from this viewer by distribution. The page
     * does not tell a reader that records exist which it will not
     * show them; the empty state says *no event you can see carries
     * this value*, which distinguishes absent from hidden without
     * quantifying the gap (§1.1 D3).
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array
     */
    public function forOccurrences(array $user, $value,
        array $options = array()
    ) {
        $valueModel = $this->model('Value');
        $summary = $valueModel->occurrenceSummaryFor(
            $user,
            $value,
            array_merge($options, array('with_deleted' => true))
        );
        $rows = $valueModel->occurrencesFor(
            $user,
            $value,
            array_merge($options, array(
                'limit' => self::OVERVIEW_OCCURRENCE_CAP,
                'order' => self::OCCURRENCE_ORDER,
            ))
        );

        $this->attachTags($rows);
        $rows = $this->attachCreatorOrgs($user, $rows);
        // After the org attach, so the event-tag read is over the rows
        // that survived it rather than over the rows fetched.
        $this->attachEventTags($rows);
        $this->attachProposalCounts($rows);
        $this->attachSpellings($rows, $value);
        $this->attachEffectiveDistribution($user, $rows);

        $stats = ValueStatsTool::occurrenceStats($rows, $summary['occurrences']);
        /*
         * **The events and organisations are the value's, not the
         * page's**, and this is the §14.4 trap caught on the first
         * render rather than by reading. `occurrenceStats` derives both
         * by walking the rows it was handed, which is exact while every
         * row is in hand and becomes a count of one page the moment a
         * cap bites — *"you are then counting one page and labelling it
         * a total"*. At 25 rows the cap bit constantly and at 8 it bites
         * on almost everything: `8.8.8.8` has 26 occurrences across 20
         * events, and the card headed itself *19 events* beside a fact
         * strip reading 20.
         *
         * Both numbers come from the aggregate that already ran for the
         * total, so the card, the strip and the Occurrences tab now
         * read one query's answer rather than three tallies that ought
         * to agree. `shown` stays the row count, because that is the
         * one number on the line that *is* about the page.
         *
         * The Occurrences tab carries the same construction at a cap of
         * 300 and so the same defect above 300 occurrences — `443` has
         * 48,255. It is `forOccurrenceTable`'s to fix and the fix is
         * this one; §16.2 hands it on rather than changing a built
         * panel from here.
         */
        $stats['events'] = $summary['events'];
        $stats['orgs'] = $summary['orgs'];

        return array(
            'value' => $value,
            'occurrences' => $rows,
            'occurrence_stats' => $stats,
            /*
             * The card's Tags column draws **one** chip and folds the
             * rest, so which taxonomy leads is the whole of what a
             * reader sees of an occurrence's labelling. The column is
             * ordered where it is rendered rather than here — the two
             * scopes are merged and deduplicated in the element — so
             * what this carries is the plan and not an order.
             *
             * `resolveFor()` memoises per request, and this card is
             * its own request, so the cost is the one statement.
             */
            'label_plan' => ValueLabelPriority::planFor(
                array_key_exists('profile', $options)
                    ? $options['profile']
                    : ClassRegistry::init('AnalystProfile')
                        ->resolveFor($user)
            ),
        );
    }

    /**
     * The Overview's reporting card: who put this value on the
     * instance, and when.
     *
     * **Two questions the occurrence preview was being read for, and
     * could not answer.** A reader scrolling that card's twenty-five
     * rows was counting organisations in the *Reported by* column and
     * eyeballing the *Last seen* one — tallying a sample by hand, which
     * is both slow and wrong the moment the cap bites. Both are one
     * grouped aggregate each, so they are stated instead, and the
     * preview above is eight rows
     * (`31-overview-balance.md`).
     *
     * **Neither half is new to the page; both are new to this tab.**
     * The organisation split is the occurrence half of the Assessment
     * tab's *Who says what* — same read, same `to_ids` stance word, one
     * fewer column set — and the month strip is the Timeline tab's
     * *Activity on this value* with the axis the data's own extent
     * rather than a brushed twelve-month window. A reader who opens
     * either tab must find the same numbers there, which is why this
     * reads the same two methods rather than counting rows.
     *
     * **Three queries, and three on every value** — the stance
     * aggregate, the organisation names behind it, and the month
     * aggregate — because both reads are grouped over the value's own
     * indexed rows rather than over its occurrences. 347 ms on `443`,
     * the instance's heaviest value at 48,255 occurrences, against the
     * 223 ms `forOccurrences` pays beside it; 2 ms on a value with one
     * occurrence. Its own endpoint rather than folded into that one, on
     * the tab's standing rule — one endpoint per panel, so a slow read
     * never holds up the card next to it.
     *
     * **`orgStanceFor` excludes soft-deleted rows and the fact strip's
     * total does not**, so the two are not the same number and this
     * does not print the strip's. The split's denominator is the sum of
     * its own rows, which is what the bar actually divides; saying
     * *N of 26* against a strip reading 26 would claim the split
     * accounts for rows it left out.
     *
     * **A month with no occurrence is drawn rather than skipped.** The
     * gaps are the reading — `lifecycle.continuity` scores exactly this
     * and the Assessment tab prints *4 months without a month of
     * silence* off it — so the span is filled in here rather than left
     * to the template to infer from the keys it was handed.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array
     */
    public function forReporting(array $user, $value,
        array $options = array()
    ) {
        $valueModel = $this->model('Value');
        $stance = $valueModel->orgStanceFor($user, $value, $options);
        $names = $this->organisationNames($stance);

        $orgs = array();
        $total = 0;
        foreach ($stance as $row) {
            $id = (int)$row['Event']['orgc_id'];
            $count = (int)$row[0]['occurrences'];
            $total += $count;
            $orgs[] = array(
                'id' => $id,
                'name' => isset($names[$id])
                    ? $names[$id]
                    : __('Unknown organisation'),
                'occurrences' => $count,
                'stance' => $this->verdictStanceWord(array(
                    'to_ids_yes' => $row[0]['to_ids_yes'],
                    'to_ids_no' => $row[0]['to_ids_no'],
                )),
                // When this organisation first held it, and last
                // touched it — the card prints the first as a tooltip.
                'oldest' => empty($row[0]['oldest'])
                    ? null
                    : (int)$row[0]['oldest'],
                'newest' => empty($row[0]['newest'])
                    ? null
                    : (int)$row[0]['newest'],
            );
        }

        /*
         * **`orgStanceFor` orders by occurrence count and nothing
         * else**, and on `8.8.8.8` five organisations hold the value
         * once each — so which of them survived `REPORTING_ORG_CAP`
         * changed between two loads of the same page, with *2 further
         * organisations not shown* underneath naming a different two
         * each time. MariaDB is entitled to that; a card is not.
         *
         * The tiebreak is the name, which is the same one
         * `contextOrgs` settles its own ties with — two cards listing
         * one value's organisations in two orders is the defect this
         * avoids, not merely an unstable slice.
         */
        usort($orgs, function ($a, $b) {
            if ($a['occurrences'] !== $b['occurrences']) {
                return $b['occurrences'] - $a['occurrences'];
            }
            return strcasecmp($a['name'], $b['name']);
        });

        return array(
            'value' => $value,
            'reporting' => array(
                'orgs' => array_slice($orgs, 0, self::REPORTING_ORG_CAP),
                'orgs_total' => count($orgs),
                'occurrences' => $total,
                'months' => $this->reportingMonths(
                    $valueModel->activityMonthsFor($user, $value, $options)
                ),
            ),
        );
    }

    /**
     * The activity months, with the silent ones put back.
     *
     * `activityMonthsFor` answers a `GROUP BY month`, so a month nobody
     * reported the value in is simply absent from the result — and a
     * strip drawn straight off those keys shows a value reported every
     * month of its life however long it went quiet. The run is what the
     * card is for, so the gaps are materialised here.
     *
     * @param array $months `YYYY-MM` => occurrences, oldest first
     * @return array `YYYY-MM` => occurrences, every month in the span
     */
    private function reportingMonths(array $months)
    {
        if (empty($months)) {
            return array();
        }
        $keys = array_keys($months);
        $cursor = new DateTime(reset($keys) . '-01');
        $last = new DateTime(end($keys) . '-01');
        $step = new DateInterval('P1M');
        $filled = array();
        /*
         * Bounded by the value's age in months rather than by its
         * occurrence count, which is what makes an unbounded loop safe
         * here: the oldest attribute on a MISP instance is a decade of
         * months, not a million of them.
         */
        while ($cursor <= $last) {
            $key = $cursor->format('Y-m');
            $filled[$key] = isset($months[$key]) ? (int)$months[$key] : 0;
            $cursor->add($step);
        }
        return $filled;
    }

    /**
     * The Overview's context card: what the community has labelled this
     * value.
     *
     * Four reads and a cap:
     *
     *   1. `topTagsFor` — the labels on its occurrences, most-carried
     *      first, bounded
     *   2. `eventTagsFor` — the labels on the events it appears in,
     *      the same way, and folded into the first
     *   3. `getTagConflicts` — MISP's own exclusivity ruling
     *   4. `fetchGalaxyClusters` — which clusters this viewer may know
     *      exist
     *
     * **It was five reads and unbounded, and `443` is why it is not.**
     * The first build scoped the tags through `occurrenceEventsFor`,
     * read them with `ownTagsFor` and resolved every carrying event's
     * organisation with `fetchSimpleEvents`, so that each tag could
     * name who applied it. On `443` that is 1,844 events and **3,860
     * distinct tags**, and the card rendered all of them: a **2.9 MB**
     * fragment for a panel whose heading is a summary. The per-tag
     * organisations went with the rework, and they are the part worth
     * missing least — neither `attribute_tags` nor `event_tags` records
     * who applied a tag, so that list was never *who said this*, only
     * *whose events carry it*, which is a weaker claim than the
     * tooltip was making.
     *
     * **What the cap costs is stated rather than hidden.** The card
     * draws the most-carried `CONTEXT_TAG_CAP` labels and says so when
     * there are more, and no scale is drawn on a capped read at all —
     * a position means *one tag of this dimension*, and a truncated
     * list cannot tell that from *one that was read*.
     *
     * **The conflict marker is MISP's and not this page's.**
     * `Taxonomy::getTagConflicts` reads `exclusive` off the taxonomy
     * and the predicate, and it knows that `tlp:white` and `tlp:clear`
     * are one colour under two spellings. A rule invented here would
     * have marked every instance still carrying both as contradicting
     * itself.
     *
     * **Galaxy tags are not galaxy names.** The reader returns them
     * with `is_galaxy` set and `ownTagsFor` says in its own docblock
     * that naming the cluster needs `fetchGalaxyClusters` to rule
     * first — the ruling is the caller's either way. A tag whose
     * cluster does not come back is absent from the card, uncounted and
     * unmentioned.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array
     */
    public function forContext(array $user, $value,
        array $options = array()
    ) {
        $valueModel = $this->model('Value');
        /*
         * **One cap per kind**, because a single cap over both makes
         * the smaller list a hostage to the larger. `443` carries
         * 3,858 plain tags and two galaxy tags, so under one cap which
         * clusters survived depended on how crowded the plain list was
         * — and the live probe caught the consequence: a CIRCL org
         * admin, seeing 45 of the value's 1,844 events, was shown *more*
         * clusters than a site admin who can see all of them. Neither
         * reader saw a row they should not have; what was wrong is that
         * the galaxy list was never the value's galaxies, it was the
         * galaxies that happened to survive the tag cap.
         *
         * ----------------------------------------------------------
         * **Two scopes, one list.**
         * ----------------------------------------------------------
         * Each kind is read at both scopes and the results are folded
         * together before anything is grouped. The card drew them as
         * two sections for one day, and the reason it no longer does is
         * the one that governs the rest of the page: an attribute is
         * covered by its event's labelling, so *tagged on the report*
         * and *tagged on the indicator* are the same statement about
         * this value made at two removes, not two findings. And an
         * attribute carrying a tag of its own is the rare case — most
         * do not — so the split spent a heading, a glyph and half the
         * card's height separating a long list from a usually empty
         * one.
         *
         * **What the fold costs is the `×N` beside each chip**, and it
         * is the honest price. `topTagsFor` counts the occurrences
         * carrying a tag and `eventTagsFor` counts the events carrying
         * it; the same tag answers 2 and 8 on `8.8.8.8`. Their union is
         * not a number either read holds — an occurrence tagged
         * `tlp:white` inside an event tagged `tlp:white` is one thing
         * counted on both sides — and buying it costs a second pass
         * over the value's `attribute_tags`, 450ms on `443` for a
         * number in small print. So `mergeTagScopes` keeps both counts
         * exactly as they were read, sorts on the larger, and the card
         * states each one in the chip's title where it can name its own
         * unit. Every remaining `×N` on this page still counts one
         * thing.
         *
         * **It does not move the Assessment.** `reporting.attribution`
         * scores *no galaxy on any occurrence* and still means exactly
         * that; a cluster on the event is a weaker claim about the
         * value and is not evidence the engine was asked for. A reader
         * seeing clusters here and *no galaxy on any occurrence* in the
         * rail is reading two sentences about different things.
         *
         * Each read asks for one row more than the list will draw, so
         * *there are more* is answered by the fetch rather than by a
         * second aggregate.
         */
        $ownTags = $this->ownTags($user, $value, $options);
        unset($options['fresh']);
        $tags = $this->mergeTagScopes(
            $ownTags['tags'],
            $valueModel->eventTagsFor(
                $user,
                $value,
                self::CONTEXT_TAG_CAP + 1,
                $options + array('galaxy' => false)
            )
        );
        $capped = count($tags) > self::CONTEXT_TAG_CAP;
        if ($capped) {
            $tags = array_slice($tags, 0, self::CONTEXT_TAG_CAP, true);
        }
        $galaxyTags = $this->mergeTagScopes(
            array_slice($ownTags['galaxy'], 0, self::CONTEXT_GALAXY_CAP, true),
            $valueModel->eventTagsFor(
                $user,
                $value,
                self::CONTEXT_GALAXY_CAP,
                $options + array('galaxy' => true)
            )
        );
        if (count($galaxyTags) > self::CONTEXT_GALAXY_CAP) {
            $galaxyTags = array_slice(
                $galaxyTags,
                0,
                self::CONTEXT_GALAXY_CAP,
                true
            );
        }

        /*
         * The reader's own priority lists, which reorder what is drawn
         * and say which dimensions are drawn even when the value
         * carries none of them (`02-context-priority.md` §2). Free on a
         * page that assessed anything — `resolveFor()` memoises per
         * request — and on a stock instance it changes nothing, because
         * `default-v1` declares no list at all.
         */
        $plan = ValueLabelPriority::planFor(
            ClassRegistry::init('AnalystProfile')->resolveFor($user)
        );
        if (empty($tags) && empty($galaxyTags)) {
            return array(
                'value' => $value,
                'tags' => array(),
                'galaxies' => array(),
                'tag_cap' => null,
                'absent' => $this->pinnedAbsences(array(), array(), $plan),
            );
        }
        $taxonomies = empty($tags) ? array() : ValueContextTool::taxonomies(
            $tags,
            $this->taxonomyFold(array_keys($tags)),
            $this->tagConflicts($tags),
            $capped
        );
        $galaxies = empty($galaxyTags)
            ? array()
            : ValueContextTool::galaxies(
                $galaxyTags,
                $this->galaxyClusters($user, $galaxyTags)
            );
        return array(
            'value' => $value,
            'tags' => ValueLabelPriority::order(
                $taxonomies,
                $plan,
                ValueLabelPriority::TAXONOMIES
            ),
            'galaxies' => ValueLabelPriority::order(
                $galaxies,
                $plan,
                ValueLabelPriority::GALAXIES
            ),
            'tag_cap' => $capped ? self::CONTEXT_TAG_CAP : null,
            'absent' => $this->pinnedAbsences($taxonomies, $galaxies, $plan),
        );
    }

    /**
     * The pinned dimensions this value carries nothing of, in both
     * kinds, with the instance's enablement applied.
     *
     * **The floor is a query and it is the only one here** (D41), which
     * is why it is paid on the model's side of `ValueLabelPriority`
     * rather than inside it: a pin on a taxonomy a site admin has
     * disabled draws nothing, because `enabled = 0` says *this does not
     * exist here* and a pin says *when it is used, it matters*. The
     * first wins. Nothing is read at all unless a profile pins
     * something, so the stock instance pays for none of it.
     *
     * The stored declaration is untouched by any of this: the profile
     * keeps its entry, and re-enabling the taxonomy brings the pin
     * back rather than leaving an analyst to discover it was silently
     * erased a week ago.
     *
     * @param array $taxonomies The taxonomy groups, before ordering
     * @param array $galaxies The galaxy groups, before ordering
     * @param array $plan `ValueLabelPriority::planFor()`
     * @return array `taxonomies` and `galaxies`, each a list of keys
     */
    private function pinnedAbsences(array $taxonomies, array $galaxies,
        array $plan
    ) {
        $absent = array('taxonomies' => array(), 'galaxies' => array());
        $pinnedTaxonomies = ValueLabelPriority::keys(
            $plan,
            ValueLabelPriority::TAXONOMIES,
            ValueLabelPriority::PINNED
        );
        if (!empty($pinnedTaxonomies)) {
            $rows = $this->model('Taxonomy')->find('all', array(
                'conditions' => array(
                    'LOWER(Taxonomy.namespace)' => $pinnedTaxonomies,
                    'Taxonomy.enabled' => 1,
                ),
                'fields' => array('Taxonomy.namespace'),
                'recursive' => -1,
            ));
            $permitted = array();
            foreach ($rows as $row) {
                $permitted[] = $row['Taxonomy']['namespace'];
            }
            $absent['taxonomies'] = ValueLabelPriority::absent(
                $taxonomies,
                $plan,
                ValueLabelPriority::TAXONOMIES,
                $permitted
            );
        }
        $pinnedGalaxies = ValueLabelPriority::keys(
            $plan,
            ValueLabelPriority::GALAXIES,
            ValueLabelPriority::PINNED
        );
        if (!empty($pinnedGalaxies)) {
            $rows = $this->model('Galaxy')->find('all', array(
                'conditions' => array(
                    'LOWER(Galaxy.type)' => $pinnedGalaxies,
                    'Galaxy.enabled' => 1,
                ),
                'fields' => array('Galaxy.type'),
                'recursive' => -1,
            ));
            $permitted = array();
            foreach ($rows as $row) {
                $permitted[] = $row['Galaxy']['type'];
            }
            $absent['galaxies'] = ValueLabelPriority::absent(
                $galaxies,
                $plan,
                ValueLabelPriority::GALAXIES,
                $permitted
            );
        }
        return $absent;
    }

    /**
     * `topTagsFor` and `eventTagsFor`, folded into one list.
     *
     * Keyed by tag name, which is what both readers key by and what
     * makes a tag applied at both scopes one entry rather than two
     * chips reading as two sources agreeing.
     *
     * **`count` is a sort weight and not a quantity.** The two counts
     * are kept beside it under their own names and never added: one
     * counts occurrences and the other events, and a value's occurrence
     * carrying `tlp:white` inside an event carrying `tlp:white` would
     * be counted twice by a sum. The larger of the two orders the list,
     * which is a ranking and claims nothing about how many of what.
     *
     * **A tag is local only where every attachment was local**, which
     * is the rule each reader already applies within its own scope,
     * extended across them: a tag attached locally on an occurrence and
     * globally on the event is a globally attached tag, and the chip
     * must not mark it otherwise.
     *
     * @param array $own `Value::topTagsFor` — counts occurrences
     * @param array $event `Value::eventTagsFor` — counts events
     * @return array name => `tag`, `count`, `occurrences`, `events`
     */
    private function mergeTagScopes(array $own, array $event)
    {
        $merged = array();
        foreach ($own as $name => $row) {
            $merged[$name] = array(
                'tag' => $row['tag'],
                'occurrences' => (int)$row['count'],
                'events' => null,
            );
        }
        foreach ($event as $name => $row) {
            if (!isset($merged[$name])) {
                $merged[$name] = array(
                    'tag' => $row['tag'],
                    'occurrences' => null,
                    'events' => null,
                );
            } elseif (empty($row['tag']['local'])) {
                $merged[$name]['tag']['local'] = false;
            }
            $merged[$name]['events'] = (int)$row['count'];
        }
        foreach ($merged as $name => $row) {
            $merged[$name]['count'] = max(
                $row['occurrences'] === null ? 0 : $row['occurrences'],
                $row['events'] === null ? 0 : $row['events']
            );
        }
        uasort($merged, function ($a, $b) {
            if ($a['count'] === $b['count']) {
                return strcasecmp($a['tag']['name'], $b['tag']['name']);
            }
            return $b['count'] - $a['count'];
        });
        return $merged;
    }

    /**
     * The Overview rail's galaxy matrix: the techniques of every matrix
     * galaxy the value's occurrences, or the events holding it, are
     * tagged with, by tactic.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array `value` and `matrix`, as EventMatrixTool::compact()
     *     draws it with no origins and nothing left to roll up
     */
    public function forMatrix(array $user, $value,
        array $options = array()
    ) {
        $hits = $this->matrixHits($user, $value, $options);
        $parentNames = $this->model('Galaxy')->matrixParentNames(
            EventMatrixTool::missingParents($hits),
            $user
        );
        return array(
            'value' => $value,
            'matrix' => array(
                'rolledUp' => true,
                'galaxies' => EventMatrixTool::compact(
                    $hits,
                    0,
                    $parentNames
                ),
                'origins' => array(),
            ),
        );
    }

    /**
     * One matrix galaxy in full, for the matrix modal.
     *
     * @param array $user
     * @param string $value
     * @param int $galaxyId
     * @param string|null $tab The tab to draw; the busiest when null
     * @return array|null `value` and `matrix`, as EventMatrixTool::full();
     *     null when the galaxy is no matrix this user may see
     */
    public function forGalaxyMatrix(array $user, $value, $galaxyId,
        $tab = null
    ) {
        $galaxyModel = $this->model('Galaxy');
        $galaxy = $galaxyModel->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'Galaxy.id' => (int)$galaxyId,
                $galaxyModel->buildConditions($user),
            ),
        ));
        if (
            empty($galaxy)
            || !EventMatrixTool::isMatrixGalaxy($galaxy['Galaxy'])
        ) {
            return null;
        }
        $matrix = EventMatrixTool::full(
            $galaxyModel->matrixSkeleton($user, $galaxy['Galaxy']),
            $galaxy['Galaxy'],
            $this->matrixHits($user, $value),
            0,
            $tab
        );
        $matrix['origins'] = array();
        return array('value' => $value, 'matrix' => $matrix);
    }

    /**
     * `Value::topTagsFor` at the widest caps its two callers draw, held
     * in Redis.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor, plus `fresh`
     * @return array `tags` and `galaxy`, as Value::topTagsFor
     */
    private function ownTags(array $user, $value, array $options = array())
    {
        $fresh = !empty($options['fresh']);
        unset($options['fresh']);
        $key = 'misp:value_intelligence:own_tags:v'
            . self::CACHE_SHAPE . ':' . self::cacheScope($user)
            . ':' . hash('sha256', $value . '|' . json_encode($options));
        return $this->cachedFold($key, $fresh,
            function () use ($user, $value, $options) {
                return $this->model('Value')->topTagsFor(
                    $user,
                    $value,
                    self::CONTEXT_TAG_CAP + 1,
                    max(self::CONTEXT_GALAXY_CAP, self::MATRIX_GALAXY_CAP),
                    $options
                );
            }, self::OWN_TAGS_TTL);
    }

    /**
     * The value's galaxy tags as EventMatrixTool hits: a cluster on any
     * occurrence is the strong state, one only on the events holding the
     * value the weaker, counted in events.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array
     */
    private function matrixHits(array $user, $value,
        array $options = array()
    ) {
        $ownTags = $this->ownTags($user, $value, $options);
        unset($options['fresh']);
        $tags = $this->mergeTagScopes(
            $ownTags['galaxy'],
            $this->model('Value')->eventTagsFor(
                $user,
                $value,
                self::MATRIX_GALAXY_CAP,
                $options + array('galaxy' => true)
            )
        );
        if (empty($tags)) {
            return array();
        }
        $names = array();
        $byName = array();
        foreach ($tags as $name => $row) {
            $names[$row['tag']['id']] = $name;
            $byName[strtolower($name)] = $row;
        }
        $clusters = $this->model('GalaxyCluster')->getClustersByTags(
            $names,
            $user,
            true,
            false
        );
        $hits = array();
        foreach ($clusters as $cluster) {
            $cluster = $cluster['GalaxyCluster'];
            $row = $byName[strtolower($cluster['tag_name'])] ?? null;
            if ($row === null) {
                continue;
            }
            $hits[] = array(
                'cluster' => $cluster,
                'event' => empty($row['occurrences']) ? array() : array(0),
                'indicators' => empty($row['events'])
                    ? array()
                    : array(0 => $row['events']),
            );
        }
        return $hits;
    }

    /**
     * The Overview rail's Lifecycle card — three questions that all
     * bear on *is this still worth acting on*.
     *
     * The freshness third went live with the Analyst Profile's phase 5
     * and is `forRelevance`'s own answer, reused rather than
     * recomputed. The other two are this phase's.
     *
     * **The warninglist line reads the Assessment tab's own resolver.**
     * `verdictWarninglist` resolves each hit's category through the
     * analyst's override map, the shipped name map, the column and then
     * the default — a four-step order `WarninglistCategory` owns — and
     * the Assessment tab's warninglist band prints the answer. Two
     * surfaces on one page resolving one hit's category independently
     * is how they come to disagree, and this page has been bitten by
     * that three times.
     *
     * **The correlation line is a flag and not a count.** Nothing can
     * produce a correlation total honestly: correlations attach to attributes
     * rather than to values, so a value's total is a union over its
     * occurrences and grows with them, and phase 24 found the
     * correlation engine has nothing to say about a value in the first
     * place. What survives is the half that changes what a reader
     * should do — MISP marking the value over-correlating, which says
     * its correlations mean nothing — and it draws only when set: *0
     * correlations* would be false rather than merely unhelpful, since
     * the correlations exist and are simply not counted here (§1.1 D2).
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array
     */
    public function forLifecycle(array $user, $value,
        array $options = array()
    ) {
        $warninglist = $this->warninglistFor($user, $value, $options);
        return array(
            'value' => $value,
            'relevance' => $this->forRelevance(
                $user,
                $value,
                $options
            )['relevance'],
            'warninglists' => $warninglist['hits'],
            'warninglists_checked' => $warninglist['lists_checked'],
            'correlations' => array(
                'over_correlating' => $this->overCorrelating($value),
                /*
                 * Config rather than a query, and it is here so the
                 * warning can name the number it crossed. The same
                 * limit `relationSettings` reports to the Relationships
                 * tab.
                 */
                'threshold' => (int)$this
                    ->model('OverCorrelatingValue')->getLimit(),
            ),
        );
    }

    /**
     * The warninglist answer, resolved exactly as the Assessment tab
     * resolves it.
     *
     * A thin public seam onto `verdictWarninglist` so that a caller
     * outside the assessment gets the categories through the same four
     * steps and the same override map. It costs the profile, which is
     * why the banner chip does not use it.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array `hits`, `lists_checked`, `category`
     */
    public function warninglistFor(array $user, $value,
        array $options = array()
    ) {
        $profile = array_key_exists('profile', $options)
            ? $options['profile']
            : ClassRegistry::init('AnalystProfile')->resolveFor($user);
        return $this->verdictWarninglist(
            $value,
            Value::asTypes(
                $this->model('Value')->typesFor($user, $value, $options)
            ),
            $profile
        );
    }

    /**
     * The Occurrences tab: the facet rail and the table it counts.
     *
     * One method for both, because a facet count and the rows it counts
     * have to come out of one assembly or they can disagree with each
     * other — which is the same reason `viewOccurrenceTable` is one
     * endpoint rather than two.
     *
     * Six queries, none of them per-occurrence or per-event:
     *
     *   1. the viewer's occurrence count            `Value`
     *   2. the occurrence rows, capped              `Value`
     *   3. their attribute tags (the hasMany half of 2's contain)
     *   4. the tag records behind those             `MispAttribute`
     *   5. `Event.Orgc` for all N events at once    `Event`
     *   6. pending proposals per row                `ShadowAttribute`
     *
     * @param array $user
     * @param string $value
     * @param array $options Reserved; `types` reaches `Value`
     * @return array
     */
    public function forOccurrenceTable(array $user, $value,
        array $options = array()
    ) {
        $valueModel = $this->model('Value');
        $summary = $valueModel->occurrenceSummaryFor(
            $user,
            $value,
            array_merge($options, array('with_deleted' => true))
        );
        $total = $summary['occurrences'];
        $rows = $valueModel->occurrencesFor(
            $user,
            $value,
            array_merge($options, array(
                'limit' => self::OCCURRENCE_CAP,
                'order' => self::OCCURRENCE_ORDER,
            ))
        );

        $this->attachTags($rows);
        $rows = $this->attachCreatorOrgs($user, $rows);
        // After the org attach, so the event-tag read is over the rows
        // that survived it rather than over the rows fetched.
        $this->attachEventTags($rows);
        // After both tag attaches: a row's clusters are the galaxy tags
        // of either scope, ruled on together in one call.
        $this->attachClusters($user, $rows);
        $this->attachProposalCounts($rows, true);
        $this->attachSpellings($rows, $value);
        $this->attachEffectiveDistribution($user, $rows);
        $this->attachFeedHits($user, $rows);

        $stats = ValueStatsTool::occurrenceStats($rows, $total);
        /*
         * **The events and organisations are the value's, not the
         * page's**, as on the Overview card — `forOccurrences` has the
         * argument and phase 29 §14.2 the case. `occurrenceStats`
         * derives both by walking the rows it was handed, which is
         * exact while every row is in hand and becomes a count of one
         * page the moment a cap bites. At 300 that is rarer than the
         * card's 8 and not rare: `443` is 48,255 occurrences across
         * 1,844 events, and this header claimed the events of its first
         * 300 beside a fact strip reading the real number.
         *
         * `occurrenceCountFor` is gone from here with it. The summary
         * answers the total from the same conditions in the same query
         * as the other two, so the three cannot drift and the panel
         * pays one aggregate rather than two.
         */
        $stats['events'] = $summary['events'];
        $stats['orgs'] = $summary['orgs'];

        /*
         * One plan for the whole tab. The rail folds at ten and the
         * table's two label columns fold at four and three, so the
         * profile has to reach all three before their folds rather
         * than after; built once here so the rail cannot rank a
         * taxonomy the column beside it ranks differently.
         * `resolveFor()` memoises, so this tab pays nothing for it.
         */
        $plan = ValueLabelPriority::planFor(
            array_key_exists('profile', $options)
                ? $options['profile']
                : ClassRegistry::init('AnalystProfile')
                    ->resolveFor($user)
        );

        return array(
            'value' => $value,
            'occurrences' => $rows,
            'occurrence_stats' => $stats,
            'label_plan' => $plan,
            'feeds_shown' => !empty(
                $user['Role']['perm_view_feed_correlations']
            ),
            /*
             * Null rather than a set of zero groups on a value with no
             * occurrence the viewer may see: a rail of zeroes is a lie
             * about the value (tabs/00-shared.md §5), and the table
             * renders one honest empty state at full width instead.
             */
            'occurrence_facets' => empty($rows)
                ? null
                : ValueStatsTool::occurrenceFacets($rows, $total, $plan),
            'occurrence_cap' => $total > $stats['shown']
                ? array('shown' => $stats['shown'], 'total' => $total)
                : null,
            'standalone_proposals' => $this->standaloneProposals(
                $user,
                $value,
                $options
            ),
        );
    }

    /**
     * The proposals that propose *adding* this value, which no
     * occurrence read can see.
     *
     * **`value-intelligence-coverage.md` §2.2's defect, and it is visible on
     * real rows.** A proposal with `old_id = 0` proposes a new
     * attribute rather than a change to one, so nothing in `attributes`
     * holds the value yet — and a page built entirely on occurrence
     * reads therefore renders `123.123.123.1`, which three
     * organisations can see proposed on event 195, as §2.12's unknown
     * page. The verification instance carries six such rows across
     * three values and the tab was blind to all of them.
     *
     * **Not merged into the occurrence rows, and that is the whole of
     * the counting question §5.1 asked.** The table's header states *N
     * attribute rows across M events*, its rail counts facets over
     * those rows, and its script sorts and pages them; a proposal
     * folded into that set would be counted by all three as a row of a
     * table it is not a row of. §5.1's own answer is that a proposal is
     * not an attribute row and the header should not say it is, so the
     * rows travel beside the table under a heading of their own and
     * every number the table prints is the number it printed before.
     *
     * **One statement, because the other could not match.** `reach` is
     * `proposed`: the `target` scope joins `Attribute` through `old_id`
     * and a standalone proposal has no target, so that half is a query
     * whose empty result is guaranteed.
     *
     * **The gate is looser here than anywhere else on this page, and it
     * is MISP's.** `ShadowAttribute::buildConditions` ORs `old_id = 0`
     * past the whole attribute-and-object distribution test — there is
     * no attribute to test — leaving these rows gated on **event
     * visibility alone**. `Value::proposalsFor` applies it as MISP
     * wrote it; this records that the occurrence table's ACL reasoning
     * does not carry over to the block beneath it.
     *
     * Withdrawn proposals are kept and marked, the way phase 26's
     * report panel keeps withdrawn reports: a proposal somebody
     * discarded is still a dated thing that happened to this value.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array|null Null where there are none at all
     */
    private function standaloneProposals(array $user, $value,
        array $options = array()
    ) {
        $rows = array();
        $withdrawn = 0;
        $proposals = $this->model('Value')->proposalsFor(
            $user,
            $value,
            array_merge($options, array('reach' => array('proposed')))
        );
        foreach ($proposals as $proposal) {
            if ($proposal['old_id'] !== 0) {
                continue;
            }
            if (!empty($proposal['deleted'])) {
                $withdrawn++;
            }
            $rows[] = $proposal;
        }
        if (empty($rows)) {
            /*
             * Null and not an empty list, under the rule the rail
             * follows: a heading over nothing is a claim about the
             * value, and the tab already draws one honest empty state.
             */
            return null;
        }
        usort($rows, function ($a, $b) {
            return $b['timestamp'] - $a['timestamp'];
        });
        $capped = count($rows) > self::STANDALONE_PROPOSAL_CAP;
        return array(
            'rows' => array_slice(
                $rows,
                0,
                self::STANDALONE_PROPOSAL_CAP
            ),
            'total' => count($rows),
            'withdrawn' => $withdrawn,
            'capped' => $capped,
        );
    }

    /**
     * The Sightings tab's chart: the reports as a stacked histogram,
     * with the value's remaining shelf life drawn through it.
     *
     * **The overlay changed subject in phase 5** and it is a better
     * chart for it (`06-staleness.md` §4.2). It used to draw one decay
     * score per applicable model — two estimates of one quantity, on a
     * page whose ledger already answers *how bad is this* from more
     * evidence — where it now plots **evidence against remaining shelf
     * life**, which is two different quantities and a question an
     * analyst actually has.
     *
     * It also stopped being the slow panel. The decay envelope
     * evaluated MISP's polynomial per occurrence per day per model and
     * was the only thing on this page doing work proportional to that
     * product; the runway is one expression per day. The five-endpoint
     * split stays, because the reasons for it in `ValuesController` were
     * never only the envelope.
     *
     * @param array $user
     * @param string $value
     * @param array $options Reserved; `types` reaches `Value`
     * @return array
     */
    public function forSightingChart(array $user, $value,
        array $options = array()
    ) {
        $context = $this->sightingContext($user, $value, $options);
        $span = $this->spanFor($user, $value, $context, $options);
        $relevance = $this->relevanceFor(
            $user,
            $value,
            $context,
            $options
        );
        return array(
            'value' => $value,
            'sightings' => $this->sightingHeader($context),
            'sighting_series' => $span === null
                ? null
                : ValueStatsTool::sightingSeries(
                    $context['sightings'],
                    $span,
                    $context['totals'],
                    $this->runwayCurve($relevance, $span)
                ),
            'sighting_notes' => ValueStatsTool::sightingNotes(
                $context['totals']
            ),
            'relevance' => $relevance,
        );
    }

    /**
     * The runway as the chart's one overlay series.
     *
     * The series shape is the one the browser already reads — a label,
     * a threshold and one point per day — because the payload, the
     * hover readout and the legend were all written against it and none
     * of them cares what the line means. What changes is the scale: a
     * runway is a fraction, and the chart's right axis is 0–100, so it
     * goes over as a percentage of shelf life.
     *
     * `threshold` is null rather than a number. A decay model's
     * threshold was a constant the rail drew as a tick; expiry is the
     * axis reaching zero, which the axis already shows.
     *
     * @param array $relevance From relevanceFor
     * @param array|null $span From `ValueStatsTool::sightingSpan`
     * @return array One curve, or none when there is nothing to draw
     */
    private function runwayCurve(array $relevance, $span)
    {
        if ($span === null || $relevance['state'] === null) {
            return array();
        }
        $points = ValueRelevanceTool::runwaySeries(
            $relevance,
            $this->dayGrid($span),
            /*
             * `first` is the value's own earliest evidence and `from`
             * is where the span was clipped to, so a value first seen in
             * 2015 draws from the clip rather than from a day the chart
             * does not show. Before that day the series draws nothing,
             * which is the gap the retired code also drew and for the
             * same reason: zero is a score, absence is not.
             */
            strtotime($span['first'] . ' 00:00:00')
        );
        foreach ($points as $i => $point) {
            $points[$i] = $point === null
                ? null
                : (int)round($point * 100);
        }
        return array(array(
            'model' => __('Lifetime left'),
            'threshold' => null,
            'points' => $points,
        ));
    }

    /**
     * The Overview's sightings card: the three counts, who filed them,
     * and a 90-day sparkline.
     *
     * On the Overview and not the Sightings tab, and the only panel of
     * either that this method serves. It is here rather than in the
     * Overview's own methods because of what it is made of: the same
     * `sightingContext` the tab's four endpoints share, so a card and a
     * tab on one page cannot disagree about the same value.
     *
     * No relevance work, like the list: a card above the fold should
     * not wait for the axis, and the three counts it shows are not part
     * of it.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forSightings(array $user, $value,
        array $options = array()
    ) {
        $context = $this->sightingContext($user, $value, $options);
        /*
         * No spark at all for a value nobody has reported, rather than
         * forty empty columns. The card already says `Nobody has
         * reported seeing this` underneath, and a flat strip over that
         * sentence is a chart of nothing.
         *
         * Quiet is not the same as absent, so a value with reports but
         * none in the last ninety days keeps its strip: there, the
         * empty columns are the answer to the question the strip asks.
         */
        $reported = $context['totals']['total'] > 0;
        return array(
            'value' => $value,
            'sightings' => $this->sightingHeader($context) + array(
                'spark' => $reported
                    ? ValueStatsTool::sightingSpark(
                        $context['sightings'],
                        date('Y-m-d')
                    )
                    : array(),
            ),
        );
    }

    /**
     * The individual sightings, and the range note the brush drives.
     *
     * No relevance work at all, which is the point of it being its own
     * endpoint: the table is the part of the tab a reader can act on and
     * it should not wait for the overlay beside it.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forSightingList(array $user, $value,
        array $options = array()
    ) {
        $context = $this->sightingContext($user, $value, $options);
        return array(
            'value' => $value,
            'sighting_rows' => ValueStatsTool::sightingList(
                $context['sightings'],
                $context['sighted']
            ),
            'sighting_notes' => ValueStatsTool::sightingNotes(
                $context['totals']
            ),
        );
    }

    /**
     * The rail's relevance card: how fresh this value is, and what
     * made it so.
     *
     * The decay card's replacement, at panel scale
     * (`06-staleness.md` §4). It computes the axis a second time rather
     * than sharing the chart's, because the two panels are two requests
     * and this page has no cache — §14.4 leaves caching out
     * deliberately. What that buys is the same thing it bought before:
     * the state in the rail is the last point of the curve in the chart
     * by construction rather than by coincidence, which is the sentence
     * the card closes with. It is now cheap enough that the argument
     * barely needs making.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forRelevance(array $user, $value,
        array $options = array()
    ) {
        $context = $this->sightingContext($user, $value, $options);
        return array(
            'value' => $value,
            'sightings' => $this->sightingHeader($context),
            'relevance' => $this->relevanceFor(
                $user,
                $value,
                $context,
                $options
            ),
            'sighting_notes' => ValueStatsTool::sightingNotes(
                $context['totals']
            ),
            /*
             * The dates the axis is built on, side by side. One
             * aggregate, and it belongs to this panel rather than to
             * the shared context: nothing else reads it, and the
             * verdict must keep working when it is not there.
             */
            'timeline_facts' => $this->model('Value')->timelineFactsFor(
                $user,
                $value,
                $options
            ),
        );
    }

    /**
     * The rail's reporters card: one bar per organisation, every report
     * it filed of any type.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forSightingReporters(array $user, $value,
        array $options = array()
    ) {
        $context = $this->sightingContext($user, $value, $options);
        return array(
            'value' => $value,
            'sightings' => $this->sightingHeader($context),
        );
    }

    /**
     * The rail's write card, still disabled, and the fan-out sentence
     * that has to be true before it ever is enabled.
     *
     * The count is the occurrence set `Sighting::saveSightings` would
     * actually write to: it resolves the value through
     * `fetchAttributesSimple`, which is the same fetcher behind
     * `Value::occurrenceIdsFor` and neither of them drops a
     * soft-deleted row. So the number here is larger than the number of
     * occurrences the sighting *list* beside it can show, and it is the
     * write's number that this card owes the reader.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forSightingAdd(array $user, $value,
        array $options = array()
    ) {
        $summary = $this->summaryFor($user, $value, $options);
        return array(
            'value' => $value,
            'sighting_fanout' => array(
                'occurrences' => $summary['occurrences'],
                'events' => $summary['events'],
                'orgs' => $summary['orgs'],
            ),
        );
    }

    /**
     * The reports on a value, and the summary of the occurrence set they
     * were filed against. Every sightings panel starts here.
     *
     * One query of ours plus the two `Sighting::listSightings` makes,
     * and **none of them touches every occurrence the value has**:
     *
     *   1. the occurrences carrying a report          `Value`
     *   2. `listSightings`' own attribute re-fetch    `MispAttribute`
     *   3. the sighting rows                          `Sighting`
     *
     * Query 1 is the one this panel could not do without, and the first
     * version of this phase did not have it: it scoped `listSightings`
     * by the value's whole occurrence set. On `443` that is 48,255 ids
     * handed to a fetcher that re-resolves every one of them, measured
     * at 1.6 to 3.4 seconds per panel — for three sightings. Narrowing
     * to the occurrences that have actually been reported is the whole
     * difference between this tab working on a real instance and not.
     *
     * **`listSightings` re-resolves the ids it is given**, through
     * `fetchAttributes` with `Attribute.deleted = 0` forced. So a report
     * filed against a soft-deleted occurrence is invisible to this tab
     * while the occurrence itself is visible on the Occurrences tab —
     * a defect in shared code, reported rather than fixed here per
     * §14.7. It is also why the ids are pre-filtered: handed nothing but
     * soft-deleted ids the fetcher returns nothing and `listSightings`
     * throws `MethodNotAllowedException` rather than an empty list.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array `summary`, `sighted`, `sightings`, `totals`, `span`
     */
    private function sightingContext(array $user, $value,
        array $options = array()
    ) {
        $sighted = $this->model('Value')->sightedOccurrenceIdsFor(
            $user,
            $value,
            $options
        );
        $sightable = array();
        foreach ($sighted as $id => $occurrence) {
            if (empty($occurrence['deleted'])) {
                $sightable[] = $id;
            }
        }
        $sightings = array();
        if (!empty($sightable)) {
            $sightings = $this->model('Sighting')->listSightings(
                $user,
                $sightable,
                'attribute',
                false,
                false,
                false
            );
        }
        return array(
            'sighted' => $sighted,
            'sightings' => $sightings,
            'totals' => ValueStatsTool::sightingTotals($sightings),
        );
    }

    /**
     * The occurrence summary, fetched at most once per request.
     *
     * Lazy because two of the five panels never need it and it is the
     * one query on this tab whose cost tracks the value's size: 413 ms
     * on `443`, whose 48,255 occurrences it has to scan to count them.
     * The reporters card and the sightings table are the tab's fast
     * panels and asking them to wait for it made them four times
     * slower for nothing.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array From `Value::occurrenceSummaryFor`
     */
    private function summaryFor(array $user, $value, array $options)
    {
        $this->forget($value);
        if ($this->summary === null) {
            $this->summary = $this->model('Value')
                ->occurrenceSummaryFor($user, $value, $options);
        }
        return $this->summary;
    }

    /**
     * The chart's span, or null when the value has no occurrence this
     * viewer can see — there is then no axis to draw and no window to
     * invent one over.
     *
     * @param array $user
     * @param string $value
     * @param array $context From sightingContext
     * @param array $options
     * @return array|null
     */
    private function spanFor(array $user, $value, array $context,
        array $options
    ) {
        $summary = $this->summaryFor($user, $value, $options);
        return $summary['occurrences'] === 0
            ? null
            : ValueStatsTool::sightingSpan(
                $summary,
                $context['sightings'],
                date('Y-m-d')
            );
    }

    /**
     * The `sightings` key three of the five panels read: the header
     * counts, the reporter bars and the phrase for the last report.
     *
     * @param array $context From sightingContext
     * @return array
     */
    private function sightingHeader(array $context)
    {
        $totals = $context['totals'];
        return array(
            'total' => $totals['total'],
            'fp' => $totals['fp'],
            'expiration' => $totals['expiration'],
            'reporters' => $totals['reporters'],
            'last' => ValueStatsTool::agoPhrase(
                $totals['last_stamp'],
                time()
            ),
            /*
             * The stamp as well as the phrase. `last` is *16 days ago*,
             * which is the right thing beside a count and the wrong
             * thing in a column of dates — the relevance card's
             * provenance table prints `date_sighting` next to
             * `Attribute.timestamp` and the two have to be comparable.
             */
            'last_stamp' => $totals['last_stamp'],
        );
    }

    /**
     * The relevance axis for one value, and the facts the two panels
     * that render it read.
     *
     * **This is what replaced 338 lines of decay envelope**
     * (`06-staleness.md` §4). The old path evaluated MISP's polynomial
     * once per occurrence per day per model — around 200,000 calls on
     * the busiest value, which is why the Sightings tab was split into
     * five endpoints in the first place. The relevance axis is
     * arithmetic over a handful of dates, so this method issues **no
     * query of its own**: the clock's occurrence half rides on the
     * stance aggregate the assessment already reads, and its sighting
     * half is folded from the rows `sightingContext` has in hand.
     *
     * The aggregation decision phase 23 recorded transfers intact
     * (§4.1). Its problem was *"turn per-attribute time facts into one
     * value-level statement"* and its answer was *"take the maximum and
     * label it with the occurrence holding it"* —
     * `last_independent_corroboration` has exactly that problem and
     * exactly that answer, so the clock names what supplied it.
     *
     * @param array $user
     * @param string $value
     * @param array $context From sightingContext
     * @param array $options As conditionsFor, plus `profile` to score
     *                       against one other than the viewer's — the
     *                       seam a profile simulator needs and the only
     *                       way to check that a relevance setting moves
     *                       the axis and nothing else
     * @return array The `relevance` block, plus the profile that
     *               produced it
     */
    private function relevanceFor(array $user, $value, array $context,
        array $options = array()
    ) {
        $profile = array_key_exists('profile', $options)
            ? $options['profile']
            : ClassRegistry::init('AnalystProfile')->resolveFor($user);
        // Not a query option, and `conditionsFor` is handed the rest.
        unset($options['profile']);
        $exclusions = new ValueExclusionTool();
        $plan = $exclusions->planFor($profile, $user);
        $options = array_merge(
            $options,
            $exclusions->conditionOptions($plan)
        );
        $rows = $exclusions->applyToSightings(
            $context['sightings'],
            $context['sighted'],
            $plan
        );
        $summary = $this->model('Value')
            ->recordSummaryFor($user, $value, $options);
        $facts = array(
            'value' => $value,
            'now' => time(),
            'as_of' => date('Y-m-d'),
            'types' => $this->model('Value')
                ->typesFor($user, $value, $options),
            'occurrences' => array(
                'total' => $summary['occurrences'],
                'events' => $summary['events'],
                'orgs' => $summary['orgs'],
                'oldest' => $summary['oldest'],
                'newest' => $summary['newest'],
            ),
            'temporal' => array(
                'occurrences' => $summary['occurrences'],
                'with_first_seen' => $summary['dated'],
            ),
            'orgs' => $this->verdictOrgs($user, $value, $options),
            'trust' => $this->verdictTrust($profile),
            'corroboration' => ValueRelevanceTool::corroborationFrom(
                $rows['rows'],
                $context['sighted']
            ),
            'budget' => array('hot' => false),
            'missing' => array(),
        );
        $relevance = ValueRelevanceTool::relevanceFor($facts, $profile);
        $relevance['profile'] = $profile === null
            ? null
            : (isset($profile['name']) ? $profile['name'] : null);
        $relevance['sightings_excluded'] = $rows['excluded'];
        return $relevance;
    }

    /**
     * The day grid the runway is sampled on: one point per day of the
     * span, at the end of each day, and `now` for the last one.
     *
     * End of day rather than start, so a report filed this morning has
     * already moved today's point. And `now` rather than the end of
     * today, so the series' last point is the runway the rail card
     * prints — which is what makes the card's closing sentence true
     * rather than approximately true.
     *
     * @param array $span From `ValueStatsTool::sightingSpan`
     * @return array Ascending unix timestamps
     */
    private function dayGrid(array $span)
    {
        $now = time();
        $grid = array();
        $day = strtotime($span['from'] . ' 00:00:00');
        $stop = strtotime($span['to'] . ' 00:00:00');
        while ($day <= $stop) {
            $end = $day + 86399;
            $grid[] = min($end, $now);
            $day += 86400;
        }
        if (empty($grid)) {
            $grid[] = $now;
        }
        return $grid;
    }

    /**
     * The tag records behind each row's attribute tags.
     *
     * `contain => ['AttributeTag']` gives only `tag_id`; this turns
     * those into the records the chips and the rail's facets are drawn
     * from. `includeAllTags` because `Tag.exportable = 0` is a statement
     * about exports, not about visibility — this page is an inspection
     * view, and a tag the reader can see on the event page should not
     * disappear here.
     *
     * @param array $rows
     * @return void
     */
    private function attachTags(array &$rows)
    {
        if (empty($rows)) {
            return;
        }
        $this->model('MispAttribute')->attachTagsToAttributes(
            $rows,
            array('includeAllTags' => true)
        );
    }

    /**
     * The tags on each row's **event**, under `EventTag`.
     *
     * `attachTags`' event-scope twin, and it exists because the Tags
     * column was showing a minority of what anybody had said about the
     * value: an analyst tags the report far more often than the
     * indicator, and this page joined `attribute_tags` alone. On
     * `8.8.8.8` that is 7 distinct labels drawn against 48 not drawn.
     *
     * **One query for every event on the page, never one per row.**
     * `attachCreatorOrgs` states this page's standing rule and this
     * follows it: the rows are capped — 8 on the Overview card, 300 on
     * the tab — so the distinct events behind them are bounded by the
     * cap, and the whole column costs one `IN`.
     *
     * **No ACL of its own, because there is none to add.** Every row
     * here came back through `fetchAttributesSimple` under
     * `buildConditions`, so its event is one the reader may open; an
     * event's tags are visible to anyone who can open it. `local` is an
     * export rule rather than an access one — `Value::eventTagsFor`
     * carries the argument and the callers that set
     * `excludeLocalTags` — so local tags are kept and marked rather
     * than dropped.
     *
     * `Tag.exportable` is not filtered, matching `attachTags`, which
     * passes `includeAllTags`. Two tag lists in one table cell obeying
     * two different export rules would be a distinction the cell cannot
     * draw.
     *
     * @param array $rows Occurrence rows, by reference
     * @return void
     */
    private function attachEventTags(array &$rows)
    {
        if (empty($rows)) {
            return;
        }
        $eventIds = array();
        foreach ($rows as $row) {
            if (!empty($row['Event']['id'])) {
                $eventIds[(int)$row['Event']['id']] = true;
            }
        }
        if (empty($eventIds)) {
            return;
        }
        $tagged = $this->model('EventTag')->find('all', array(
            'conditions' => array(
                'EventTag.event_id' => array_keys($eventIds),
            ),
            'recursive' => -1,
            'fields' => array(
                'EventTag.event_id',
                'EventTag.tag_id',
                'EventTag.local',
            ),
            'contain' => array(
                'Tag' => array(
                    'fields' => array(
                        'Tag.id',
                        'Tag.name',
                        'Tag.colour',
                        'Tag.is_galaxy',
                    ),
                ),
            ),
        ));

        $byEvent = array();
        foreach ($tagged as $row) {
            if (empty($row['Tag']['id'])) {
                continue;
            }
            $eventId = (int)$row['EventTag']['event_id'];
            $tag = $row['Tag'];
            $tag['local'] = !empty($row['EventTag']['local']);
            $byEvent[$eventId][] = array('Tag' => $tag,
                'local' => $tag['local']);
        }
        foreach ($rows as $k => $row) {
            $eventId = empty($row['Event']['id'])
                ? null
                : (int)$row['Event']['id'];
            $rows[$k]['EventTag'] = $eventId !== null
                && isset($byEvent[$eventId])
                ? $byEvent[$eventId]
                : array();
        }
    }

    /**
     * The galaxy clusters each row is attributed to, under `Cluster`.
     *
     * A galaxy tag reaches the row on either scope — its own
     * `AttributeTag` or its event's `EventTag` — and until now every
     * surface in the occurrences pane **dropped** it. That was
     * `Fields/tag_list`'s rule inherited without being re-argued: a
     * cluster is not a label, and the Overview's context card draws it
     * as a cluster. What the rule missed is that the context card is
     * *the value's* attribution, and the table's question is which
     * occurrences — on `8.8.8.8`, 9 of 26 rows carry a cluster and 26
     * distinct ones are on the page, none of them reachable from the
     * tab a reader is looking at.
     *
     * **A galaxy tag is not a cluster until `fetchGalaxyClusters` says
     * so**, which is the same ruling `ValueIntelligence::galaxyClusters`
     * makes for the card and for the same two reasons: the tag carries
     * no readable name, and seeing a row is not permission to know what
     * its cluster is. `1.162.239.42` carries four galaxy tags of which
     * **two** come back. A tag with no cluster row is absent, with
     * nothing drawn in its place and no count of what was withheld.
     *
     * **One query for the page**, as everything else that attaches here
     * does: the rows are capped at `OCCURRENCE_CAP`, so their distinct
     * galaxy tags are bounded by it — 26 on the widest value the
     * instance has, resolved in 11ms.
     *
     * Each row's clusters are deduplicated by tag name, so a cluster on
     * the attribute *and* on its event is one entry. They carry their
     * galaxy, because the column groups by it and the rail names it.
     *
     * @param array $user
     * @param array $rows Occurrence rows, by reference
     * @return void
     */
    private function attachClusters(array $user, array &$rows)
    {
        if (empty($rows)) {
            return;
        }
        $names = array();
        foreach ($rows as $row) {
            foreach (array('AttributeTag', 'EventTag') as $scope) {
                foreach ($row[$scope] ?? array() as $entry) {
                    if (!empty($entry['Tag']['is_galaxy'])
                        && !empty($entry['Tag']['name'])
                    ) {
                        $names[$entry['Tag']['name']] = true;
                    }
                }
            }
        }
        if (empty($names)) {
            foreach ($rows as $k => $row) {
                $rows[$k]['Cluster'] = array();
            }
            return;
        }

        $named = array();
        $found = $this->model('GalaxyCluster')->fetchGalaxyClusters(
            $user,
            array('conditions' => array(
                'GalaxyCluster.tag_name' => array_keys($names),
            ))
        );
        foreach ($found as $row) {
            $cluster = $row['GalaxyCluster'];
            if (empty($cluster['tag_name'])) {
                continue;
            }
            $named[$cluster['tag_name']] = array(
                'id' => (int)$cluster['id'],
                'name' => empty($cluster['value'])
                    ? $cluster['tag_name']
                    : $cluster['value'],
                // `arrangeData` moves the contained `Galaxy` inside the
                // cluster, which is where this reads it; at the top
                // level it is silently absent.
                'galaxy' => empty($cluster['Galaxy']['name'])
                    ? $cluster['type']
                    : $cluster['Galaxy']['name'],
                /*
                 * What a profile's priority lists name this galaxy by,
                 * which the display name above is not: the lists hold
                 * `threat-actor` and the name reads *Threat Actor*.
                 * Beside it rather than instead of it, because the
                 * rail prints one and ranks by the other.
                 */
                'type' => $cluster['type'],
                'tag_name' => $cluster['tag_name'],
            );
        }

        foreach ($rows as $k => $row) {
            $seen = array();
            $clusters = array();
            foreach (array('AttributeTag', 'EventTag') as $scope) {
                foreach ($row[$scope] ?? array() as $entry) {
                    $name = $entry['Tag']['name'] ?? null;
                    if ($name === null
                        || empty($entry['Tag']['is_galaxy'])
                        || isset($seen[$name])
                        || !isset($named[$name])
                    ) {
                        continue;
                    }
                    $seen[$name] = true;
                    $clusters[] = $named[$name];
                }
            }
            /*
             * By galaxy, then by cluster, so a cell listing six reads
             * as the groups the card draws rather than as the order
             * two tag tables happened to return.
             */
            usort($clusters, function ($a, $b) {
                $galaxy = strcasecmp($a['galaxy'], $b['galaxy']);
                return $galaxy === 0
                    ? strcasecmp($a['name'], $b['name'])
                    : $galaxy;
            });
            $rows[$k]['Cluster'] = $clusters;
        }
    }

    /**
     * `Event.Orgc` for every event the rows sit on, in one call.
     *
     * §14.4's one performance commitment: never one call per event. A
     * value in seven events is one `fetchSimpleEvents`, not seven
     * `fetchEvent`s — the cheap path §14.10 found that §8.2 had costed
     * as a full event graph per event.
     *
     * A nested `contain => ['Event' => ['Orgc']]` would have folded this
     * into the row fetch for nothing, since both are `belongsTo` and
     * become joins. It is a separate call so that the event's ACL is
     * checked by the model that owns events:
     * `Event::createEventConditions` is the same event predicate
     * `MispAttribute::buildConditions` embeds, so it can never be
     * stricter and the drop below can never fire — which is the point of
     * having it, since a divergence would then cost a row rather than
     * leak one.
     *
     * The organisation is rebuilt from `Event.orgc_id` rather than read
     * out of the contained record, because `fetchSimpleEvents` fixes its
     * own `contain` at `Orgc.name` and the facet token is the id.
     *
     * @param array $user
     * @param array $rows
     * @return array Rows whose event this viewer may open
     */
    private function attachCreatorOrgs(array $user, array $rows)
    {
        if (empty($rows)) {
            return $rows;
        }
        $eventIds = array();
        foreach ($rows as $row) {
            $eventIds[$row['Event']['id']] = true;
        }
        $events = $this->model('Event')->fetchSimpleEvents(
            $user,
            array('conditions' => array(
                'Event.id' => array_keys($eventIds),
            )),
            true
        );
        $orgs = array();
        foreach ($events as $event) {
            $orgs[$event['Event']['id']] = array(
                'id' => $event['Event']['orgc_id'],
                'name' => isset($event['Orgc']['name'])
                    ? $event['Orgc']['name']
                    : __('Unknown organisation'),
            );
        }
        $kept = array();
        foreach ($rows as $row) {
            $eventId = $row['Event']['id'];
            if (!isset($orgs[$eventId])) {
                continue;
            }
            $row['Event']['Orgc'] = $orgs[$eventId];
            $kept[] = $row;
        }
        return $kept;
    }

    /**
     * Who can actually see each occurrence.
     *
     * An attribute's own `distribution` column is level 5 — *inherit* —
     * for almost every row on a real instance, so reporting it tells the
     * reader nothing: the level that matters is the conjunction of the
     * attribute's, its object's and its event's, which is the same rule
     * `MispAttribute::buildConditions` enforces to decide whether the row
     * is visible at all. `ValueStatsTool::effectiveDistribution()` owns
     * the resolution; this stamps the answer on the row so the table's
     * badge and the rail's facet cannot resolve it differently.
     *
     * Every level it needs is already on the row — the attribute's, the
     * object's from the `contain`, the event's from the same — so this
     * costs no query. Sharing group *names* do cost one, and only when
     * some row resolves to level 4.
     *
     * `SharingGroup::fetchAllAuthorised($user, 'name')` and not a plain
     * find: it returns only the groups this viewer is authorised for, so
     * a group name cannot be read off a row whose event the reader
     * happens to own. A level-4 row whose group does not resolve keeps
     * its badge and loses only the name.
     *
     * @param array $user
     * @param array $rows
     * @return void
     */
    private function attachEffectiveDistribution(array $user, array &$rows)
    {
        if (empty($rows)) {
            return;
        }
        $names = array();
        foreach ($rows as $row) {
            $levels = array(
                (int)$row['Attribute']['distribution'],
                (int)($row['Event']['distribution'] ?? -1),
                empty($row['Object']['id'])
                    ? -1
                    : (int)$row['Object']['distribution'],
            );
            if (in_array(4, $levels, true)) {
                $names = $this->model('SharingGroup')
                    ->fetchAllAuthorised($user, 'name');
                break;
            }
        }
        foreach ($rows as &$row) {
            $row['effective_distribution'] =
                ValueStatsTool::effectiveDistribution($row, $names);
        }
        unset($row);
    }

    /**
     * The cached feeds each row's value hits, as the event view finds
     * them: the same call, so the two agree, and it enforces
     * `perm_view_feed_correlations` itself.
     *
     * @param array $user
     * @param array $rows
     * @return void
     */
    private function attachFeedHits(array $user, array &$rows)
    {
        if (empty($rows)) {
            return;
        }
        $event = array();
        $keys = array_keys($rows);
        $attached = $this->model('Feed')->attachFeedCorrelations(
            array_column($rows, 'Attribute'),
            $user,
            $event
        );
        foreach (array_values($attached) as $i => $attribute) {
            $feeds = array();
            foreach ($attribute['Feed'] ?? array() as $feed) {
                $feeds[] = array(
                    'id' => (int)$feed['id'],
                    'name' => (string)$feed['name'],
                );
            }
            $rows[$keys[$i]]['Feed'] = $feeds;
        }
    }

    /**
     * The pending shadow attributes proposing a change to each row.
     *
     * The id set comes from the row fetch rather than from a second
     * resolution of the value, so permissions were settled before the
     * read ran and the two cannot drift.
     * `ShadowAttribute::buildConditions()` mirrors the attribute
     * visibility model — a proposal against an attribute is visible to
     * whoever may see that attribute — so it is already satisfied by the
     * set this receives and re-applying it would only re-join `events`.
     *
     * Every caller gets `proposal_count`. With `$content`, each row also
     * gets `proposals`: who proposed what, as the field changes accepting
     * it would make. The proposer's email is not read.
     *
     * @param array $rows
     * @param bool $content
     * @return void
     */
    /**
     * `spelled` on each row holding the value in another spelling than
     * the page's.
     */
    private function attachSpellings(array &$rows, $value)
    {
        if (empty($rows)) {
            return;
        }
        $value = (string)$value;
        $dictionary = $this->model('AttributeValue');
        $ids = $dictionary->resolveCi(array($value))[$value] ?? array();
        $isMember = array();
        foreach (empty($ids) ? array() : $dictionary->fetchValues($ids) as $text) {
            $isMember[(string)$text] = true;
        }
        foreach ($rows as &$row) {
            $halves = array(
                (string)($row['Attribute']['value1'] ?? ''),
                (string)($row['Attribute']['value2'] ?? ''),
            );
            if (in_array($value, $halves, true)) {
                continue;
            }
            foreach ($halves as $half) {
                if ($half !== '' && isset($isMember[$half])) {
                    $row['spelled'] = $half;
                    break;
                }
            }
        }
        unset($row);
    }

    private function attachProposalCounts(array &$rows, $content = false)
    {
        if (empty($rows)) {
            return;
        }
        $ids = array();
        foreach ($rows as $row) {
            $ids[] = $row['Attribute']['id'];
        }
        $conditions = array(
            'ShadowAttribute.old_id' => $ids,
            // A soft-deleted proposal is a resolved one, and the badge
            // means "somebody is waiting on you".
            'ShadowAttribute.deleted' => 0,
        );
        $byAttribute = array();
        if ($content) {
            $proposals = $this->model('ShadowAttribute')->find('all', array(
                'fields' => array(
                    'ShadowAttribute.id',
                    'ShadowAttribute.old_id',
                    'ShadowAttribute.event_id',
                    'ShadowAttribute.type',
                    'ShadowAttribute.category',
                    'ShadowAttribute.value',
                    'ShadowAttribute.to_ids',
                    'ShadowAttribute.comment',
                    'ShadowAttribute.first_seen',
                    'ShadowAttribute.last_seen',
                    'ShadowAttribute.proposal_to_delete',
                    'ShadowAttribute.timestamp',
                    'ShadowAttribute.org_id',
                ),
                'conditions' => $conditions,
                'contain' => array('Org' => array('fields' => array('name'))),
                'order' => array('ShadowAttribute.timestamp' => 'DESC'),
            ));
            foreach ($proposals as $proposal) {
                $byAttribute[$proposal['ShadowAttribute']['old_id']][] =
                    $proposal;
            }
        } else {
            $counts = $this->model('ShadowAttribute')->find('all', array(
                'fields' => array(
                    'ShadowAttribute.old_id',
                    'COUNT(*) AS proposal_count',
                ),
                'conditions' => $conditions,
                'group' => array('ShadowAttribute.old_id'),
                'recursive' => -1,
            ));
            foreach ($counts as $count) {
                $byAttribute[$count['ShadowAttribute']['old_id']] =
                    (int)$count[0]['proposal_count'];
            }
        }
        foreach ($rows as &$row) {
            $found = $byAttribute[$row['Attribute']['id']] ?? null;
            if (!$content) {
                $row['proposal_count'] = $found ?? 0;
                continue;
            }
            $row['proposal_count'] = $found === null ? 0 : count($found);
            $row['proposals'] = array();
            foreach ($found ?? array() as $proposal) {
                $row['proposals'][] = self::proposalChange(
                    $row['Attribute'],
                    $proposal
                );
            }
        }
        unset($row);
    }

    /**
     * What accepting one proposal would do to the attribute it targets:
     * the fields `ShadowAttribute::acceptProposal()` copies across, each
     * one that differs as a was/is pair.
     *
     * @param array $attribute The row's `Attribute`
     * @param array $proposal A `ShadowAttribute` row with its `Org`
     * @return array `id`, `event_id`, `org`, `timestamp`, `op`
     *     (delete | replace | refile | none), `change`
     */
    private static function proposalChange(array $attribute, array $proposal)
    {
        $shadow = $proposal['ShadowAttribute'];
        $item = array(
            'id' => (int)$shadow['id'],
            'event_id' => (int)$shadow['event_id'],
            'org' => $proposal['Org']['name'] ?? __('Unknown organisation'),
            'timestamp' => (int)$shadow['timestamp'],
            'op' => 'delete',
            'change' => array(),
        );
        if (!empty($shadow['proposal_to_delete'])) {
            return $item;
        }
        $value = (string)$shadow['value'];
        $seen = function ($iso) {
            return empty($iso) ? '' : date('Y-m-d H:i', strtotime($iso));
        };
        $yesNo = function ($flag) {
            return empty($flag) ? __('no') : __('yes');
        };
        $pairs = array(
            'value' => array((string)$attribute['value'], $value),
            'category' => array(
                (string)$attribute['category'],
                (string)$shadow['category'],
            ),
            'type' => array(
                (string)$attribute['type'],
                (string)$shadow['type'],
            ),
            'to_ids' => array(
                $yesNo($attribute['to_ids']),
                $yesNo($shadow['to_ids']),
            ),
            'comment' => array(
                (string)$attribute['comment'],
                (string)$shadow['comment'],
            ),
            'first_seen' => array(
                $seen($attribute['first_seen'] ?? null),
                $seen($shadow['first_seen'] ?? null),
            ),
            'last_seen' => array(
                $seen($attribute['last_seen'] ?? null),
                $seen($shadow['last_seen'] ?? null),
            ),
        );
        foreach ($pairs as $field => $pair) {
            if ($pair[0] !== $pair[1]) {
                $item['change'][] = array(
                    'field' => $field,
                    'was' => $pair[0],
                    'is' => $pair[1],
                );
            }
        }
        if (empty($item['change'])) {
            $item['op'] = 'none';
        } else {
            $item['op'] = $pairs['value'][0] === $pairs['value'][1]
                ? 'refile' : 'replace';
        }
        return $item;
    }

    /**
     * The taxonomies behind these tags, with their ordinal values.
     *
     * One query for the namespaces actually in play — a handful on any
     * real value — rather than the whole taxonomy table. Predicates and
     * entries both carry `numerical_value`, and both are returned,
     * because a machine tag can put its reading in either component:
     * `tlp:amber` is a predicate and
     * `admiralty-scale:source-reliability="b"` is an entry.
     *
     * Disabled taxonomies are read too. A tag on a value is a fact
     * about the record whatever the instance has since switched off,
     * and dropping the scale for it would leave the card rendering the
     * tag with no way to read it.
     *
     * @param array $tagNames
     * @return array namespace => `predicates`
     */
    private function taxonomyFold(array $tagNames)
    {
        $namespaces = array();
        foreach ($tagNames as $name) {
            $parts = explode(':', (string)$name, 2);
            if (count($parts) === 2) {
                $namespaces[mb_strtolower($parts[0])] = true;
            }
        }
        if (empty($namespaces)) {
            return array();
        }
        /*
         * `LOWER()` on both sides, which is how `getTaxonomyForTag`
         * does it and not a nicety: MISP's columns collate
         * `utf8mb3_bin`, so a value carrying `PAP:RED` against a
         * taxonomy stored as `pap` matches nothing at all and the
         * scale silently does not draw. The whole fold is keyed
         * lowercase for the same reason.
         */
        $rows = $this->model('Taxonomy')->find('all', array(
            'conditions' => array(
                'LOWER(Taxonomy.namespace)' => array_keys($namespaces),
            ),
            'contain' => array('TaxonomyPredicate' => array('TaxonomyEntry')),
            'recursive' => -1,
        ));
        $fold = array();
        foreach ($rows as $row) {
            $predicates = array();
            foreach ($row['TaxonomyPredicate'] as $predicate) {
                $entries = array();
                if (!empty($predicate['TaxonomyEntry'])) {
                    foreach ($predicate['TaxonomyEntry'] as $entry) {
                        $entries[mb_strtolower($entry['value'])] = array(
                            'expanded' => $entry['expanded'] ?? null,
                            'numerical' => self::numerical($entry),
                        );
                    }
                }
                $predicates[mb_strtolower($predicate['value'])] = array(
                    'expanded' => $predicate['expanded'] ?? null,
                    'numerical' => self::numerical($predicate),
                    'entries' => $entries,
                );
            }
            $fold[mb_strtolower($row['Taxonomy']['namespace'])] = array(
                'predicates' => $predicates,
            );
        }
        return $fold;
    }

    /**
     * A taxonomy row's `numerical_value` as a number, or null.
     *
     * Null and zero are different answers here and the column stores
     * both: `admiralty-scale`'s `e` and `g` are a genuine zero, while
     * an unordered taxonomy leaves the column empty. Reading the empty
     * one as zero would sort every unordered tag to the bottom of a
     * scale it has no place on, which is exactly the invented ranking
     * `ValueContextTool::position` refuses to draw.
     *
     * @param array $row A predicate or entry row
     * @return int|null
     */
    private static function numerical(array $row)
    {
        return isset($row['numerical_value'])
            && $row['numerical_value'] !== ''
            && $row['numerical_value'] !== null
            ? (int)$row['numerical_value']
            : null;
    }

    /**
     * Which of these tags MISP considers to be contradicting another.
     *
     * `Taxonomy::getTagConflicts` and not a rule of this page's own,
     * for the reason `ValueContextTool` gives: it reads `exclusive` off
     * the taxonomy and the predicate, and it carries the knowledge that
     * `tlp:white` and `tlp:clear` are one colour under two spellings.
     *
     * Local and global tags are asked separately, which is what
     * `Taxonomy::getTagConflictsForEvent` does: a local tag and a
     * shared one are not in the same conversation, so two readers
     * seeing different halves of the record should not both be told the
     * record contradicts itself.
     *
     * @param array $tags `Value::topTagsFor`
     * @return array Tag name => true
     */
    private function tagConflicts(array $tags)
    {
        $global = array();
        $local = array();
        foreach ($tags as $name => $row) {
            if (!empty($row['tag']['is_galaxy'])) {
                continue;
            }
            if (empty($row['tag']['local'])) {
                $global[] = $name;
            } else {
                $local[] = $name;
            }
        }
        $taxonomy = $this->model('Taxonomy');
        $conflicted = array();
        foreach (array($global, $local) as $set) {
            if (count($set) < 2) {
                continue;
            }
            foreach ($taxonomy->getTagConflicts($set) as $conflict) {
                foreach ($conflict['tags'] as $name) {
                    $conflicted[$name] = true;
                }
            }
        }
        return $conflicted;
    }

    /**
     * The galaxy clusters this viewer may be told about, by tag name.
     *
     * The ACL ruling the tag readers defer to their caller, made
     * here. Sends nothing when no tag is a galaxy tag, because an empty
     * `IN ()` is not a query worth issuing.
     *
     * @param array $user
     * @param array $tags `Value::topTagsFor`
     * @return array Tag name => a `fetchGalaxyClusters` row
     */
    private function galaxyClusters(array $user, array $tags)
    {
        $names = array();
        foreach ($tags as $name => $row) {
            if (!empty($row['tag']['is_galaxy'])) {
                $names[] = $name;
            }
        }
        if (empty($names)) {
            return array();
        }
        $rows = $this->model('GalaxyCluster')->fetchGalaxyClusters(
            $user,
            array('conditions' => array('GalaxyCluster.tag_name' => $names))
        );
        $byTag = array();
        foreach ($rows as $row) {
            if (!empty($row['GalaxyCluster']['tag_name'])) {
                $byTag[$row['GalaxyCluster']['tag_name']] = $row;
            }
        }
        return $byTag;
    }

    /**
     * Whether MISP has marked this value as over-correlating.
     *
     * The same read `relationSettings` makes for the Relationships tab,
     * and the same one the assessment's evidence budget gives up on —
     * so the Lifecycle card's warning, the Relationships tab's note and
     * the engine's refusal to read rows are one fact stated three
     * times rather than three opinions.
     *
     * @param string $value
     * @return bool
     */
    private function overCorrelating($value)
    {
        // An indexed probe for the group; isBlocked() loads every blocked spelling
        $value = (string)$value;
        $ids = $this->model('AttributeValue')
            ->resolveCi(array($value))[$value] ?? array();
        return !empty($ids) && $this->model('OverCorrelatingValue')->hasAny(
            array('OverCorrelatingValue.value_id' => array_map('intval', $ids))
        );
    }

    /*
     * ==================================================================
     * The Relationships tab.
     *
     * Three notions of *related*, three sources, and none of them is
     * the correlation engine — which is this phase's headline finding
     * and is argued in `24-relationships.md` §3. In short: a
     * `default_correlations` row links two attributes carrying the
     * *same* value, so for one value the engine returns other
     * occurrences of it (the Occurrences tab) and its CIDR/ssdeep
     * partners (section two). It never returns a different value, so
     * section one — *values that appear in the same events* — has to be
     * an event join, and the settings card is where the engine's own
     * state is reported instead.
     * ==================================================================
     */

    /**
     * Section one: everything else in the events this value sits in,
     * plus the object siblings above it.
     *
     * Nine queries, none of them per-event or per-occurrence:
     *
     *   1. the value's events, newest first, capped     `Value`
     *   2. how big each of those events is              `MispAttribute`
     *   3. the neighbour rows inside the budget         `Value`
     *   4. their attribute tags (the hasMany of 3)
     *   5. the tag records behind those                 `MispAttribute`
     *   6. the objects this value sits in, capped       `Value`
     *   7. the sibling rows inside those objects        `Value`
     *   8. creator organisation names                   `Organisation`
     *   9. event metadata for the event roll-up         `Event`
     *
     * plus one `SharingGroup::authorizedIds` inside `buildConditions`
     * for a non-site-admin, and one more for sharing-group names when
     * some neighbour resolves to distribution 4.
     *
     * @param array $user
     * @param string $value
     * @param array $options Reserved; `types` reaches `Value`
     * @return array
     */
    public function forRelationCooccurrence(array $user, $value,
        array $options = array()
    ) {
        /*
         * Lifted out before anything else sees `$options`: the
         * narrowing describes rows the fold has already fetched, and
         * the query builders below take their keys from the same
         * array.
         */
        $filters = isset($options['filters'])
            ? (array)$options['filters']
            : array();
        unset($options['filters']);
        $context = $this->cooccurrenceContext($user, $value, $options,
            $filters);
        return array(
            'value' => $value,
            /*
             * Beside the fold rather than inside it. The fold is
             * cached and shared between everybody who may read the
             * same rows; a reader's own priorities are not a property
             * of the neighbourhood, and folding them in would make one
             * analyst's cache entry another's wrong order.
             *
             * So the panel carries the plan and the label table orders
             * its rows on the way to the page — before its own cut, so
             * the profile decides which labels are listed rather than
             * how the listed ones read.
             */
            'label_plan' => ValueLabelPriority::planFor(
                array_key_exists('profile', $options)
                    ? $options['profile']
                    : ClassRegistry::init('AnalystProfile')
                        ->resolveFor($user)
            ),
            'relationships' => array(
                'summary' => $this->relationSummary(
                    $user,
                    $value,
                    $options,
                    array('cooccurrence' => $context['co'])
                ),
                'cooccurrence' => $context['co'],
                'settings' => $this->relationSettings($user, $value),
            ),
        );
    }

    /**
     * Section two: values that are close to this one without being it.
     *
     * Two queries at most, and neither of them reads the correlation
     * table — there is nothing in it to read. `Correlation` records no
     * provenance, so a CIDR containment row is indistinguishable from
     * an exact match once written; both engines are therefore
     * re-derived here from the same inputs the engine itself uses.
     *
     * @param array $user
     * @param string $value
     * @param array $options Reserved; `types` reaches `Value`
     * @return array
     */
    public function forRelationNearMatch(array $user, $value,
        array $options = array()
    ) {
        $types = $this->model('Value')->typesFor($user, $value, $options);
        return array(
            'value' => $value,
            'types' => $types,
            'relationships' => array(
                'near' => $this->nearMatches($user, $value, $types),
            ),
        );
    }

    /**
     * Section three: relationships somebody wrote down on purpose.
     *
     * @param array $user
     * @param string $value
     * @param array $options Reserved; `types` reaches `Value`
     * @return array
     */
    public function forRelationAsserted(array $user, $value,
        array $options = array()
    ) {
        return array(
            'value' => $value,
            'relationships' => array(
                'asserted' => $this->assertedClaims($user, $value,
                    $options),
            ),
        );
    }

    /**
     * Section five: the object joins that carry a pair of dates.
     *
     * Folded with the co-occurrence scan rather than queried again, so
     * this endpoint's cost is the scan's — usually a Redis read — and
     * never a second object join. `03-relationships.md` §23.5.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forRelationDated(array $user, $value,
        array $options = array()
    ) {
        unset($options['filters']);
        $context = $this->cooccurrenceContext($user, $value, $options);
        return array(
            'value' => $value,
            'relationships' => array(
                'dated' => $context['co']['dated'],
                'siblings' => array(
                    'in_objects' => $context['co']['siblings']['in_objects'],
                    'objects' => $context['co']['siblings']['objects'],
                    'cap' => $context['co']['siblings']['cap'],
                ),
                'suppressed' => !empty($context['co']['suppressed']),
                'read_at' => isset($context['co']['scan']['read_at'])
                    ? (int)$context['co']['scan']['read_at']
                    : time(),
                'ttl' => self::RELATION_SCAN_TTL,
            ),
        );
    }

    /**
     * Section six: MISP's own typed relation between two objects.
     *
     * Its own read and not the scan's, deliberately: three indexed
     * lookups and a resolve, against a scan that can read 20,000 rows.
     * A reader whose co-occurrence panel is still working should not be
     * waiting on it to learn that this address is `hosted-by` something.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forRelationReferences(array $user, $value,
        array $options = array()
    ) {
        unset($options['filters']);
        return array(
            'value' => $value,
            'relationships' => array(
                'references' => $this->referenceSection($user, $value,
                    $options),
            ),
        );
    }

    /**
     * The rail's second card: what MISP is configured to count, and
     * where this value stands against it.
     *
     * The one panel on the tab that still says something true about a
     * value with nothing at all — and, now that section one is not
     * engine output, the only panel that reads the correlation engine's
     * state at all.
     *
     * **It reads no fold, and that is the point.** This card used to
     * pull the whole digest for one thing: the eight counts in the
     * breakdown at its foot. So the rail's live statement about the
     * correlation engine — *this value is past the limit*, *this value
     * is excluded* — waited on a 20,000-row neighbourhood scan and the
     * four sections built on it, which on `443` was 2.5 s to render
     * three alerts and a settings list that cost 20 ms to read.
     *
     * The counts now arrive the way the contents strip's already do:
     * every panel stamps its own headline number on itself as it
     * lands, and `initRelationSummary` copies it into both places. The
     * strip proved the pattern and its docblock states the reason — a
     * total computed here would run the scan again to print an integer
     * the panel that owns it is about to print anyway.
     *
     * That also settles the age disclosure. The subtitle used to date
     * the counts off the digest; each count now carries whatever age
     * its own panel discloses, which is the honest figure since the
     * panels no longer land together.
     *
     * @param array $user
     * @param string $value
     * @param array $options Unused; the panel reads no fold
     * @return array
     */
    public function forRelationSettings(array $user, $value,
        array $options = array()
    ) {
        return array(
            'value' => $value,
            'relationships' => array(
                // config and engine state, and now the whole panel
                'settings' => $this->relationSettings($user, $value),
            ),
        );
    }

    /**
     * The rail's third card: which named threats this value sits next
     * to.
     *
     * The one thing on the tab that answers *what does this mean*
     * rather than *what is related*. Everything else here lists edges;
     * this names the campaigns, actors, malware and tooling reachable
     * through the value, which is the read every peer platform leads
     * with and the one this tab had no answer for.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forRelationThreats(array $user, $value,
        array $options = array()
    ) {
        $digest = $this->relationDigest($user, $value, $options);
        return array(
            'value' => $value,
            'relationships' => array(
                'threats' => $digest['threats'],
                'tactics' => $digest['tactics'],
                'read_at' => $digest['read_at'],
            ),
        );
    }

    /**
     * The Overview card: how many feeds and sync servers hold this value,
     * counting only the ones this reader may be told about.
     *
     * @param array $user
     * @param string $value
     * @param array $options Reserved
     * @return array
     */
    public function forExternal(array $user, $value,
        array $options = array()
    ) {
        return array(
            'value' => $value,
            'external' => $this->externalPresence($user, $value),
        );
    }

    /**
     * Section four: the remote events a feed or sync server holds this
     * value in.
     *
     * The same method the Overview card counts. Two panels filtering
     * independently is how the looser one becomes a disclosure and the
     * stricter one's accuracy becomes decorative
     * (`tabs/03-relationships.md` §20.1).
     *
     * @param array $user
     * @param string $value
     * @param array $options Reserved
     * @return array
     */
    public function forRelationExternal(array $user, $value,
        array $options = array()
    ) {
        return array(
            'value' => $value,
            'external' => $this->externalPresence($user, $value),
        );
    }

    /**
     * Which cached feeds and sync servers hold this value, filtered to
     * what this reader may see.
     *
     * **The visibility rule is per source, not per reader**, and it is
     * chosen so the page is never looser than any surface MISP already
     * ships:
     *
     *   lookup_visible = 1   every role — `/feeds/searchCaches` is
     *                        reachable by everyone and returns these by
     *                        name, so gating them here would hide what
     *                        the same reader gets one click away.
     *   lookup_visible = 0   site admin. The column defaults to 0, so on
     *                        a stock instance this is every feed.
     *   sync servers         site admin only. One notch stricter than
     *                        the event view, which admits the host org,
     *                        because `servers/previewEvent` is site
     *                        admin only and the link is the row's whole
     *                        value.
     *
     * **The feed rule read `perm_view_feed_correlations` until B3, and
     * that was a disclosure.** All three surfaces MISP ships withhold a
     * non-lookup-visible feed's *identity* from everyone but a site
     * admin: `Feed::getCachedFeedsOrServers` conditions on
     * `lookup_visible = 1` for `!perm_site_admin`, and `/feeds/index`
     * and `/feeds/searchCaches` add a host-org branch that cannot fire
     * — they compare a session `org_id` (string `'1'`) against
     * `MISP.host_org_id` (int `1`) with `!==`, so every non-site-admin
     * takes the limited path. `perm_view_feed_correlations` gates
     * *whether feed correlations are shown at all*, never *which feeds
     * may be named*, and `AppModel`'s own migration sets it to 1 for
     * every existing role — so on any upgraded instance the old rule
     * handed each of them the name, URL and remote events of feeds
     * `/feeds/index` refuses to list for them. Measured on the dev
     * instance 2026-09-01: a non-host-org Org Admin carrying the perm
     * was handed `CIRCL OSINT Feed`, its URL and two event links for a
     * value, while `searchCaches` returned that reader one feed and
     * `/feeds/index` did not list it at all.
     *
     * The host-org branch is deliberately not reproduced here. Copying
     * it would mean copying a comparison that does not do what it reads
     * as doing, and fixing it belongs to those surfaces, not to a page
     * that only reads them.
     *
     * `Feed::searchCaches` applies no role check at all, so nothing here
     * may render its output directly. It is called for the whole
     * instance and its hits are then intersected with the ids this
     * reader is allowed to be told about.
     *
     * **`restricted` is keyed on the role and never on the value.** It
     * is true whenever the instance holds cached sources of that kind
     * that this reader's role cannot reach, whether or not this
     * particular value hits any of them — which is what lets it exist
     * at all under `live/00-contract.md` §14.6. A notice that appeared
     * only when something was hidden would be the same disclosure at
     * one bit.
     *
     * @param array $user
     * @param string $value
     * @return array
     */
    /**
     * Which cached sources exist, and which of them this reader may be
     * told about — the config half of §20.2's rule, with no value in it.
     *
     * Split out from `externalPresence()` because the rail's "What is
     * counted" card states these rules for a value with nothing to
     * count, so it needs them without paying for a cache lookup.
     * Everything it returns is a property of the instance and the
     * reader's role, never of a value.
     *
     * @param array $user
     * @return array
     */
    private function externalVisibility(array $user)
    {
        $isSiteAdmin = !empty($user['Role']['perm_site_admin']);

        $cachedFeeds = $this->model('Feed')->find('all', array(
            'conditions' => array('Feed.caching_enabled' => 1),
            'recursive' => -1,
            'fields' => array('Feed.id', 'Feed.lookup_visible'),
        ));
        $cachedServerCount = $this->model('Server')->find('count', array(
            'conditions' => array('Server.caching_enabled' => 1),
            'recursive' => -1,
        ));

        $visibleFeedIds = array();
        $withheldFeeds = 0;
        foreach ($cachedFeeds as $feed) {
            if ($isSiteAdmin || !empty($feed['Feed']['lookup_visible'])) {
                $visibleFeedIds[(string)$feed['Feed']['id']] = true;
            } else {
                $withheldFeeds++;
            }
        }

        return array(
            'site_admin' => $isSiteAdmin,
            'visible_feed_ids' => $visibleFeedIds,
            'cached' => array(
                'feeds' => count($cachedFeeds),
                'servers' => $cachedServerCount,
            ),
            'visible' => array(
                'feeds' => count($visibleFeedIds),
                'servers' => $isSiteAdmin ? $cachedServerCount : 0,
            ),
            // role and instance config only — never a value
            'restricted' => array(
                'feeds' => $withheldFeeds > 0,
                'servers' => !$isSiteAdmin && $cachedServerCount > 0,
            ),
            'event_cap' => self::EXTERNAL_EVENT_CAP,
        );
    }

    private function externalPresence(array $user, $value)
    {
        $feedModel = $this->model('Feed');
        $visibility = $this->externalVisibility($user);
        $visibleFeedIds = $visibility['visible_feed_ids'];
        $isSiteAdmin = $visibility['site_admin'];

        $presence = array(
            'sources' => array(),
            'counts' => array('feeds' => 0, 'servers' => 0),
            'events' => 0,
            /*
             * The same event tally as `events`, kept apart by kind.
             *
             * The Overview card drew two lines — *N hits in feeds*, *N
             * hits on sync servers* — and one number under both of
             * them, so *12 remote events name this value* belonged to
             * neither line and a reader had to guess whether the twelve
             * were the server's, the feeds', or a sum. They are a sum;
             * split here, each line states its own and there is nothing
             * left to reconcile.
             */
            'event_counts' => array('feeds' => 0, 'servers' => 0),
            'restricted' => $visibility['restricted'],
            'cached' => $visibility['cached'],
            'visible' => $visibility['visible'],
            'event_cap' => self::EXTERNAL_EVENT_CAP,
        );

        if (empty($visibleFeedIds) && !$isSiteAdmin) {
            return $presence;
        }
        if (empty($visibility['cached']['feeds'])
            && empty($visibility['cached']['servers'])
        ) {
            return $presence;
        }

        foreach ($feedModel->searchCaches($value, false) as $hit) {
            $source = $hit['Feed'];
            $isServer = ($source['type'] === 'MISP Server');
            if ($isServer) {
                if (!$isSiteAdmin) {
                    continue;
                }
            } elseif (!isset($visibleFeedIds[(string)$source['id']])) {
                continue;
            }

            $events = array();
            if (!empty($source['direct_urls']) && !empty($source['uuid'])) {
                foreach ($source['direct_urls'] as $link) {
                    $events[] = array(
                        'name' => $link['name'],
                        'url' => $link['url'],
                    );
                }
            }
            $presence['sources'][] = array(
                'id' => $source['id'],
                'name' => $source['name'],
                'url' => isset($source['url']) ? $source['url'] : null,
                // The only column MISP has that hints at what a feed
                // mirrors, which is what `feeds.mirrored` folds by.
                'provider' => isset($source['provider'])
                    ? $source['provider']
                    : null,
                'kind' => $source['type'],
                'scope' => $isServer ? 'server' : 'feed',
                'events' => array_slice($events, 0, self::EXTERNAL_EVENT_CAP),
                'events_total' => count($events),
                // A MISP feed's events, by which `feeds.reporters`
                // finds the local copies' creator.
                'event_uuids' => !empty($source['uuid'])
                    && is_array($source['uuid'])
                    ? $source['uuid']
                    : array(),
            );
            $scope = $isServer ? 'servers' : 'feeds';
            $presence['events'] += count($events);
            $presence['event_counts'][$scope] += count($events);
            $presence['counts'][$scope]++;
        }

        return $presence;
    }

    /**
     * The neighbourhood, folded — at most once per request.
     *
     * **The scope is chosen before anything is read**, which is the
     * whole design of this section. Events come newest-first; an event
     * larger than `RELATION_EVENT_SIZE_CAP` is dropped outright,
     * because co-occurrence inside an event that size is a statement
     * about the event and not about this value; then events are taken
     * until `RELATION_SCAN_BUDGET` rows would be exceeded. Whatever
     * survives is read *completely*, so every count the panel prints is
     * exact over a scope the panel also prints.
     *
     * Reading the events first and choosing second is what makes this
     * affordable: the size query is index-only and cost 61 ms over
     * `8.8.8.8`'s 19 events, against 4.8 seconds for the neighbour scan
     * it then avoided.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array `co` and the scan's own numbers
     */
    private function cooccurrenceContext(array $user, $value,
        array $options = array(), array $filters = array()
    ) {
        /*
         * Keyed on the narrowing as well, so the once-per-request memo
         * cannot hand a filtered fold to a caller that asked for the
         * whole neighbourhood.
         */
        if ($this->cooccurrence !== null
            && $this->cooccurrenceFilters === $filters
            && $this->memoValue === $value
        ) {
            return $this->cooccurrence;
        }
        $this->forget($value);
        $this->cooccurrenceFilters = $filters;
        $fresh = !empty($options['fresh']);
        unset($options['fresh']);
        $scan = $this->relationScan($user, $value, $options, $fresh);

        $co = ValueRelationTool::cooccurrence($scan['rows'], array(
            'orgs' => $scan['orgs'],
            'events' => $scan['event_meta'],
            'sharing_groups' => $scan['sharing_groups'],
            'our_objects' => $scan['our_objects'],
            'filters' => $filters,
            'row_cap' => self::RELATION_ROW_CAP,
            'page_size' => self::RELATION_PAGE_SIZE,
            /*
             * Read over the whole scan, so the facet the fold builds
             * from it counts the neighbourhood and not the page — the
             * same promise every other facet in that bar makes.
             */
            'warninglists' => isset($scan['warninglists'])
                ? $scan['warninglists']
                : array(),
            'warninglists_checked' => isset($scan['warninglists_checked'])
                ? $scan['warninglists_checked']
                : 0,
            /*
             * Also read over the whole scan, and for a stronger reason
             * than the facet's: this is what the **Most specific** rank
             * divides by, and the rank decides which neighbours reach
             * the cut. A denominator covering only the carried hundred
             * would rank a page instead of a fold.
             */
            'prevalence' => isset($scan['prevalence'])
                ? $scan['prevalence']
                : array(),
            /*
             * §10.2's label side. `own_tags` and the events' own tags
             * are what a label neighbour is folded from; `clusters` is
             * the ACL ruling on the galaxy ones, without which a tag
             * name is not a cluster this viewer may be shown.
             *
             * All three are lookups, which is why they arrive as
             * context: `ValueRelationTool` issues no queries.
             */
            'own_tags' => isset($scan['own_tags'])
                ? $scan['own_tags']
                : array(),
            'clusters' => isset($scan['clusters'])
                ? $scan['clusters']
                : array('by_tag' => array(), 'by_uuid' => array()),
        ));
        $co['siblings'] = $scan['siblings'];
        $co['dated'] = $scan['dated'];
        $co['scan'] = array(
            'events_read' => count($scan['picked']),
            'events_seen' => $scan['events_seen'],
            'events_oversized' => $scan['events_oversized'],
            'events_unread' => $scan['events_unread'],
            'event_cap' => self::RELATION_EVENT_CAP,
            'size_cap' => self::RELATION_EVENT_SIZE_CAP,
            'budget' => self::RELATION_SCAN_BUDGET,
            'rows_read' => count($scan['rows']),
            'row_cap' => self::RELATION_ROW_CAP,
            /*
             * When the rows under this panel were read. Zero seconds on
             * a scan that just ran, up to `RELATION_SCAN_TTL` on one
             * served from Redis — and the panel prints it, because a
             * cached read that does not say how old it is is the reason
             * a cache this long would otherwise be a trap.
             */
            'read_at' => $scan['read_at'],
            'ttl' => self::RELATION_SCAN_TTL,
        );
        /*
         * Not "the engine stored nothing" — the opposite claim. Every
         * event this value appears in is too large to read for
         * co-occurrence, so there is a neighbourhood and it is not
         * being shown, which is what `.vp-suppressed` says and what an
         * empty state would get exactly backwards.
         */
        $co['suppressed'] = empty($scan['picked'])
            && $scan['events_oversized'] > 0;

        $this->cooccurrence = array('co' => $co);
        return $this->cooccurrence;
    }

    /**
     * Everything the fold reads, from Redis where it is still warm.
     *
     * The narrowing re-requests the panel, so the same scan would
     * otherwise run again to fold the same rows against a different
     * filter. Cached, the first request pays for it and every narrowing
     * after it is a fold over rows already in hand.
     *
     * Keyed on the viewer, because every row in here went through
     * `buildConditions($user)` and two readers of one value do not see
     * the same neighbourhood. Redis being unavailable is not an error:
     * the scan runs, and the page is merely as slow as it was before.
     *
     * `$fresh` is the reader pressing the panel's own refresh: the
     * entry is skipped on the way in and rewritten on the way out, so
     * one press lands on new rows rather than on an empty cache.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @param bool $fresh
     * @return array
     */
    /**
     * The threats card's rows, held as one small entry so the card does
     * not inflate the whole scan out of Redis on every request.
     *
     * Held on the same terms as the scan: the same TTL, and the same
     * per-viewer key because every row went through
     * `buildConditions($user)`. `read_at` is the scan's stamp, the
     * oldest thing in here.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array `threats`, `tactics`, `read_at`
     */
    private function relationDigest(array $user, $value,
        array $options = array()
    ) {
        $fresh = !empty($options['fresh']);
        $keyOptions = $options;
        unset($keyOptions['fresh']);
        /*
         * The threats panel is ordered and filtered by the reader's
         * profile, so a different profile or a new revision of it is a
         * different digest.
         */
        $profile = ClassRegistry::init('AnalystProfile')->resolveFor($user);
        $profileKey = empty($profile)
            ? '-'
            : (isset($profile['uuid']) ? $profile['uuid'] : '')
                . '@' . (isset($profile['revision'])
                    ? (int)$profile['revision']
                    : 0);
        $key = 'misp:value_intelligence:relation_digest:v'
            . self::CACHE_SHAPE . ':' . self::cacheScope($user)
            . ':' . hash('sha256', $value . '|' . $profileKey . '|'
                . json_encode($keyOptions));

        return $this->cachedFold($key, $fresh,
            function () use ($user, $value, $options) {
                return $this->readRelationDigest($user, $value, $options);
            });
    }

    /**
     * The digest itself, once the cache has decided it must be read.
     *
     * Split out so `cachedFold` can hold the single-flight lock over
     * it.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    private function readRelationDigest(array $user, $value,
        array $options
    ) {
        $context = $this->cooccurrenceContext($user, $value, $options);
        $asserted = $this->assertedClaims($user, $value, $options);

        $digest = array(
            /*
             * **Read off the scan now, and the property that made that
             * safe is the scan's, not this card's.** The scan skips an
             * event too large to fold for co-occurrence, but an event's
             * tags cost the same whatever its size — so `readRelationScan`
             * reads the label side over every event the value is in.
             * Tying the named threats to the attribute budget would
             * drop them for an unrelated reason, and this card still
             * answers on values whose neighbourhood table is suppressed
             * entirely. §10.2.
             */
            /*
             * `$asserted['claims']`, not `$asserted` — that array is a
             * section, and its other keys are counts. Passing the whole
             * thing made the fold iterate `total` and `orgs` as though
             * they were claims, which skips every one of them without
             * erroring: `$claim['target']` on an integer is null, and
             * null is not `GalaxyCluster`.
             */
            'threats' => $this->neighbourhoodThreats(
                $user,
                $context['co'],
                isset($asserted['claims'])
                    ? $asserted['claims']
                    : array()
            ),
            /*
             * The same card's second group, and a second reader of the
             * same label rows rather than a second read of anything:
             * the `attack-pattern` clusters the card above filters out
             * are the ones this folds. The chain it orders them on is
             * the one lookup, over a 130-row table, held here with the
             * rest of the digest.
             */
            'tactics' => $this->neighbourhoodTactics(
                $context['co'],
                $this->tacticChain()
            ),
            'read_at' => isset($context['co']['scan']['read_at'])
                ? (int)$context['co']['scan']['read_at']
                : time(),
        );

        return $digest;
    }

    /**
     * The named threats reachable through this value, as a slice of the
     * co-occurrence fold.
     *
     * **A named threat is a galaxy cluster and nothing else**, and
     * `GalaxyCategory` holds both that rule and the evidence for it.
     * The short version: freetext tags cannot carry the claim — the two
     * most-used on this instance are the word `malware` and ` C2`, and
     * one malware family appears under seven spellings — and no
     * installed taxonomy names an individual threat, they classify one.
     *
     * **This used to be six queries and is now one.** §10.2's change of
     * definition is what made that possible: a galaxy cluster is a
     * neighbour in its own right now, so the events, their metadata,
     * their tags, the tags on this value's own occurrences and the
     * `fetchGalaxyClusters` ruling over all of them are read once by
     * `readRelationScan` and folded once by `ValueRelationTool`. This
     * card reads that fold, filters it to `named-threat`, and ranks
     * what is left for a 340px rail.
     *
     * The one query left is the one the fold cannot answer: a claim
     * points at a cluster by UUID and may name one that appears on no
     * event here, so `claimClusters` still resolves those under the
     * viewer's ACL. It sends nothing when no claim names a cluster.
     *
     * **The scope property that had to survive.** The card answers on
     * values whose neighbourhood table is suppressed entirely, because
     * an event's tags cost the same whatever its size while its
     * attributes do not. That is why `readRelationScan` reads the label
     * side over every event the value is in rather than over the events
     * the attribute budget afforded — the note is there too, and the
     * two have to stay in step.
     *
     * **What `orgs` counts, and what it cannot.** Neither `event_tags`
     * nor `attribute_tags` records who applied a tag — there is no org
     * and no user on either table — so this counts the *creator
     * organisations of the events carrying the cluster*, and the card
     * says so in words. A claim is the one source that does record an
     * author, and contributes that org instead.
     *
     * **Four ways in, one word out.** A cluster can arrive on the
     * value's own occurrence, on a neighbouring attribute, on an event
     * the value appears in, or as the far end of an analyst's claim
     * about it. Where more than one applies the most specific wins,
     * which is the order in `threatRank` — and it is a decision rather
     * than a derivation: a claim outranks a tag on the value because it
     * carries an author and a relationship type, so it is the more
     * informative thing to print. The first three are the fold's own
     * `attachment`, decided in `ValueRelationTool::$attachments` so
     * that the word on this row and the word on the table's row are
     * the same word from the same place.
     *
     * **A fifth is coming.** Objects cannot be tagged yet: the join
     * tables are `attribute_tags`, `event_tags` and
     * `event_report_tags`, there is no `object_tags`, and `MispObject`
     * reaches a tag only through its attributes. When `ObjectTag`
     * lands, a cluster on the object a value sits in belongs between
     * `value` and `neighbour` in both rank tables — grep either name to
     * find them.
     *
     * @param array $user
     * @param array $co The co-occurrence fold, `$context['co']`
     * @param array $claims `assertedClaims()['claims']` — the list,
     *     not the section that wraps it
     * @return array rows, total, cap, events_read
     */
    private function neighbourhoodThreats(array $user, array $co,
        array $claims
    ) {
        $found = array(
            'rows' => array(),
            'total' => 0,
            'cap' => self::THREAT_ROW_CAP,
            'events_read' => isset($co['scan']['events_seen'])
                ? (int)$co['scan']['events_seen']
                : 0,
            'event_cap' => self::RELATION_EVENT_CAP,
        );

        /*
         * Event titles for the figures hover, off the fold's own event
         * roll-up rather than a second `eventMetadata` read. Every
         * event carrying a label produces a group, and the roll-up is
         * built from the groups after the labels are folded in — so an
         * event on a row here is an event with a row there.
         */
        $eventTitles = array();
        if (isset($co['rollups']['event']['rows'])) {
            foreach ($co['rollups']['event']['rows'] as $eventRow) {
                $eventTitles[(int)$eventRow['event']['id']] = array(
                    'id' => (int)$eventRow['event']['id'],
                    'info' => $eventRow['event']['info'],
                    'date' => $eventRow['event']['date'],
                );
            }
        }

        /*
         * The panel names what this reader counts as attribution: the
         * profile's list where it declares one, the named-threat
         * galaxies where it does not.
         */
        $profile = ClassRegistry::init('AnalystProfile')->resolveFor($user);
        $attribution = ValueLabelPriority::attribution($profile);

        $rows = array();
        /*
         * The label section's rows, which are held uncapped for exactly
         * this reader — the table beside them renders the first `cap`,
         * and a cluster reaching this value through one event sits
         * nowhere near the top of a list ranked by shared events.
         */
        $labels = isset($co['labels']['rows'])
            ? $co['labels']['rows']
            : array();
        foreach ($labels as $label) {
            if ($label['kind'] !== ValueRelationTool::KIND_CLUSTER
                || empty($label['cluster'])
            ) {
                continue;
            }
            $this->addThreat(
                $rows,
                $label['cluster'],
                $label['attachment'],
                $label,
                $eventTitles,
                $attribution
            );
        }

        /*
         * The claims, which are not in the fold: a `Relationship` row
         * is not a label on an event, and the asserted section is what
         * reads them. A claim naming a cluster the fold already holds
         * lands on that row; one naming a cluster nothing here is
         * tagged with brings its own.
         */
        $clusters = $this->claimClusters($user, $claims);
        foreach ($claims as $claim) {
            if ($claim['target']['kind'] !== 'GalaxyCluster') {
                continue;
            }
            $uuid = $claim['target']['uuid'];
            if (!isset($clusters['by_uuid'][$uuid])) {
                continue;
            }
            $this->addThreat(
                $rows,
                $clusters['by_uuid'][$uuid],
                'claim',
                null,
                $eventTitles,
                $attribution,
                $claim
            );
        }

        /*
         * Both sets were accumulated keyed, so a cluster reached
         * through three sources on one event counts that event once.
         * The counts are what the row prints and the lists are what
         * the hover names, which is why both survive.
         */
        foreach ($rows as $id => $row) {
            $rows[$id]['events'] = count($row['event_list']);
            $rows[$id]['orgs'] = count($row['org_names']);
            $rows[$id]['event_list'] = array_values($row['event_list']);
            $rows[$id]['org_names'] = array_values($row['org_names']);
            sort($rows[$id]['org_names']);
        }
        $rows = array_values($rows);
        /*
         * Organisations, then events, then the name — and attachment
         * is not in the sort on purpose. The word on the row already
         * says how a cluster got there; ranking by it as well would
         * bury a threat four organisations reported under one somebody
         * tagged on the value once.
         */
        usort($rows, function ($a, $b) {
            if ($a['orgs'] !== $b['orgs']) {
                return $b['orgs'] - $a['orgs'];
            }
            if ($a['events'] !== $b['events']) {
                return $b['events'] - $a['events'];
            }
            return strcasecmp($a['name'], $b['name']);
        });
        /*
         * And then the reader's own order over that one. The panel
         * opens with eight, so eight of a neighbourhood's sixty-three
         * are chosen — by count until now, which is how a threat actor
         * ends up below six pieces of tooling. Ordered last, so what
         * the profile does not rank keeps the count order it just got.
         */
        $rows = ValueLabelPriority::order(
            $rows,
            $profile,
            ValueLabelPriority::GALAXIES
        );
        $found['rows'] = $rows;
        $found['total'] = count($rows);
        return $found;
    }

    /**
     * One cluster onto the card, or nothing if it names no threat.
     *
     * **This is where §10.2's filter is applied**, and it stays here
     * rather than moving into the fold: the table carries every
     * cluster it found, and *named threat* is the rail card's own
     * question about them. A `TECHNIQUE` cluster is a perfectly good
     * neighbour and a bad answer to *who is this*.
     *
     * @param array $rows Accumulator, keyed by cluster id
     * @param array $cluster A `fetchGalaxyClusters` row
     * @param string $attachment `event`, `neighbour`, `value` or
     *     `claim`
     * @param array|null $label The fold's row for this cluster, whose
     *     events and organisations are the card's figures. Null for a
     *     cluster a claim brought in, which the fold never saw.
     * @param array $eventTitles Event id => id, info, date
     * @param array|null $attribution Galaxy types the profile counts
     *     as attribution, lowercased; null for the named-threat set
     * @param array|null $claim The claim, where one is what brought
     *     the cluster in. Kept so the card's own badge can say who
     *     asserted it, how, and when — three words on the row is the
     *     right size for the rail, and the rest belongs on hover.
     * @return void
     */
    private function addThreat(array &$rows, array $cluster,
        $attachment, $label, array $eventTitles, array $attribution = null,
        array $claim = null
    ) {
        $row = $cluster['GalaxyCluster'];
        $counted = $attribution === null
            ? GalaxyCategory::isNamedThreat($row['type'])
            : in_array(
                mb_strtolower((string)$row['type']),
                $attribution,
                true
            );
        if (!$counted) {
            return;
        }
        $id = (int)$row['id'];
        if (!isset($rows[$id])) {
            $rows[$id] = array(
                'id' => $id,
                'name' => $row['value'],
                'galaxy' => empty($row['Galaxy']['name'])
                    ? $row['type']
                    : $row['Galaxy']['name'],
                /*
                 * What a profile's priority lists name this galaxy by,
                 * so the eight this panel opens with are the eight
                 * this reader asked for rather than the eight the
                 * neighbourhood happened to report most widely.
                 */
                'key' => $row['type'],
                'sub_category' => GalaxyCategory::subCategoryOf($row['type']),
                'attachment' => $attachment,
                /*
                 * Names, not ids, and that is the second query this
                 * card stopped issuing: the fold resolved the
                 * organisations behind its rows already, over the same
                 * ids and under the same `Organisation` read the value
                 * rows needed anyway.
                 */
                'org_names' => array(),
                'event_list' => array(),
                'claims' => array(),
                /*
                 * The same display shape the asserted section builds
                 * for a claim's far end, so the card renders the very
                 * same hover element rather than a second one that
                 * would drift from it. Free: the GalaxyCluster branch
                 * of `claimTarget` reads only the row already fetched,
                 * and `claimTargetOrg` returns null rather than
                 * insisting on an organisation lookup — so the card
                 * omits that row instead of costing a query for it.
                 */
                'target' => $this->claimTarget(
                    'GalaxyCluster',
                    $row['uuid'],
                    $cluster,
                    array(
                        'orgs' => array(),
                        'tags' => array(),
                        'galaxy_by_event' => array(),
                        'clusters' => array(),
                    )
                ),
            );
        }
        if ($claim !== null) {
            $rows[$id]['claims'][] = array(
                'type' => $claim['relationship_type'],
                'anchor' => isset($claim['anchor'])
                    ? $claim['anchor']
                    : null,
                'org' => $claim['org'],
                'date' => $claim['date'],
            );
        }
        if (self::threatRank($attachment)
            > self::threatRank($rows[$id]['attachment'])
        ) {
            $rows[$id]['attachment'] = $attachment;
        }
        if ($label === null) {
            return;
        }
        foreach ($label['orgs'] as $name) {
            $rows[$id]['org_names'][$name] = $name;
        }
        foreach ($label['events'] as $eventId) {
            $eventId = (int)$eventId;
            $rows[$id]['event_list'][$eventId] =
                isset($eventTitles[$eventId])
                    ? $eventTitles[$eventId]
                    : array(
                        'id' => $eventId,
                        'info' => '',
                        'date' => '',
                    );
        }
    }

    /**
     * How specific a way of reaching the value is.
     *
     * The fold's own `$attachments` plus `claim` on top, because a
     * claim is not a label on an event and reaches this card by
     * another road — see `neighbourhoodThreats`. `object` belongs
     * between `value` and `neighbour` once objects can be tagged, in
     * both tables.
     *
     * @param string $attachment
     * @return int
     */
    private static function threatRank($attachment)
    {
        $ranks = array(
            'claim' => 4,
            'value' => 3,
            'neighbour' => 2,
            'event' => 1,
        );
        return isset($ranks[$attachment]) ? $ranks[$attachment] : 0;
    }

    /**
     * Where in the intrusion this value's neighbourhood sits: the
     * technique clusters around it, collapsed to their tactics.
     *
     * A second group on the named-threat card, answering *what stage*
     * where that one answers *who* — which is why it is a group and not
     * more rows in the same list. It is a fold over the labels the
     * co-occurrence scan already holds: the `attack-pattern` clusters
     * that card filters out are sitting in `$co['labels']['rows']` with
     * their events and organisations counted, so this issues no query
     * and reads nothing the tab has not already read.
     *
     * **A technique counts in every tactic it belongs to**, because
     * ATT&CK genuinely files several that way — *Registry Run Keys /
     * Startup Folder* is persistence and privilege escalation both, and
     * picking one of the two would be this page inventing a fact. The
     * consequence is that the counts sum to more than the techniques
     * they were folded from, so the group states the technique total
     * beside them rather than leaving a reader to add the chips up and
     * get a bigger number than the neighbourhood holds.
     *
     * **A technique with no `kill_chain` element cannot be placed**, and
     * is counted rather than dropped: 7 of the clusters tagged on events
     * here are in that state — 2 attack patterns and 5 ICS techniques
     * whose galaxy ships no kill chain at all. The group says how many
     * it could not place, on the same rule every cap on this tab
     * follows.
     *
     * @param array $co The co-occurrence fold, `$context['co']`
     * @param array $chain Tactic token => position, `tacticChain()`
     * @return array rows, total, techniques, placed, unplaced, multi
     */
    private function neighbourhoodTactics(array $co, array $chain)
    {
        $found = array(
            'rows' => array(),
            'total' => 0,
            'techniques' => 0,
            'placed' => 0,
            'unplaced' => 0,
            'multi' => 0,
        );
        $labels = isset($co['labels']['rows'])
            ? $co['labels']['rows']
            : array();

        $byTactic = array();
        foreach ($labels as $label) {
            if ($label['kind'] !== ValueRelationTool::KIND_CLUSTER
                || empty($label['cluster'])
            ) {
                continue;
            }
            $record = $label['cluster']['GalaxyCluster'];
            if (!GalaxyCategory::isAttackPattern($record['type'])) {
                continue;
            }
            $found['techniques']++;
            $tactics = empty($record['tactics'])
                ? array()
                : $record['tactics'];
            if (empty($tactics)) {
                $found['unplaced']++;
                continue;
            }
            $found['placed']++;
            if (count($tactics) > 1) {
                $found['multi']++;
            }
            foreach ($tactics as $token) {
                if (!isset($byTactic[$token])) {
                    $byTactic[$token] = array(
                        'tactic' => $token,
                        'name' => self::tacticName($token),
                        'techniques' => array(),
                        'events' => array(),
                        'orgs' => array(),
                        'galaxies' => array(),
                    );
                }
                /*
                 * Whose kill chain this tactic is on, and the chip's
                 * hover is where it has to be said. The strip is one
                 * ordered run of chips, so a value whose techniques
                 * span two frameworks — `attck4fraud`'s tactics after
                 * ATT&CK's, which is what the fraud events here
                 * produce — reads as a single chain running past
                 * `Impact`, and no framework claims that. Naming the
                 * galaxy is the same answer the rows above give for a
                 * cluster's family, from the same field.
                 */
                $galaxy = empty($record['Galaxy']['name'])
                    ? $record['type']
                    : $record['Galaxy']['name'];
                $byTactic[$token]['galaxies'][$galaxy] = $galaxy;
                /*
                 * The cluster's own name, which is what the fold prints
                 * in place of a value — `Masquerading - T1036` rather
                 * than the tag string storing it.
                 */
                $byTactic[$token]['techniques'][$label['label']] =
                    $label['label'];
                foreach ($label['events'] as $eventId) {
                    $byTactic[$token]['events'][(int)$eventId] = true;
                }
                foreach ($label['orgs'] as $name) {
                    $byTactic[$token]['orgs'][$name] = $name;
                }
            }
        }

        $rows = array();
        $frameworks = array();
        foreach ($byTactic as $token => $tactic) {
            $names = array_values($tactic['techniques']);
            sort($names);
            $galaxies = array_values($tactic['galaxies']);
            sort($galaxies);
            foreach ($galaxies as $galaxy) {
                $frameworks[$galaxy] = $galaxy;
            }
            $rows[] = array(
                'tactic' => $token,
                'name' => $tactic['name'],
                'techniques' => count($names),
                'technique_names' => $names,
                'events' => count($tactic['events']),
                'orgs' => count($tactic['orgs']),
                'galaxies' => $galaxies,
                /*
                 * A tactic the chain cannot place still gets a chip —
                 * it is a real reading of a real cluster — and sorts
                 * after the ones it can, rather than at a position the
                 * data never stated.
                 */
                'position' => isset($chain[$token])
                    ? $chain[$token]
                    : null,
            );
        }
        usort($rows, function ($a, $b) {
            if (($a['position'] === null) !== ($b['position'] === null)) {
                return $a['position'] === null ? 1 : -1;
            }
            if ($a['position'] !== null
                && $a['position'] !== $b['position']
            ) {
                return $a['position'] - $b['position'];
            }
            return strcasecmp($a['name'], $b['name']);
        });
        $found['rows'] = $rows;
        $found['total'] = count($rows);
        /*
         * How many kill chains the strip is showing at once. One is the
         * ordinary case and needs no words; more than one is the case
         * where the strip's single ordered run stops being a single
         * chain, and the group says so.
         */
        $found['frameworks'] = count($frameworks);
        return $found;
    }

    /**
     * A tactic token as a reader should see it.
     *
     * The token is whatever the galaxy wrote after the last colon of a
     * `kill_chain` element, normalised — so `defense-evasion` and
     * `Defense Evasion` are one tactic rather than two chips saying the
     * same thing. Sentence case rather than ATT&CK's own Title Case:
     * the chips sit under a card whose rows are proper names, and
     * title-casing a phrase competes with them for the same glance.
     *
     * @param string $token
     * @return string
     */
    private static function tacticName($token)
    {
        $words = str_replace('-', ' ', $token);
        return mb_strtoupper(mb_substr($words, 0, 1)) . mb_substr($words, 1);
    }

    /**
     * One tactic token, as the two callers have to agree on it.
     *
     * A `kill_chain` element is `<tab>:<tactic>` — `attack-Windows:
     * defense-evasion` — and occasionally `<galaxy>:<tab>:<tactic>`,
     * which the deprecated MITRE galaxies write. The tactic is the last
     * segment either way, and the tab in front of it is the *platform*
     * rather than a second dimension: one technique carries up to 40 of
     * these elements, the same handful of tactics repeated once per
     * operating system it applies to. Reading the last segment and
     * de-duplicating is what collapses that back to the tactics.
     *
     * Lower-cased and dashed, which merges the three spellings the
     * shipped galaxies use for one tactic — ATT&CK's `defense-evasion`,
     * ATRM's `Initial Access`, MoTIF's `Initial-Access`. It does not
     * merge `defence-evasion` with `defense-evasion`: that is a real
     * spelling difference between two frameworks and papering over it
     * would need a dictionary this page has no business holding.
     *
     * @param string $value A `kill_chain` element's value
     * @return string
     */
    private static function tacticToken($value)
    {
        $parts = explode(':', (string)$value);
        $tactic = trim(array_pop($parts));
        return str_replace(' ', '-', mb_strtolower($tactic));
    }

    /**
     * Which tactics each of these clusters names, keyed by cluster id.
     *
     * One indexed read over `galaxy_elements`, and it is the query B9
     * was scoped believing it would not need: the tactic is not on the
     * cluster row. `fetchGalaxyClusters` contains `Galaxy` and nothing
     * else unless asked for everything, so the `kill_chain` elements —
     * 5,964 rows of the table's 304,132 — have to be read. Scoped to
     * the `attack-pattern` clusters actually in play, which is tens of
     * ids against an index on `galaxy_cluster_id`.
     *
     * It runs in the scan rather than in the digest so that the card's
     * fold stays query-free and the answer ages at the rate the panel
     * already discloses.
     *
     * @param array $clusters `claimClusters`' by_uuid / by_tag maps
     * @return array Cluster id => tactic tokens, in first-seen order
     */
    private function clusterTactics(array $clusters)
    {
        $ids = array();
        foreach (array('by_tag', 'by_uuid') as $side) {
            if (empty($clusters[$side])) {
                continue;
            }
            foreach ($clusters[$side] as $row) {
                $record = $row['GalaxyCluster'];
                if (GalaxyCategory::isAttackPattern($record['type'])) {
                    $ids[(int)$record['id']] = true;
                }
            }
        }
        if (empty($ids)) {
            return array();
        }
        $elements = $this->model('GalaxyElement')->find('all', array(
            'recursive' => -1,
            'fields' => array(
                'GalaxyElement.galaxy_cluster_id',
                'GalaxyElement.value',
            ),
            'conditions' => array(
                'GalaxyElement.key' => 'kill_chain',
                'GalaxyElement.galaxy_cluster_id' => array_keys($ids),
            ),
        ));
        $tactics = array();
        foreach ($elements as $element) {
            $id = (int)$element['GalaxyElement']['galaxy_cluster_id'];
            $token = self::tacticToken($element['GalaxyElement']['value']);
            if ($token === '') {
                continue;
            }
            if (!isset($tactics[$id])) {
                $tactics[$id] = array();
            }
            $tactics[$id][$token] = $token;
        }
        foreach ($tactics as $id => $tokens) {
            $tactics[$id] = array_values($tokens);
        }
        return $tactics;
    }

    /**
     * The kill chain these tactics sit on, as token => position.
     *
     * **Ordered by the galaxies' own `kill_chain_order`, pooled across
     * the ATT&CK-shaped families rather than read off one of them**, and
     * pooling is what makes the order come out right. `mitre-attack-
     * pattern`'s order is a map of *platform* tabs — one list per
     * operating system — and no tab holds both `reconnaissance` and
     * `initial-access`, so that galaxy alone cannot say which of them
     * comes first. It matters: `attack-PRE`'s two tactics reach 36
     * events on the verification instance, and a strip putting
     * reconnaissance after impact reads as a bug. Two galaxies ship the
     * whole chain as a single list — `cmtmf-attack-pattern` states
     * ATT&CK's fourteen tactics in order and `mitre-atlas-attack-
     * pattern` states them with its two ML stages inserted — and
     * reading those alongside the platform tabs supplies exactly the
     * relation the tabs omit. So the answer stays derived from shipped
     * data instead of from a tactic list hardcoded here, which is the
     * whole reason `GalaxyCategory` exists.
     *
     * **A single-list galaxy is read before a multi-tab one**, longest
     * list first, because one list is an unambiguous statement about
     * the whole chain while many tabs state an order per platform and
     * nothing between the platforms. Read the other way round, the
     * platform tabs place `initial-access` first and the complete chain
     * then contradicts them.
     *
     * **The merge inserts and never moves.** Each list walks the chain
     * built so far, and a tactic it names that is already placed only
     * advances the insertion point — so where two frameworks genuinely
     * disagree the first one read wins, deterministically, rather than
     * the merge having to detect a cycle and pick a loser anyway. A
     * list sharing no tactic with the chain is a separate framework's
     * kill chain — `attck4fraud`'s seven, the deprecated `pre-attack`'s
     * seventeen — and follows the chain rather than being interleaved
     * into it.
     *
     * **A new tactic lands as late as its list allows**, immediately
     * before the next tactic that list names and the chain has already
     * placed, rather than immediately after the previous one. Both
     * satisfy the list; the late reading puts a tactic beside the ones
     * it belongs with. MoTIF's `defence-evasion` is the case that shows
     * it: its list says only *after persistence, before credential
     * access*, and inserting early left the British spelling sitting
     * two places ahead of ATT&CK's `defense-evasion` instead of next
     * to it, which reads as a sort fault rather than as two frameworks
     * spelling one tactic differently.
     *
     * @return array Tactic token => position
     */
    private function tacticChain()
    {
        $rows = $this->model('Galaxy')->find('all', array(
            'recursive' => -1,
            'fields' => array('Galaxy.type', 'Galaxy.kill_chain_order'),
            'conditions' => array(
                'Galaxy.type' => GalaxyCategory::typesOfSubCategory(
                    GalaxyCategory::ATTACK_PATTERN
                ),
            ),
        ));

        /*
         * `Galaxy::afterFind` decodes the column, and leaves null both
         * where it is empty and where it holds the literal `null` a
         * hand-made galaxy can carry.
         */
        $orders = array();
        foreach ($rows as $row) {
            $order = $row['Galaxy']['kill_chain_order'];
            if (empty($order) || !is_array($order)) {
                continue;
            }
            $tokens = 0;
            foreach ($order as $columns) {
                $tokens += count($columns);
            }
            $orders[] = array(
                'type' => $row['Galaxy']['type'],
                'tabs' => count($order),
                'tokens' => $tokens,
                'order' => $order,
            );
        }
        usort($orders, function ($a, $b) {
            if ($a['tabs'] !== $b['tabs']) {
                return $a['tabs'] - $b['tabs'];
            }
            if ($a['tokens'] !== $b['tokens']) {
                return $b['tokens'] - $a['tokens'];
            }
            return strcmp($a['type'], $b['type']);
        });

        $chain = array();
        foreach ($orders as $galaxy) {
            foreach ($galaxy['order'] as $columns) {
                $sequence = array();
                foreach ($columns as $column) {
                    $token = self::tacticToken($column);
                    if ($token !== '') {
                        $sequence[$token] = $token;
                    }
                }
                self::mergeTactics($chain, array_values($sequence));
            }
        }
        return array_flip($chain);
    }

    /**
     * One kill chain merged into the chain built so far.
     *
     * See `tacticChain` for why it inserts and never moves. A sequence
     * with nothing in common with the chain is appended whole, because
     * a framework whose tactics relate to none of the placed ones has
     * stated no position among them.
     *
     * @param array $chain Ordered tokens, modified in place
     * @param array $sequence One tab's tactics, in its own order
     * @return void
     */
    private static function mergeTactics(array &$chain, array $sequence)
    {
        if (empty($sequence)) {
            return;
        }
        if (empty(array_intersect($sequence, $chain))) {
            foreach ($sequence as $token) {
                $chain[] = $token;
            }
            return;
        }
        $at = -1;
        $pending = array();
        foreach ($sequence as $token) {
            $found = array_search($token, $chain, true);
            if ($found === false) {
                $pending[] = $token;
                continue;
            }
            if (!empty($pending)) {
                $insert = max($at + 1, $found);
                array_splice($chain, $insert, 0, $pending);
                $found += count($pending);
                $pending = array();
            }
            $at = max($at, $found);
        }
        if (!empty($pending)) {
            array_splice($chain, $at + 1, 0, $pending);
        }
    }

    private function relationScan(array $user, $value, array $options,
        $fresh = false
    ) {
        $key = 'misp:value_intelligence:relation_scan:v'
            . self::CACHE_SHAPE . ':' . self::cacheScope($user)
            . ':' . hash('sha256', $value . '|' . json_encode($options));
        return $this->cachedFold($key, $fresh,
            function () use ($user, $value, $options) {
                $scan = $this->readRelationScan($user, $value, $options);
                $scan['read_at'] = time();
                return $scan;
            });
    }

    /**
     * Whom a cached fold is computed for. What a reader may see follows
     * from their organisation and their role, so colleagues sharing both
     * share the fold, and a reader moved to another organisation or role
     * stops reading the old one at once.
     *
     * @param array $user
     * @return string
     */
    private static function cacheScope(array $user)
    {
        return 'o' . (int)$user['org_id'] . 'r' . (int)$user['role_id'];
    }

    /**
     * Read a fold from Redis, and let exactly one request compute it.
     *
     * **The tab's nine panels are nine requests, and five of them want
     * this.** `mispOvermind.js` fires every `.ajax-card` on a tab the
     * moment it is shown, so on the first visit to Relationships the
     * co-occurrence and dated panels ask for the scan while the graph,
     * threat and settings panels ask for the digest that contains it.
     * A plain `GET`/`SETEX` pair means all five miss together and all
     * five scan, so the reader pays for one scan five times over and
     * the five copies contend for the same rows while they do it.
     *
     * Measured on `8.8.8.8` before this: the nine panels cold took
     * **15.1 s** wall-clock, against **5.4 s** for the same nine when a
     * single scan had been primed first — worse than *sequential*,
     * whose slowest panel was 6.2 s. The duplication was not merely
     * wasted, it was the largest single cost on the tab.
     *
     * So the first request through takes a lock and computes; the rest
     * wait on the key it will write. A waiter that finds the lock gone
     * with nothing written computes rather than reporting an error —
     * the leader died, and a slow answer beats none. Losing Redis
     * entirely degrades to what this replaced: everyone computes.
     *
     * @param string $key The cache key, already scoped and versioned
     * @param bool $fresh Skip the read; still take the lock
     * @param callable $compute Returns the fold to cache
     * @param int $ttl Seconds the fold is held
     * @return array
     */
    private function cachedFold($key, $fresh, callable $compute,
        $ttl = self::RELATION_SCAN_TTL
    ) {
        $redis = null;
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            $redis = null;
        }
        if ($redis === null) {
            return $compute();
        }
        $read = function () use ($redis, $key) {
            return RedisTool::deserialize(
                RedisTool::decompress($redis->get($key))
            );
        };
        if (!$fresh) {
            $cached = $read();
            if (!empty($cached)) {
                return $cached;
            }
        }

        $lockKey = $key . ':lock';
        $leader = (bool)$redis->set($lockKey, 1, array(
            'nx',
            'ex' => self::RELATION_LOCK_TTL,
        ));
        if (!$leader) {
            $deadline = microtime(true) + self::RELATION_LOCK_WAIT;
            while (microtime(true) < $deadline) {
                usleep(self::RELATION_LOCK_POLL);
                $cached = $read();
                if (!empty($cached)) {
                    return $cached;
                }
                if (!$redis->exists($lockKey)) {
                    break;
                }
            }
        }

        try {
            $fold = $compute();
            $redis->setex(
                $key,
                $ttl,
                RedisTool::compress(RedisTool::serialize($fold))
            );
        } finally {
            if ($leader) {
                $redis->del($lockKey);
            }
        }
        return $fold;
    }

    /**
     * The scan itself: choose the scope, then read it completely.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    private function readRelationScan(array $user, $value, array $options)
    {
        $valueModel = $this->model('Value');
        $events = $valueModel->occurrenceEventsFor(
            $user,
            $value,
            array_merge($options, array(
                'limit' => self::RELATION_EVENT_CAP,
            ))
        );
        $sizes = $this->eventSizes(array_keys($events));

        $picked = array();
        $spent = 0;
        $oversized = 0;
        $unread = 0;
        foreach ($events as $eventId => $meta) {
            $size = isset($sizes[$eventId]) ? $sizes[$eventId] : 0;
            if ($size > self::RELATION_EVENT_SIZE_CAP) {
                $oversized++;
                continue;
            }
            if ($spent + $size > self::RELATION_SCAN_BUDGET) {
                $unread++;
                continue;
            }
            $picked[] = $eventId;
            $spent += $size;
        }

        $rows = $valueModel->neighbourRowsFor(
            $user,
            $value,
            array('events' => $picked),
            array_merge($options, array('tags' => true))
        );
        $this->attachTags($rows);

        /*
         * **Read over every event the value is in, not over the events
         * the attribute budget could afford.** §10.2 makes a label a
         * neighbour in its own right, and a label costs the same
         * whatever the size of the event carrying it: one indexed
         * `EventTag` read over at most `RELATION_EVENT_CAP` ids either
         * way. Scoping it to `$picked` would drop a cluster for a
         * reason that has nothing to do with clusters — the exact
         * argument `relationDigest` already made for keeping the threat
         * card off the scan, and the reason that card can now be a
         * slice of this fold instead of a second read.
         *
         * So the two halves of the table have two scopes, and the panel
         * states both rather than averaging them: values over the
         * events that were read, labels over the events that exist.
         */
        $eventMeta = $this->eventMetadata($user, array_keys($events));
        $ownTags = $valueModel->ownTagsFor(
            $user,
            $value,
            array_keys($events),
            $options
        );

        /*
         * Which of the galaxy tags in play name a cluster this viewer
         * may know exists. One `fetchGalaxyClusters` over every galaxy
         * name the three sources between them mention — the value's own
         * occurrences, the events it appears in, and the neighbouring
         * attributes the scan read.
         *
         * Unresolved is dropped, not printed, for the reason spelled
         * out at `claimTarget`: the tag string would disclose the
         * cluster the instance is withholding.
         */
        $galaxyNames = array();
        foreach ($eventMeta as $meta) {
            foreach ($meta['galaxy_tags'] as $name) {
                $galaxyNames[$name] = true;
            }
        }
        foreach ($ownTags as $name => $entry) {
            if ($entry['tag']['is_galaxy']) {
                $galaxyNames[$name] = true;
            }
        }
        foreach ($rows as $row) {
            if (empty($row['AttributeTag'])) {
                continue;
            }
            foreach ($row['AttributeTag'] as $attributeTag) {
                if (empty($attributeTag['Tag'])
                    || empty($attributeTag['Tag']['is_galaxy'])
                ) {
                    continue;
                }
                $galaxyNames[$attributeTag['Tag']['name']] = true;
            }
        }
        $clusters = $this->claimClusters(
            $user,
            array(),
            array_keys($galaxyNames)
        );

        /*
         * Which tactic each technique cluster names, written onto the
         * cluster record so the fold carries it into the label rows and
         * the tactic group needs no second lookup — the same decoration
         * `Galaxy::getMatrix` does with `external_id`, and for the same
         * reason: the element is what the caller wants and the row is
         * where it has to arrive.
         */
        $clusterTactics = $this->clusterTactics($clusters);
        foreach (array('by_tag', 'by_uuid') as $side) {
            foreach ($clusters[$side] as $key => $row) {
                $id = (int)$row['GalaxyCluster']['id'];
                $clusters[$side][$key]['GalaxyCluster']['tactics'] =
                    isset($clusterTactics[$id])
                        ? $clusterTactics[$id]
                        : array();
            }
        }

        /*
         * The organisations credited on a label row are the creator
         * organisations of the events carrying it — which reaches
         * further than the rows' own events now that labels are read
         * over all of them, so the ids come from both.
         */
        $eventOrgIds = array();
        $eventLevels = array();
        foreach ($eventMeta as $meta) {
            if (!empty($meta['orgc_id'])) {
                $eventOrgIds[(int)$meta['orgc_id']] = true;
            }
            $eventLevels[] = (int)$meta['distribution'];
        }
        $orgs = $this->organisationNames($rows, array_keys($eventOrgIds));

        /*
         * Held with the rows it describes rather than recomputed per
         * request, and that is the honest place for it: the panel
         * already prints how old this scan is, so the listing verdicts
         * age at the rate the panel discloses instead of at a rate it
         * does not mention. It costs 65 ms over `8.8.8.8`'s 10,040
         * neighbours (`ValueWarninglistTool`), which is worth paying
         * once a scan rather than on every narrowing of it.
         *
         * The consequence is bounded and stated: enabling a list shows
         * up here within `RELATION_SCAN_TTL`, or at once on the panel's
         * own refresh, which re-reads the scan.
         */
        $warninglistModel = $this->model('Warninglist');
        $probes = array();
        foreach ($rows as $row) {
            $probes[] = array(
                'value' => $row['Attribute']['value'],
                'type' => $row['Attribute']['type'],
            );
        }

        /*
         * The sibling join runs before the fold, because the fold needs
         * the object templates this value sits in: `sibling` is one of
         * the tokens a row is matched on, and a token the fold cannot
         * build is a filter the fold cannot apply.
         */
        $sections = $this->objectSections($user, $value, $options, $orgs);
        $siblings = $sections['siblings'];
        $ourObjects = array();
        foreach ($siblings['rows'] as $sibling) {
            $ourObjects[$sibling['object']] = true;
        }

        return array(
            'rows' => $rows,
            'picked' => $picked,
            'events_seen' => count($events),
            'events_oversized' => $oversized,
            'events_unread' => $unread,
            'orgs' => $orgs,
            'sharing_groups' => $this->sharingGroupNames(
                $user,
                $rows,
                $eventLevels
            ),
            'event_meta' => $eventMeta,
            /*
             * The label side of the fold, and the reason the threat
             * card no longer runs its own five queries: the tags on
             * this value's own occurrences, and the clusters those and
             * the event tags resolve to under this viewer's ACL.
             */
            'own_tags' => $ownTags,
            'clusters' => $clusters,
            'siblings' => $siblings,
            /*
             * Folded here rather than in its own endpoint because it
             * reads the rows this scan has already fetched. A second
             * endpoint would mean a second object join for a panel
             * whose whole input is sitting in this array.
             */
            'dated' => $sections['dated'],
            'our_objects' => $ourObjects,
            'warninglists' => ValueWarninglistTool::hitsFor(
                $warninglistModel,
                $probes
            ),
            'warninglists_checked' => ValueWarninglistTool::enabledCount(
                $warninglistModel
            ),
            /*
             * The **Most specific** rank's denominator, held with the
             * rows it describes for the same reason the warninglist
             * verdicts are: it is a lookup over the whole fold, it does
             * not change between narrowings of that fold, and the panel
             * already prints how old this scan is. 775 ms over
             * `8.8.8.8`'s 9,520 neighbours and 361 ms over `443`'s 758
             * sibling values — worth paying once a scan rather than on
             * every re-rank of it.
             *
             * Two maps because the two tables count different things.
             * The values table's rows are events, so a neighbour's
             * spread is events; the sibling table's rows are objects
             * and its visible count is objects, so a fraction in events
             * would not match the column beside it.
             */
            'prevalence' => $valueModel->prevalenceFor(
                $user,
                $this->neighbourValues($rows),
                $options
            ),
        );
    }

    /**
     * The neighbour value strings a prevalence lookup needs, deduped.
     *
     * Keyed exactly as `ValueRelationTool::cooccurrence` keys its
     * groups — on `Attribute.value` — so the map it hands back can be
     * read straight off the row without a second interpretation of
     * what a value is.
     *
     * @param array $rows Neighbour rows
     * @return array Value strings
     */
    private function neighbourValues(array $rows)
    {
        $values = array();
        foreach ($rows as $row) {
            if (!empty($row['Attribute']['value'])) {
                $key = $row['Attribute']['value'];
                $values[$key] = isset($values[$key])
                    ? $values[$key] + 1
                    : 1;
            }
        }
        /*
         * **Most locally frequent first**, because that is the order
         * `Value::prevalenceFor` cuts its tail off in. A value carried
         * by many of the rows this scan read is a value many of the
         * panel's own rows rest on, so if the probe cap bites it should
         * bite the neighbours that appear once. Stable within a
         * frequency so the fold stays reproducible between scans.
         */
        arsort($values, SORT_NUMERIC);
        return array_map('strval', array_keys($values));
    }


    /**
     * How many attributes each candidate event holds.
     *
     * Tier 2, and the written reason is that this is the query that
     * makes the rest of the section affordable: the answer is one
     * number per event, it is index-only on `attributes.event_id`, and
     * every row it counts is a row the neighbour scan then does not
     * have to read. No ACL is applied and none is needed — the number
     * never reaches the page. It decides which events are worth
     * reading, and the reading itself goes through
     * `buildConditions($user)` like everything else here.
     *
     * @param array $eventIds
     * @return array event id => attribute count
     */
    private function eventSizes(array $eventIds)
    {
        if (empty($eventIds)) {
            return array();
        }
        $rows = $this->model('MispAttribute')->find('all', array(
            'fields' => array(
                'Attribute.event_id',
                'COUNT(*) AS attributes',
            ),
            'conditions' => array('Attribute.event_id' => $eventIds),
            'recursive' => -1,
            'group' => array('Attribute.event_id'),
        ));
        $sizes = array();
        foreach ($rows as $row) {
            $sizes[(int)$row['Attribute']['event_id']] =
                (int)$row[0]['attributes'];
        }
        return $sizes;
    }

    /**
     * The event roll-up's own columns — info, date, creator, tags.
     *
     * One `fetchSimpleEvents` for all N, per §14.4's batching rule, and
     * one tag fetch beside it. The neighbour rows carry `Event.info`
     * already; this exists for the events that survived the scan but
     * whose only neighbour rows were dropped, so the roll-up cannot
     * name an event it has no title for.
     *
     * @param array $user
     * @param array $eventIds
     * @return array event id => info, date, orgc_id, distribution, tags
     */
    private function eventMetadata(array $user, array $eventIds)
    {
        if (empty($eventIds)) {
            return array();
        }
        $events = $this->model('Event')->fetchSimpleEvents(
            $user,
            array('conditions' => array('Event.id' => $eventIds)),
            true
        );
        $meta = array();
        foreach ($events as $event) {
            $meta[(int)$event['Event']['id']] = array(
                'info' => $event['Event']['info'],
                'date' => $event['Event']['date'],
                /*
                 * The event's own modification stamp, which is what a
                 * label row's **Last together** reads. A tag carries no
                 * date of its own on either join table, and the event
                 * date is the day the incident is filed under rather
                 * than the day the record last moved — so the honest
                 * pairing with a value row's `Attribute.timestamp` is
                 * this, the same clock and the same meaning.
                 */
                'timestamp' => (int)$event['Event']['timestamp'],
                'orgc_id' => (int)$event['Event']['orgc_id'],
                'distribution' => (int)$event['Event']['distribution'],
                'sharing_group_id' =>
                    (int)$event['Event']['sharing_group_id'],
                'tags' => array(),
                'galaxy_tags' => array(),
            );
        }
        $tags = $this->model('EventTag')->find('all', array(
            'conditions' => array(
                'EventTag.event_id' => array_keys($meta),
            ),
            'recursive' => -1,
            'contain' => array('Tag' => array('fields' => array(
                'Tag.id', 'Tag.name', 'Tag.colour', 'Tag.is_galaxy',
            ))),
        ));
        foreach ($tags as $tag) {
            $eventId = (int)$tag['EventTag']['event_id'];
            if (!isset($meta[$eventId]) || empty($tag['Tag'])) {
                continue;
            }
            /*
             * Kept rather than dropped, for `claimEventTags`' reason
             * one level up: the Tags column does not draw a galaxy tag,
             * so every other reader here filters them out — but the
             * neighbourhood card is made of them, and they are already
             * in this result set. Only the name is kept, because a
             * cluster still has to go through `fetchGalaxyClusters`
             * before it may be shown at all.
             */
            if (!empty($tag['Tag']['is_galaxy'])) {
                $meta[$eventId]['galaxy_tags'][] = $tag['Tag']['name'];
                continue;
            }
            /*
             * Whether the tag left the instance. A local tag is real to
             * this viewer and false to everybody else, and §10.2's
             * table now gives one a row of its own — so the row has to
             * be able to say so rather than reading as shared context.
             */
            $tag['Tag']['local'] = !empty($tag['EventTag']['local']);
            $meta[$eventId]['tags'][] = $tag['Tag'];
        }
        return $meta;
    }

    /**
     * Creator organisation names for the rows' events.
     *
     * A plain `Organisation` list rather than an ACL'd fetcher, and it
     * is not a tier-3 bypass: `buildConditions($user)` already decided
     * which rows this viewer may see, and every one of those rows
     * carries its creator organisation on the event page and in every
     * attribute index in MISP. The only thing resolved here is an id
     * into the name beside it.
     *
     * @param array $rows
     * @param array $extra Further ids the caller holds — the events a
     *     label was read on reach past the events the rows came from
     * @return array org id => name
     */
    private function organisationNames(array $rows, array $extra = array())
    {
        $ids = array();
        foreach ($rows as $row) {
            if (!empty($row['Event']['orgc_id'])) {
                $ids[(int)$row['Event']['orgc_id']] = true;
            }
        }
        foreach ($extra as $orgId) {
            if (!empty($orgId)) {
                $ids[(int)$orgId] = true;
            }
        }
        if (empty($ids)) {
            return array();
        }
        return $this->model('Organisation')->find('list', array(
            'recursive' => -1,
            'fields' => array('Organisation.id', 'Organisation.name'),
            'conditions' => array(
                'Organisation.id' => array_keys($ids),
            ),
        ));
    }

    /**
     * Sharing-group names, and only when a row could need one.
     *
     * `fetchAllAuthorised` rather than a plain find, for the reason
     * `attachEffectiveDistribution` gives: a group name must not be
     * readable off a row whose event the reader happens to own.
     *
     * @param array $user
     * @param array $rows
     * @param array $extra Further distribution levels the caller holds
     *     — a label row's audience is its event's, and labels are read
     *     over events no row came from
     * @return array
     */
    private function sharingGroupNames(array $user, array $rows,
        array $extra = array()
    ) {
        foreach ($rows as $row) {
            $levels = array(
                (int)$row['Attribute']['distribution'],
                (int)($row['Event']['distribution'] ?? -1),
                empty($row['Object']['id'])
                    ? -1
                    : (int)$row['Object']['distribution'],
            );
            if (in_array(4, $levels, true)) {
                return $this->model('SharingGroup')
                    ->fetchAllAuthorised($user, 'name');
            }
        }
        if (in_array(4, array_map('intval', $extra), true)) {
            return $this->model('SharingGroup')
                ->fetchAllAuthorised($user, 'name');
        }
        return array();
    }

    /**
     * The object siblings — the same object, other relations.
     *
     * Not a correlation and not the engine's to suppress: a join on
     * `Attribute.object_id` over occurrences this viewer can already
     * see. It is the reason a value whose events are all too large to
     * scan still has something on this tab, and the reason the
     * suppressed band above it does not short-circuit the panel.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @param array $orgs Names already resolved for the neighbour rows
     * @return array
     */
    private function objectSections(array $user, $value, array $options,
        array $orgs
    ) {
        $valueModel = $this->model('Value');
        $objects = $valueModel->occurrenceObjectIdsFor(
            $user,
            $value,
            array_merge($options, array(
                'limit' => self::SIBLING_OBJECT_CAP,
            ))
        );
        $relations = array();
        foreach ($objects as $objectId => $meta) {
            $relations[$objectId] = $meta['relation'];
        }
        $rows = $valueModel->neighbourRowsFor(
            $user,
            $value,
            array('objects' => array_keys($objects)),
            $options
        );
        $missing = $this->organisationNames($rows);
        $census = $this->objectCensus($user, $value, $options,
            count($objects));
        /*
         * A second warninglist read, over this join's own rows.
         *
         * It cannot reuse the co-occurrence scan's: that one probes the
         * attributes of the *events* the scan read, and these are the
         * attributes of the *objects* the value sits in. An object can
         * survive an event the scan skipped for being oversized — which
         * is the whole reason the sibling table renders under a
         * suppressed band — so a sibling value need not appear in the
         * other probe set at all.
         *
         * What it costs is one query, `assignComments`, and only where
         * something matched. The per-value work is nearly free on the
         * overlap: `attachWarninglistToAttributes` keys its Redis cache
         * on `(type, value)`, so every value both reads share is a
         * cache hit the second time.
         */
        $warninglistModel = $this->model('Warninglist');
        $probes = array();
        foreach ($rows as $row) {
            $probes[] = array(
                'value' => $row['Attribute']['value'],
                'type' => $row['Attribute']['type'],
            );
        }
        /*
         * One context for both folds, because they read the same rows
         * against the same bounds and a second copy would be a second
         * place for the caps to drift apart.
         */
        $context = array(
            'orgs' => $orgs + $missing,
            'relations' => $relations,
            'in_objects' => $census['total'],
            'template_totals' => $census['templates'],
            'cap' => self::SIBLING_OBJECT_CAP,
            'row_cap' => self::RELATION_ROW_CAP,
            'page_size' => self::RELATION_PAGE_SIZE,
            'warninglists' => ValueWarninglistTool::hitsFor(
                $warninglistModel,
                $probes
            ),
            'warninglists_checked' => ValueWarninglistTool::enabledCount(
                $warninglistModel
            ),
            /*
             * Counted in objects, and read from these raw rows rather
             * than from the fold's output: `siblings` ranks and then
             * cuts to `row_cap`, so a denominator arriving after the
             * fold could only re-order the hundred rows that already
             * won — which is the re-rank-a-page contract the tab
             * refuses to take on.
             *
             * Objects rather than events because the sibling row's own
             * count is objects. `paloalto-threat-event · dst ·
             * 0.0.0.0` sits in 5 of `8.8.8.8`'s objects and in 32,922
             * across the instance; that ratio is what moves it off
             * page one, and it has to be the same unit as the number
             * printed beside it.
             */
            'prevalence' => $valueModel->prevalenceFor(
                $user,
                $this->neighbourValues($rows),
                array_merge($options, array('unit' => 'object'))
            ),
        );
        return array(
            'siblings' => ValueRelationTool::siblings($rows, $context),
            'dated' => ValueRelationTool::dated($rows, $context),
            'object_ids' => array_keys($objects),
        );
    }

    /**
     * How many objects this value sits in altogether, and how they
     * divide by template.
     *
     * Asked only when the cap actually bit. Below it the answer is the
     * number of objects already fetched, and a `COUNT(DISTINCT …)` over
     * 32,921 rows to learn a number we are holding would be the exact
     * mistake `occurrenceSummaryFor` was written to stop.
     *
     * **The per-template split is what the roll-up node prints**, and
     * it costs nothing extra: one `GROUP BY Object.name` gives both the
     * breakdown and the total, where the old query gave only the total.
     * Without it `0.0.0.0` would draw `paloalto-threat-event · 500
     * objects` — the cap's number, not the value's — which is the one
     * number a roll-up exists to carry.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @param int $fetched
     * @return array `total`, and `templates` as name => objects
     */
    private function objectCensus(array $user, $value, array $options,
        $fetched
    ) {
        if ($fetched < self::SIBLING_OBJECT_CAP) {
            return array('total' => $fetched, 'templates' => array());
        }
        $attributes = $this->model('MispAttribute');
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->model('Value')
            ->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.object_id >' => 0);
        $rows = $attributes->find('all', array(
            'fields' => array(
                'Object.name',
                'COUNT(DISTINCT Attribute.object_id) AS objects',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
            'group' => array('Object.name'),
        ));
        $templates = array();
        $total = 0;
        foreach ($rows as $row) {
            if (empty($row['Object']['name'])) {
                continue;
            }
            $count = (int)$row[0]['objects'];
            $templates[$row['Object']['name']] = $count;
            $total += $count;
        }
        return array(
            'total' => $total === 0 ? $fetched : $total,
            'templates' => $templates,
        );
    }

    /**
     * Section six: what MISP itself records as related to this value.
     *
     * `ObjectReference` is the only typed, directional relation in MISP
     * that a person wrote and that is not an analyst claim — a
     * `hosted-by`, a `communicates-with`, and on this instance a
     * `Crush` where somebody typed that. It is read here in **both
     * directions and at both depths**:
     *
     *     direct     the reference points at this value's own
     *                attribute (`referenced_type = 0`, 1,142 rows on
     *                the verification instance)
     *     by parent  the reference is between the object this value
     *                sits in and another one (`referenced_type = 1`,
     *                10,191 rows), in either direction
     *
     * **A reference with both ends in this value's own set is
     * dropped.** `18.117.184.102` sits in four `passive-dns` objects
     * and every one of them carries a `hosted-by` pointing back at the
     * bare attribute — the object holding the value saying the value
     * hosts it. That is a re-telling, not a relation to something else,
     * and it would have been eight of the twelve rows.
     *
     * **Its own read, not the co-occurrence scan's.** The scan reads up
     * to 20,000 attribute rows; this is three indexed lookups and a
     * resolve. Hanging it off the scan would make the cheapest section
     * on the tab wait for the most expensive one, which is the same
     * argument `ValuesController` makes for splitting the endpoints.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array As ValueRelationTool::references returns
     */
    private function referenceSection(array $user, $value,
        array $options = array()
    ) {
        if ($this->references !== null && $this->memoValue === $value) {
            return $this->references;
        }
        $this->forget($value);
        $fresh = !empty($options['fresh']);
        $keyOptions = $options;
        unset($keyOptions['fresh']);
        $key = 'misp:value_intelligence:relation_references:v'
            . self::CACHE_SHAPE . ':' . self::cacheScope($user)
            . ':' . hash('sha256', $value . '|' . json_encode($keyOptions));
        $redis = null;
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            $redis = null;
        }
        if ($redis !== null && !$fresh) {
            $cached = RedisTool::deserialize(
                RedisTool::decompress($redis->get($key))
            );
            if (!empty($cached)) {
                $this->references = $cached;
                return $cached;
            }
        }
        $section = $this->readReferences($user, $value, $keyOptions);
        if ($redis !== null) {
            $redis->setex(
                $key,
                self::RELATION_SCAN_TTL,
                RedisTool::compress(RedisTool::serialize($section))
            );
        }
        $this->references = $section;
        return $section;
    }

    /**
     * The reference read itself: our two id sets, the reference rows
     * that touch them, and the far ends resolved through the ACL.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    private function readReferences(array $user, $value, array $options)
    {
        $valueModel = $this->model('Value');
        $ourAttributes = $valueModel->occurrenceIdsFor(
            $user,
            $value,
            array_merge($options, array(
                'limit' => self::REFERENCE_OCCURRENCE_CAP,
            ))
        );
        $ourObjects = $valueModel->occurrenceObjectIdsFor(
            $user,
            $value,
            array_merge($options, array(
                'limit' => self::SIBLING_OBJECT_CAP,
            ))
        );
        /*
         * The objects *read*, not the objects the value sits in.
         * `occurrenceObjectIdsFor` is capped at `SIBLING_OBJECT_CAP`
         * and the census that corrects it belongs to the co-occurrence
         * scan, which this section deliberately does not wait for. So
         * the panel says "of the 500 objects read" rather than quoting
         * a total it did not measure.
         */
        $context = array(
            'row_cap' => self::RELATION_ROW_CAP,
            'page_size' => self::RELATION_PAGE_SIZE,
            'read_objects' => count($ourObjects),
            'object_cap' => self::SIBLING_OBJECT_CAP,
            'occurrences' => count($ourAttributes),
        );
        if (empty($ourAttributes) && empty($ourObjects)) {
            return ValueRelationTool::references(array(), $context);
        }

        $branches = array();
        if (!empty($ourAttributes)) {
            $branches[] = array(
                'ObjectReference.referenced_type' => 0,
                'ObjectReference.referenced_id' =>
                    array_keys($ourAttributes),
            );
        }
        if (!empty($ourObjects)) {
            $branches[] = array(
                'ObjectReference.object_id' => array_keys($ourObjects),
            );
            $branches[] = array(
                'ObjectReference.referenced_type' => 1,
                'ObjectReference.referenced_id' => array_keys($ourObjects),
            );
        }
        $refs = $this->model('ObjectReference')->find('all', array(
            'conditions' => array(
                'ObjectReference.deleted' => 0,
                'OR' => $branches,
            ),
            'recursive' => -1,
            'order' => array('ObjectReference.id DESC'),
            'limit' => self::REFERENCE_ROW_CAP,
        ));

        $edges = array();
        $wantObjects = array();
        $wantAttributes = array();
        $carrying = array();
        foreach ($refs as $ref) {
            $row = $ref['ObjectReference'];
            $source = (int)$row['object_id'];
            $target = (int)$row['referenced_id'];
            $targetIsObject = (int)$row['referenced_type'] === 1;
            $sourceIsOurs = isset($ourObjects[$source]);
            $targetIsOurs = $targetIsObject
                ? isset($ourObjects[$target])
                : isset($ourAttributes[$target]);
            if ($sourceIsOurs) {
                $carrying[$source] = true;
            }
            if ($targetIsOurs && $targetIsObject) {
                $carrying[$target] = true;
            }
            if ($sourceIsOurs && $targetIsOurs) {
                // Both ends are this value's own. See the docblock.
                continue;
            }
            if ($sourceIsOurs) {
                $edges[] = array(
                    'row' => $row,
                    'direction' => 'outbound',
                    'near' => array('kind' => 'object', 'id' => $source),
                    'far' => array(
                        'kind' => $targetIsObject ? 'object' : 'attribute',
                        'id' => $target,
                    ),
                );
            } elseif ($targetIsOurs) {
                $edges[] = array(
                    'row' => $row,
                    'direction' => 'inbound',
                    'near' => array(
                        'kind' => $targetIsObject ? 'object' : 'attribute',
                        'id' => $target,
                    ),
                    'far' => array('kind' => 'object', 'id' => $source),
                );
            } else {
                continue;
            }
            $end = end($edges);
            if ($end['far']['kind'] === 'object') {
                $wantObjects[$end['far']['id']] = true;
            } else {
                $wantAttributes[$end['far']['id']] = true;
            }
            /*
             * The near object too, for its template. A row that says
             * *through the `passive-dns` object this value sits in* is
             * telling the reader which of several parents carried the
             * reference, which they cannot work out from the far end.
             */
            if ($end['near']['kind'] === 'object') {
                $wantObjects[$end['near']['id']] = true;
            }
        }
        $context['with_references'] = count($carrying);
        if (empty($edges)) {
            return ValueRelationTool::references(array(), $context);
        }

        $faces = $this->referenceFaces(
            $user,
            array_keys($wantObjects),
            array_keys($wantAttributes)
        );
        $rows = array();
        foreach ($edges as $edge) {
            $far = $this->referenceFace($faces, $edge['far']);
            if ($far === null) {
                // Nothing this reader may see at the far end, so there
                // is no row — not a row saying one was withheld.
                continue;
            }
            $near = $edge['near']['kind'] === 'object'
                && isset($ourObjects[$edge['near']['id']])
                ? array(
                    'kind' => 'object',
                    'object' => isset($faces['objects']
                        [$edge['near']['id']]['object'])
                        ? $faces['objects'][$edge['near']['id']]['object']
                        : null,
                    'relation' => $ourObjects[$edge['near']['id']]
                        ['relation'],
                )
                : array('kind' => 'attribute', 'object' => null,
                    'relation' => '');
            $rows[] = array(
                'relationship' => empty($edge['row']['relationship_type'])
                    ? __('unnamed')
                    : $edge['row']['relationship_type'],
                'named' => !empty($edge['row']['relationship_type']),
                'direction' => $edge['direction'],
                'comment' => empty($edge['row']['comment'])
                    ? ''
                    : $edge['row']['comment'],
                'near' => $near,
                'far' => $far,
                'event' => (int)$edge['row']['event_id'],
            );
        }
        return ValueRelationTool::references($rows, $context);
    }

    /**
     * Both far-end kinds resolved in one ACL-filtered read, keyed the
     * two ways the caller looks them up.
     *
     * The near end is resolved by the same query where it happens to be
     * an object we already asked about — a reference between two of
     * this value's own objects is dropped, so the only near objects
     * that survive are ones whose template we still want to print.
     *
     * @param array $user
     * @param array $objectIds
     * @param array $attributeIds
     * @return array `objects` and `attributes`, keyed by id
     */
    private function referenceFaces(array $user, array $objectIds,
        array $attributeIds
    ) {
        $rows = $this->model('Value')->referenceFacesFor(
            $user,
            $objectIds,
            $attributeIds,
            self::RELATION_ROW_CAP * self::REFERENCE_FACE_CAP
        );
        $objects = array();
        $attributes = array();
        foreach ($rows as $row) {
            $attribute = $row['Attribute'];
            $id = (int)$attribute['id'];
            $value = isset($attribute['value']) ? $attribute['value'] : '';
            if (in_array($id, $attributeIds, true)) {
                $attributes[$id] = array(
                    'kind' => 'attribute',
                    'object' => empty($row['Object']['name'])
                        ? null
                        : $row['Object']['name'],
                    'label' => $value,
                    'values' => array(array(
                        'value' => $value,
                        'relation' => empty($attribute['object_relation'])
                            ? ''
                            : $attribute['object_relation'],
                        'type' => $attribute['type'],
                    )),
                    'event' => (int)$attribute['event_id'],
                    'id' => $id,
                );
            }
            $objectId = (int)$attribute['object_id'];
            if ($objectId === 0 || !in_array($objectId, $objectIds, true)) {
                continue;
            }
            if (!isset($objects[$objectId])) {
                $objects[$objectId] = array(
                    'kind' => 'object',
                    'object' => empty($row['Object']['name'])
                        ? null
                        : $row['Object']['name'],
                    'label' => '',
                    'values' => array(),
                    'event' => (int)$attribute['event_id'],
                    'id' => $objectId,
                );
            }
            if (count($objects[$objectId]['values'])
                < self::REFERENCE_FACE_CAP
            ) {
                $objects[$objectId]['values'][] = array(
                    'value' => $value,
                    'relation' => empty($attribute['object_relation'])
                        ? ''
                        : $attribute['object_relation'],
                    'type' => $attribute['type'],
                );
            }
        }
        foreach ($objects as $objectId => $object) {
            $labels = array();
            foreach ($object['values'] as $entry) {
                $labels[] = $entry['value'];
            }
            $objects[$objectId]['label'] = implode(' · ', $labels);
        }
        return array('objects' => $objects, 'attributes' => $attributes);
    }

    /**
     * @param array $faces
     * @param array $end `kind` and `id`
     * @return array|null
     */
    private function referenceFace(array $faces, array $end)
    {
        $bucket = $end['kind'] === 'object' ? 'objects' : 'attributes';
        return isset($faces[$bucket][$end['id']])
            ? $faces[$bucket][$end['id']]
            : null;
    }

    /**
     * The near-match engines and what each of them has to say.
     *
     * Three engines and, live, **four states rather than three**. The
     * brief has *active*, *not applicable* and *no engine in MISP*;
     * real data adds a fourth that is none of them — an engine MISP
     * ships, that applies to this value, and that cannot run because
     * the PHP extension behind it is not loaded. Saying *not
     * applicable* there would be a lie about the value; saying *no
     * engine* would be a lie about MISP.
     *
     * @param array $user
     * @param string $value
     * @param array $types From `Value::typesFor`
     * @return array
     */
    private function nearMatches(array $user, $value, array $types)
    {
        if (empty($types)) {
            // No occurrence this viewer can see, so no type for an
            // engine to accept or decline. The panel says exactly that
            // rather than declining on the reader's behalf.
            return array(
                'matches' => 0,
                'engines_active' => 0,
                'engines_idle' => 0,
                'threshold' => $this->ssdeepThreshold(),
                'engines' => array(),
            );
        }
        $names = array();
        foreach (Value::asTypes($types) as $type) {
            $names[$type['type']] = true;
        }
        /*
         * Fixed order, whatever each engine's state is. §4.1 weighed
         * reordering by state — with ssdeep active, CIDR's idle line
         * sits above the block that ran — and kept the stable position
         * of each engine, which is worth more now that there are four.
         *
         * The typosquat engine does **not** replace the absent tree
         * line, which is what §12 planned. §12.1 priced the tree and
         * found it is two engines rather than one: a parent lookup at
         * 10–51 ms that MISP genuinely has no code path for, and a
         * child lookup at 4,533 ms that only a schema change makes
         * affordable. A permutation engine does not make a
         * parent-domain relation exist, so dropping the line would
         * quietly close a gap this section draws on purpose.
         */
        $engines = array(
            $this->cidrEngine($user, $value, $names),
            $this->ssdeepEngine($user, $value, $names),
            $this->typosquatEngine($user, $value, $names),
            array('id' => 'tld', 'state' => 'absent', 'rows' => array()),
        );
        $matches = 0;
        $active = 0;
        foreach ($engines as $engine) {
            $matches += count($engine['rows']);
            if ($engine['state'] === 'active') {
                $active++;
            }
        }
        return array(
            'matches' => $matches,
            'engines_active' => $active,
            'engines_idle' => count($engines) - $active,
            'threshold' => $this->ssdeepThreshold(),
            'engines' => $engines,
        );
    }

    /**
     * CIDR containment through the value table's IP index, under the
     * correlation engine's rules: an address lists the recorded blocks
     * holding it (`ip-src`/`ip-dst`), a block the single addresses inside
     * it (the four IP types), an IPv4 address is never inside an IPv6
     * block, and a block never lists another block.
     *
     * One row per block or address, from the newest occurrence the reader
     * may see; a block shows its newest CIDR_SHOWN addresses and counts
     * the ones read, `capped` when the CIDR_ROWS occurrence read ran out.
     *
     * @param array $user
     * @param string $value
     * @param array $types Type name => true
     * @return array
     */
    private function cidrEngine(array $user, $value, array $types)
    {
        $range = ValueFacetTool::ipRange($value);
        $this->model('Correlation');
        if ($range === null
            || empty(array_intersect(Correlation::IP_TYPES, array_keys($types)))
        ) {
            return array(
                'id' => 'cidr',
                'state' => 'not_applicable',
                'rows' => array(),
            );
        }
        $AttributeValue = $this->model('AttributeValue');
        $facets = $AttributeValue->facets();
        if ($range[2] === 128) {
            $direction = 'containing';
            $held = $facets->containing(array($range[0]))[0];
            $ids = array_keys(array_filter($held));
            $holderTypes = Correlation::CIDR_TYPES;
        } else {
            $direction = 'members';
            $ids = array();
            $found = $AttributeValue->getDataSource()->fetchAll(
                $facets->membersQuery($range),
                array(),
                array('cache' => false)
            );
            foreach ($found as $row) {
                $row = reset($row);
                $ids[] = (int)$row['value_id'];
            }
            $holderTypes = Correlation::IP_TYPES;
        }
        $result = array(
            'id' => 'cidr',
            'state' => 'active',
            'direction' => $direction,
            'rows' => array(),
            'total' => 0,
            'capped' => false,
        );
        if (empty($ids)) {
            return $result;
        }
        $texts = $AttributeValue->fetchValues($ids);
        $occurrences = $this->model('Value')->occurrencesForAny(
            $user,
            array_values($texts),
            array('types' => $holderTypes, 'limit' => self::CIDR_ROWS)
        );
        $wanted = array_flip(array_map('strval', $texts));
        $newest = array();
        foreach ($occurrences as $row) {
            // value1 is the address or block; value2 of a composite is a port
            $text = explode('|', (string)$row['Attribute']['value'], 2)[0];
            if (isset($wanted[$text]) && !isset($newest[$text])) {
                $newest[$text] = $row;
            }
        }
        $result['total'] = count($newest);
        $result['capped'] = count($occurrences) >= self::CIDR_ROWS;
        if ($direction === 'members') {
            $newest = array_slice($newest, 0, self::CIDR_SHOWN, true);
        }
        $width = ValueFacetTool::isIpv4($range[0]) ? 32 : 128;
        $out = array();
        foreach ($this->decorate($user, array_values($newest)) as $row) {
            $text = explode('|', (string)$row['Attribute']['value'], 2)[0];
            $prefix = ValueFacetTool::ipRange($text)[2] - ($width === 32 ? 96 : 0);
            $out[] = $this->nearRow(
                $row,
                $text,
                $prefix,
                ValueRelationTool::addressSpace($prefix, $width),
                $width
            );
        }
        if ($direction === 'containing') {
            usort($out, function ($a, $b) {
                return $b['prefix'] - $a['prefix'];
            });
        }
        $result['rows'] = $out;
        return $result;
    }

    /**
     * A near-match row, carrying the reporter and the audience of the
     * *other* value rather than of ours.
     *
     * **The record the matched value sits in**, too, and it costs no
     * query: `Value::CONTEXT_FIELDS` already contains `Object.id` and
     * `Object.name`, and both near-match queries already select
     * `Attribute.id` and `Attribute.object_id`. Without them the row
     * named an event and left the reader to find the attribute in it,
     * which on a `/8` in a 300-attribute event is a search.
     *
     * For CIDR this is *an* occurrence of the block rather than the only
     * one — the engine folds to one row per block on purpose — and it is
     * the same occurrence whose event, reporter and audience the rest of
     * the row already reports.
     *
     * @param array $row
     * @param string $label
     * @param int $closeness Prefix length, or an ssdeep score
     * @param string|null $addresses
     * @param int $width Address width, or 100 for a percentage
     * @return array
     */
    private function nearRow(array $row, $label, $closeness, $addresses,
        $width
    ) {
        return array(
            'block' => $label,
            'prefix' => (int)$closeness,
            'addresses' => $addresses,
            'width' => $width,
        ) + $this->matchContext($row);
    }

    /**
     * Where a matched occurrence sits, who reported it and who may see
     * it — the half of a near-match row that has nothing to do with
     * how the match was made.
     *
     * Split out because the typosquat engine's closeness is a
     * *permutation class* and not a number: it cannot fill `prefix`,
     * `addresses` or `width`, and filling them with zeroes to reuse
     * `nearRow` would hand the template a row whose bar renders 0% and
     * whose `Similarity` filter silently drops it. Two row shapes over
     * one context, rather than one row shape carrying three fields
     * that mean nothing on a third of its rows.
     *
     * @param array $row
     * @return array
     */
    private function matchContext(array $row)
    {
        $object = empty($row['Object']['id'])
            ? null
            : (int)$row['Object']['id'];
        return array(
            'event' => (int)$row['Attribute']['event_id'],
            'attribute' => (int)$row['Attribute']['id'],
            'object' => $object,
            'object_name' => $object === null
                ? null
                : $row['Object']['name'],
            'org' => $row['org'],
            'distribution' => $row['effective_distribution']['level'] === null
                ? 5
                : $row['effective_distribution']['level'],
        );
    }

    /**
     * Creator organisation and effective audience for a small row set.
     *
     * Two queries for the whole set rather than two per row, which is
     * §14.4's batching rule applied to the near-match section — a
     * section that can name a `/8` block held in a hundred events.
     *
     * @param array $user
     * @param array $rows
     * @return array
     */
    private function decorate(array $user, array $rows)
    {
        if (empty($rows)) {
            return $rows;
        }
        $orgs = $this->organisationNames($rows);
        $sharingGroups = $this->sharingGroupNames($user, $rows);
        foreach ($rows as &$row) {
            $orgId = (int)($row['Event']['orgc_id'] ?? 0);
            $row['org'] = isset($orgs[$orgId])
                ? $orgs[$orgId]
                : __('Unknown organisation');
            $row['effective_distribution'] =
                ValueStatsTool::effectiveDistribution($row, $sharingGroups);
        }
        unset($row);
        return $rows;
    }

    /**
     * ssdeep fuzzy similarity.
     *
     * Not applicable unless the value is itself an `ssdeep` attribute,
     * which is the state the brief designs the block around. When it
     * *is* one, the state depends on something the brief could not know
     * about: `ssdeep_fuzzy_compare()` is a PHP extension MISP does not
     * require, and without it the engine is present and inert.
     *
     * The comparison is made here rather than read, because MISP keeps
     * neither the score nor which engine wrote a correlation row —
     * `Correlation::ssdeepCorrelation` computes the number only to test
     * the threshold and then throws it away.
     *
     * @param array $user
     * @param string $value
     * @param array $types
     * @return array
     */
    private function ssdeepEngine(array $user, $value, array $types)
    {
        if (empty($types['ssdeep'])) {
            return array(
                'id' => 'ssdeep',
                'state' => 'not_applicable',
                'rows' => array(),
            );
        }
        if (!function_exists('ssdeep_fuzzy_compare')) {
            return array(
                'id' => 'ssdeep',
                'state' => 'unavailable',
                'rows' => array(),
            );
        }
        $threshold = $this->ssdeepThreshold();
        /*
         * **Compare first, decorate second.** The engine used to fetch
         * a hundred decorated rows and compare against those, so the
         * candidate set was chosen by `timestamp DESC` before a single
         * comparison had happened — a value whose partner was reported
         * last year was told, in the panel's own words, that it had
         * been compared against every `ssdeep` attribute and matched
         * none of them. Comparing is the cheap half: 793,170
         * comparisons across this whole instance take 398 ms, while
         * fetching the same rows decorated takes 34.6 ms for 1,399 of
         * them. So the whole population is compared, and only the
         * survivors are fetched with the context a row needs.
         */
        $candidates = $this->model('Value')->valuesOfType(
            $user,
            'ssdeep',
            $value,
            self::SSDEEP_CANDIDATE_CAP
        );
        $scores = array();
        foreach ($candidates['values'] as $candidate) {
            $score = @ssdeep_fuzzy_compare($value, $candidate);
            if ($score === false || $score < $threshold) {
                continue;
            }
            $scores[$candidate] = (int)$score;
        }
        $rows = array();
        if (!empty($scores)) {
            /*
             * Sized to the match set, not left on the default 200.
             * This fetch exists to put an event, a reporter and an
             * audience beside each matched hash, and it orders by
             * timestamp — so a hash held in three hundred events could
             * fill the window on its own and push another matched hash
             * out of it entirely. That would drop a row the engine had
             * already decided to show, which is the failure this task
             * is about. Twenty occurrences per match is generous
             * against a measured worst case of 45 matches; whatever
             * still fails to place is counted and reported below
             * rather than quietly missing.
             */
            $matches = $this->model('Value')->occurrencesForAny(
                $user,
                array_map('strval', array_keys($scores)),
                array(
                    'types' => array('ssdeep'),
                    'limit' => min(
                        self::SSDEEP_CANDIDATE_CAP,
                        max(200, count($scores) * 20)
                    ),
                )
            );
            /*
             * **One row per matched hash, not per occurrence of it.**
             * A pair is two values, so a hash held in three events is
             * one pair and not three — and the block above the table
             * counts pairs. Folding here is what makes that sentence
             * true, and it is the same fold `cidrEngine` performs for
             * the same reason: what the row names is the match, and
             * the event beside it is *an* occurrence of the far end
             * rather than the only one.
             */
            $seen = array();
            foreach ($this->decorate($user, $matches) as $match) {
                $matched = $match['Attribute']['value'];
                if (!isset($scores[$matched]) || isset($seen[$matched])) {
                    continue;
                }
                $seen[$matched] = true;
                $rows[] = $this->nearRow(
                    $match,
                    $matched,
                    $scores[$matched],
                    null,
                    100
                );
            }
        }
        usort($rows, function ($a, $b) {
            return $b['prefix'] - $a['prefix'];
        });
        return array(
            'id' => 'ssdeep',
            'state' => 'active',
            'rows' => $rows,
            'compared' => count($candidates['values']),
            'matched' => count($scores),
            'unplaced' => count($scores) - count($rows),
            'saturated' => $candidates['saturated'],
            'cap' => self::SSDEEP_CANDIDATE_CAP,
        );
    }

    /**
     * Spellings of this domain that somebody could mistake for it, and
     * which of them already exist on this instance.
     *
     * The fourth engine, and the only one that makes a claim MISP's
     * correlation engine never makes. That is deliberate and it is the
     * section's own contract rather than a stretch of it: a near-match
     * is *not equality*, every row names the engine that produced it,
     * and the panel says so above the rows. `careflrst.com` and
     * `caref1rst.com` are two unrelated attributes as far as
     * `default_correlations` is concerned, and one is a homoglyph of
     * the other; the section exists to say the second thing.
     *
     * **Generation is `DomainPermutationTool`'s and the check is
     * ours** — the split the tool's docblock argues for. Generation is
     * pure string work over the label, 0.2 ms for a typical name; the
     * check is one indexed `IN` over `value1`/`value2`, 7.3 ms mean
     * over 25 real values, which is a fifth of what this section
     * already costs. `24b-relationships.md` §12.1 measured both, and
     * measured the alternatives that are not here: matching inside
     * `url` values is a substring scan at 1,090 ms a candidate, so
     * `url` is not in the type list below.
     *
     * **The fetch is capped and the panel says so.** `occurrencesForAny`
     * orders by `Attribute.timestamp DESC`, so a saturated fetch means
     * *the most recent* occurrences, and a look-alike seen only in
     * older events would be missing without a word — which is §4.2's
     * finding about the ssdeep candidate cap, and the reason this one
     * is reported rather than merely bounded.
     *
     * @param array $user
     * @param string $value
     * @param array $types Type name => true
     * @return array
     */
    private function typosquatEngine(array $user, $value, array $types)
    {
        $domainTypes = array('domain', 'hostname', 'domain|ip');
        if (empty(array_intersect($domainTypes, array_keys($types)))) {
            return array(
                'id' => 'typosquat',
                'state' => 'not_applicable',
                'rows' => array(),
                'candidates' => 0,
            );
        }
        $candidates = DomainPermutationTool::candidates($value);
        if (empty($candidates)) {
            /*
             * The type says domain and the value cannot carry a
             * spelling — no dot, or already at the length limit. The
             * engine applies and generated nothing, which is a
             * different sentence from *found nothing* and the panel
             * draws it as one.
             */
            return array(
                'id' => 'typosquat',
                'state' => 'active',
                'rows' => array(),
                'candidates' => 0,
                'classes' => DomainPermutationTool::CLASSES,
                'saturated' => false,
                'cap' => self::TYPOSQUAT_FETCH_CAP,
            );
        }
        /*
         * `array_map('strval', ...)` for the reason §8.1 records: an
         * array key that looks like an integer comes back from
         * `array_keys()` as one, reaches the database bound as an
         * integer, and makes MariaDB convert the column and abandon
         * the `value1` index. A domain rarely looks numeric, `123.com`
         * does not — but `4.com` is a hostname somebody registered and
         * this generator emits its neighbours.
         */
        $rows = $this->model('Value')->occurrencesForAny(
            $user,
            array_map('strval', array_keys($candidates)),
            array(
                'types' => $domainTypes,
                'limit' => self::TYPOSQUAT_FETCH_CAP,
            )
        );
        $saturated = count($rows) >= self::TYPOSQUAT_FETCH_CAP;
        $order = array_flip(DomainPermutationTool::CLASSES);
        $out = array();
        $seen = array();
        foreach ($this->decorate($user, $rows) as $row) {
            /*
             * `domain|ip` stores the domain in `value1` and the address
             * in `value2`, and the row's `value` is the composite. The
             * look-alike is the domain half.
             */
            $matched = $row['Attribute']['value'];
            if (strpos($matched, '|') !== false) {
                $matched = explode('|', $matched)[0];
            }
            $matched = strtolower($matched);
            if (!isset($candidates[$matched]) || isset($seen[$matched])) {
                continue;
            }
            $seen[$matched] = true;
            $out[] = array(
                'block' => $matched,
                'class' => $candidates[$matched],
            ) + $this->matchContext($row);
        }
        usort($out, function ($a, $b) use ($order) {
            $byClass = $order[$a['class']] - $order[$b['class']];
            return $byClass !== 0
                ? $byClass
                : strcmp($a['block'], $b['block']);
        });
        return array(
            'id' => 'typosquat',
            'state' => 'active',
            'rows' => $out,
            'candidates' => count($candidates),
            'classes' => DomainPermutationTool::CLASSES,
            'saturated' => $saturated,
            'cap' => self::TYPOSQUAT_FETCH_CAP,
        );
    }

    /**
     * Analyst-asserted relationships on this value's occurrences.
     *
     * `Relationship` hangs off an `object_uuid`, so the list is the
     * union over the value's occurrence UUIDs in both directions,
     * de-duplicated by relationship UUID. `AnalystData::buildConditions`
     * is the ACL, which is the same predicate every other analyst-data
     * reader in MISP uses.
     *
     * **A claim has no text**, and that is a schema fact rather than a
     * decision taken here: `relationships` carries `relationship_type`,
     * the two endpoints, an author, a date and a distribution, and no
     * prose column at all — unlike `notes.note` and `opinions.comment`
     * beside it. Prose about a relationship is a Note attached to the
     * relationship, which is another fetch per claim and is deferred.
     * `24-relationships.md` §7.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    private function assertedClaims(array $user, $value,
        array $options = array()
    ) {
        $occurrences = $this->model('Value')->occurrenceUuidsFor(
            $user,
            $value,
            array_merge($options, array(
                'limit' => self::CLAIM_OCCURRENCE_CAP,
                'order' => self::OCCURRENCE_ORDER,
            ))
        );
        /*
         * The three things a claim about this value can be anchored
         * on, by uuid: the occurrence itself, the event it is in, or
         * the object it sits in.
         *
         * **Attribute alone was too narrow, and the omission showed.**
         * A claim written on an event — *event 4074 is linked-to
         * APT1* — is a claim about a neighbourhood this value is part
         * of, and the tab already counts a plain galaxy *tag* on that
         * same event. Counting the tag and dropping the claim ranked a
         * label above a deliberate, authored, typed statement. The
         * parent object is the same argument one level tighter: a
         * claim about the `domain-ip` object this address sits in is
         * about the thing the address is part of.
         *
         * The containers cost no query — `occurrenceUuidsFor` already
         * joins `Event` and `Object` to read them.
         */
        $near = array(
            'Attribute' => $occurrences,
            'Event' => array(),
            'Object' => array(),
            'Value' => $this->valueAnchorUuids($user, $value),
        );
        foreach ($occurrences as $occurrence) {
            if (!empty($occurrence['event_uuid'])) {
                $near['Event'][$occurrence['event_uuid']] = true;
            }
            if (!empty($occurrence['object_uuid'])) {
                $near['Object'][$occurrence['object_uuid']] = true;
            }
        }

        $claims = array();
        $orgs = array();
        if (!empty($occurrences) || !empty($near['Value'])) {
            $relationships = $this->model('Relationship');
            $conditions = $relationships->buildConditions($user);
            /*
             * Six branches rather than two, and still one query: a
             * claim names its ends by uuid and type, so each kind of
             * anchor is one equality pair per direction.
             */
            $anchors = array();
            foreach ($near as $kind => $set) {
                if (empty($set)) {
                    continue;
                }
                $uuids = array_keys($set);
                $anchors[] = array(
                    'Relationship.object_type' => $kind,
                    'Relationship.object_uuid' => $uuids,
                );
                $anchors[] = array(
                    'Relationship.related_object_type' => $kind,
                    'Relationship.related_object_uuid' => $uuids,
                );
            }
            $conditions['AND'][] = array('OR' => $anchors);
            /*
             * `Org` and `Orgc` are contained rather than left out, and
             * it is not decoration: `AnalystData::rearrangeOrganisation`
             * runs in `afterFind` and issues **one `Organisation` find
             * per row for each of them** when they are absent. Six
             * claims is twelve queries nobody asked for. Contained,
             * it is two joins.
             */
            $rows = $relationships->find('all', array(
                'conditions' => $conditions,
                'recursive' => -1,
                'contain' => array('Org', 'Orgc'),
                'order' => array('Relationship.modified DESC'),
            ));
            foreach ($rows as $row) {
                $claim = $this->claimFrom($user, $row, $near);
                if ($claim === null) {
                    continue;
                }
                $claim['spelled'] = null;
                if ($claim['anchor'] === 'Value') {
                    $nearUuid = $claim['direction'] === 'outbound'
                        ? $row['Relationship']['object_uuid']
                        : $row['Relationship']['related_object_uuid'];
                    $spelling = $near['Value'][$nearUuid] ?? null;
                    if ($spelling !== null && $spelling !== (string)$value) {
                        $claim['spelled'] = $spelling;
                    }
                }
                $claims[$row['Relationship']['uuid']] = $claim;
                $orgs[$claim['org']] = true;
            }
            $claims = $this->resolveClaimTargets($user, $claims);
        }
        return array(
            'total' => count($claims),
            'orgs' => count($orgs),
            // §14.6: no count of claims the reader may not see.
            'hidden' => 0,
            'occurrences' => count($occurrences),
            'capped' => count($occurrences) >= self::CLAIM_OCCURRENCE_CAP,
            /*
             * Not "these claims happen to have no text" — no claim on
             * any MISP instance has any, because the column does not
             * exist. The panel says so once, at the foot.
             */
            'prose_absent' => !empty($claims),
            'claims' => array_values($claims),
        );
    }

    /**
     * One `Relationship` row, read from whichever end this value is on.
     *
     * The direction is not a column: a row is *outbound* when one of
     * this value's occurrences is its source and *inbound* when the
     * occurrence is what somebody else pointed at. Reading it off the
     * two endpoint columns is the only way to know, and it is also what
     * decides which end is the interesting one to name.
     *
     * **Either end may be an occurrence, its event or its object.** The
     * near end is whichever of the two the caller nominated, and it is
     * matched on the pair — type *and* uuid — so an `Event` uuid can
     * never be mistaken for an `Attribute` one.
     *
     * @param array $user
     * @param array $row
     * @param array $near kind => uuid => anything, from `assertedClaims`
     * @return array|null
     */
    private function claimFrom(array $user, array $row, array $near)
    {
        $relationship = $row['Relationship'];
        $isNear = function ($kind, $uuid) use ($near) {
            return isset($near[$kind]) && isset($near[$kind][$uuid]);
        };
        $outbound = $isNear(
            $relationship['object_type'],
            $relationship['object_uuid']
        );
        if ($outbound) {
            $kind = $relationship['related_object_type'];
            $uuid = $relationship['related_object_uuid'];
            /*
             * `Relationship::afterFind` has already resolved the far
             * end — one ACL'd fetch per row, whether anybody wanted it
             * or not — so reading it here costs nothing extra. The near
             * end of an inbound claim is not resolved by anything, and
             * is asked for below.
             */
            $target = isset($relationship['related_object'])
                ? $relationship['related_object']
                : array();
        } elseif ($isNear(
            $relationship['related_object_type'],
            $relationship['related_object_uuid']
        )) {
            $kind = $relationship['object_type'];
            $uuid = $relationship['object_uuid'];
            $target = $this->model('Relationship')->getRelatedElement(
                $user,
                $kind,
                $uuid
            );
        } else {
            return null;
        }
        $author = self::claimOrg($relationship, 'Orgc');
        /*
         * Owner and creator are separate columns and are the same row
         * on an instance nothing has synced into. Compared on the
         * uuids rather than on the two contained names, because that
         * is the comparison the schema actually stores; the second
         * name is dropped when it says nothing, so the meta line grows
         * only where the two really differ.
         */
        $owner = $relationship['org_uuid'] === $relationship['orgc_uuid']
            ? null
            : self::claimOrg($relationship, 'Org');
        return array(
            'relationship_type' => empty($relationship['relationship_type'])
                ? __('related-to')
                : $relationship['relationship_type'],
            'direction' => $outbound ? 'outbound' : 'inbound',
            /*
             * Which of this value's three anchors the claim was
             * written on — the occurrence, its event, or its object.
             * The near end by construction, so it is read off
             * whichever column the direction says.
             */
            'anchor' => $outbound
                ? $relationship['object_type']
                : $relationship['related_object_type'],
            /*
             * The far end as fetched, not as rendered.
             * `resolveClaimTargets` turns it into the display shape
             * once the whole list is known, so the two lookups it
             * still needs are one query each rather than one per
             * claim.
             */
            'target' => array(
                'kind' => $kind,
                'uuid' => $uuid,
                'element' => $target,
            ),
            /*
             * There is no prose to render. Left as an empty string
             * rather than a placeholder sentence, so the block draws
             * nothing and the panel explains the absence once, at the
             * foot, instead of on every claim.
             */
            'text' => '',
            'org' => $author === null
                ? __('Unknown organisation')
                : $author['name'],
            // Null is *no link*, not *no name*: a claim whose author
            // organisation did not resolve still says who it credits.
            'org_id' => $author === null ? null : $author['id'],
            'owner' => $owner === null ? null : $owner['name'],
            'owner_id' => $owner === null ? null : $owner['id'],
            'date' => substr($relationship['modified'], 0, 10),
            'distribution' => (int)$relationship['distribution'],
        );
    }

    /**
     * One organisation off a claim, as a name and something to link.
     *
     * **Nested inside the row, not beside it.**
     * `AnalystData::rearrangeOrganisation` moves a contained `Orgc`
     * under the record and unsets the top-level key, so the obvious
     * read finds nothing and every claim silently reports *Unknown
     * organisation*.
     *
     * @param array $relationship
     * @param string $key `Org` or `Orgc`
     * @return array|null id and name, or null when it did not resolve
     */
    private static function claimOrg(array $relationship, $key)
    {
        if (empty($relationship[$key]['name'])) {
            return null;
        }
        return array(
            'id' => empty($relationship[$key]['id'])
                ? null
                : (int)$relationship[$key]['id'],
            'name' => $relationship[$key]['name'],
        );
    }

    /**
     * Fill in what each claim's far end actually is.
     *
     * `claimFrom` stops at whatever `getRelatedElement` handed back,
     * because two of the things a target line wants are not on it and
     * both are cheaper asked once for the whole list than once per
     * claim: a galaxy cluster, which `getRelatedElement` does not
     * resolve at all, and the creator organisation of an event target,
     * which arrives as a bare `orgc_id` and no name.
     *
     * Three queries for the section, each skipped when nothing needs it
     * — the same trade `assertedClaims` already makes by containing the
     * authors rather than letting `afterFind` fetch them per row. The
     * tags come first because the galaxy ones among them name clusters,
     * and those resolve in the same fetch as the clusters a claim
     * points *at* rather than in a second one.
     *
     * @param array $user
     * @param array $claims Keyed by relationship UUID
     * @return array The same claims, targets in display shape
     */
    private function resolveClaimTargets(array $user, array $claims)
    {
        $tags = $this->claimEventTags($claims);
        $clusters = $this->claimClusters($user, $claims,
            array_keys($tags['galaxy']));
        foreach ($claims as $key => $claim) {
            $target = $claim['target'];
            if ($target['kind'] === 'GalaxyCluster'
                && isset($clusters['by_uuid'][$target['uuid']])
            ) {
                $claims[$key]['target']['element']
                    = $clusters['by_uuid'][$target['uuid']];
            }
        }
        $lookups = array(
            'orgs' => $this->claimTargetOrgs($claims),
            'tags' => $tags['plain'],
            'galaxy_by_event' => $tags['galaxy_by_event'],
            'clusters' => $clusters['by_tag'],
            /*
             * Resolved once for every claim on the tab rather than per
             * card: `resolveFor()` memoises per request, so the cost is
             * one statement, and a plan built here cannot differ
             * between two claims on one page.
             */
            'plan' => ValueLabelPriority::planFor(
                ClassRegistry::init('AnalystProfile')->resolveFor($user)
            ),
        );
        foreach ($claims as $key => $claim) {
            $claims[$key]['target'] = $this->claimTarget(
                $claim['target']['kind'],
                $claim['target']['uuid'],
                $claim['target']['element'],
                $lookups
            );
        }
        return $claims;
    }

    /**
     * Every event a claim's far end sits in, tagged, in one fetch.
     *
     * An event target *is* the event; an attribute or object target
     * carries its own. Both are wanted, because a reader deciding
     * whether a claim matters wants what the event was labelled with —
     * and on this page the label is the tag.
     *
     * **Galaxy tags come back separately rather than being dropped.**
     * Everywhere else on this page they are filtered out, because the
     * Tags column does not draw them and a facet on something invisible
     * is not a facet. Here they are the point: a cluster is what an
     * analyst reaching for context is looking for, and the tag name is
     * how the event stores it.
     *
     * @param array $claims
     * @return array plain => event id => tag rows, galaxy => name => true
     */
    private function claimEventTags(array $claims)
    {
        $eventIds = array();
        foreach ($claims as $claim) {
            $id = self::claimEventId($claim['target']);
            if ($id !== null) {
                $eventIds[$id] = true;
            }
        }
        $found = array(
            'plain' => array(),
            'galaxy' => array(),
            'galaxy_by_event' => array(),
        );
        if (empty($eventIds)) {
            return $found;
        }
        $rows = $this->model('EventTag')->find('all', array(
            'conditions' => array(
                'EventTag.event_id' => array_keys($eventIds),
            ),
            'recursive' => -1,
            'contain' => array('Tag' => array('fields' => array(
                'Tag.id', 'Tag.name', 'Tag.colour', 'Tag.is_galaxy',
            ))),
        ));
        foreach ($rows as $row) {
            if (empty($row['Tag']['name'])) {
                continue;
            }
            $eventId = (int)$row['EventTag']['event_id'];
            if (empty($row['Tag']['is_galaxy'])) {
                $found['plain'][$eventId][] = $row['Tag'];
                continue;
            }
            $found['galaxy'][$row['Tag']['name']] = true;
            $found['plain'][$eventId] = isset($found['plain'][$eventId])
                ? $found['plain'][$eventId]
                : array();
        }
        /*
         * Which event each galaxy tag was on, kept beside the names so
         * the fetch above stays one query and the card can still say
         * *this* event's clusters rather than the section's.
         */
        foreach ($rows as $row) {
            if (empty($row['Tag']['is_galaxy'])) {
                continue;
            }
            $eventId = (int)$row['EventTag']['event_id'];
            $found['galaxy_by_event'][$eventId][] = $row['Tag']['name'];
        }
        return $found;
    }

    /**
     * The event id a target sits in, or is.
     *
     * @param array $target As claimFrom left it, element and all
     * @return int|null
     */
    private static function claimEventId(array $target)
    {
        $element = $target['element'];
        $kind = $target['kind'];
        if ($kind === 'Event' && !empty($element['Event']['id'])) {
            return (int)$element['Event']['id'];
        }
        if (!empty($element[$kind]['Event']['id'])) {
            return (int)$element[$kind]['Event']['id'];
        }
        return null;
    }

    /**
     * The galaxy clusters this section's claims point at, in one fetch.
     *
     * `Relationship::getRelatedElement` resolves a cluster one row at
     * a time and without the fields `claimTarget` reads, so this
     * section reads them itself. A claim naming a cluster that is not
     * stored here still renders as a bare UUID.
     *
     * `fetchGalaxyClusters` is the reader the galaxy pages themselves
     * use, so a cluster the viewer may not see stays unresolved rather
     * than appearing.
     *
     * **Two callers, one query.** A cluster a claim points at is looked
     * up by UUID; a cluster an event is tagged with is looked up by the
     * tag name that stores it. Both are `GalaxyCluster` rows under the
     * same ACL, so they are one `OR` rather than two round trips.
     *
     * @param array $user
     * @param array $claims
     * @param array $tagNames Galaxy tag names found on the events
     * @return array by_uuid => uuid => row, by_tag => tag name => row
     */
    private function claimClusters(array $user, array $claims,
        array $tagNames = array()
    ) {
        $uuids = array();
        foreach ($claims as $claim) {
            if ($claim['target']['kind'] === 'GalaxyCluster') {
                $uuids[$claim['target']['uuid']] = true;
            }
        }
        $found = array('by_uuid' => array(), 'by_tag' => array());
        $or = array();
        if (!empty($uuids)) {
            $or['GalaxyCluster.uuid'] = array_keys($uuids);
        }
        if (!empty($tagNames)) {
            $or['GalaxyCluster.tag_name'] = $tagNames;
        }
        // An empty `IN ()` is not a query worth sending.
        if (empty($or)) {
            return $found;
        }
        $rows = $this->model('GalaxyCluster')->fetchGalaxyClusters(
            $user,
            array('conditions' => array('OR' => $or))
        );
        foreach ($rows as $row) {
            $found['by_uuid'][$row['GalaxyCluster']['uuid']] = $row;
            if (!empty($row['GalaxyCluster']['tag_name'])) {
                $found['by_tag'][$row['GalaxyCluster']['tag_name']] = $row;
            }
        }
        return $found;
    }

    /**
     * Names for the organisation ids a target carries but cannot name.
     *
     * An `Attribute` or `Object` target arrives with its event's
     * creator organisation already nested — `Relationship::rearrangeData`
     * puts it there — while an `Event` target is fetched with no
     * contain at all and a cluster with only its galaxy. Those two hold
     * an id and nothing to print, and the id is what this fills in.
     *
     * @param array $claims
     * @return array id => name
     */
    private function claimTargetOrgs(array $claims)
    {
        $ids = array();
        foreach ($claims as $claim) {
            $kind = $claim['target']['kind'];
            $element = $claim['target']['element'];
            if (empty($element[$kind]['orgc_id'])) {
                // Also the galaxy clusters MISP ships, which are
                // nobody's: `orgc_id` 0 is not an organisation.
                continue;
            }
            $ids[(int)$element[$kind]['orgc_id']] = true;
        }
        if (empty($ids)) {
            return array();
        }
        return $this->model('Organisation')->find('list', array(
            'conditions' => array('Organisation.id' => array_keys($ids)),
            'fields' => array('Organisation.id', 'Organisation.name'),
            'recursive' => -1,
        ));
    }

    /**
     * The far end of a claim, as the panel draws it.
     *
     * Four kinds, four different things worth knowing, one shape: a
     * label, an id the view turns into a link, the event the target
     * lives in when it lives in one, the organisation behind it, and a
     * short list of facts that are only true of that kind.
     *
     * **A target that does not resolve keeps its UUID**, and that is
     * not a fallback nobody will hit — the verification instance has a
     * claim naming a galaxy cluster this instance does not hold. Then
     * `resolved` is false, the view gives it no link and says why: a
     * claim about something that cannot be shown is still a claim
     * somebody made, and dropping the row would hide it.
     *
     * @param string $kind
     * @param string $uuid
     * @param array $element As getRelatedElement returns it
     * @param array $lookups orgs, tags and clusters for the whole list
     * @return array
     */
    private function claimTarget($kind, $uuid, array $element,
        array $lookups
    ) {
        $target = array(
            'kind' => $kind,
            'uuid' => $uuid,
            'id' => null,
            'label' => $uuid,
            'event' => null,
            'org' => null,
            'facts' => array(),
            /*
             * Kind-specific rows for the hover, as label/value pairs.
             * Every one of them is a column already on the row that was
             * fetched — nothing here is worth a second query, and a
             * detail that would need one belongs on the page it lives
             * on rather than in a tooltip.
             */
            'detail' => array(),
            'distribution' => null,
            'tags' => array(),
            'clusters' => array(),
            'resolved' => false,
        );
        if (empty($element[$kind]['id'])) {
            return $target;
        }
        $row = $element[$kind];
        $target['id'] = (int)$row['id'];
        $target['org'] = self::claimTargetOrg($row, $lookups['orgs']);
        $target['resolved'] = true;
        if (isset($row['distribution'])) {
            $target['distribution'] = (int)$row['distribution'];
        }
        if ($kind === 'Event') {
            $target['label'] = sprintf('#%s %s', $row['id'], $row['info']);
            $target['facts'] = array(
                $row['date'],
                /*
                 * Said only when it is true. An unpublished event has
                 * not left this instance, so a claim pointing at one
                 * points somewhere nobody else can follow — and the
                 * silence in the other direction is what *published*
                 * means, which needs no word.
                 */
                empty($row['published']) ? __('unpublished') : '',
            );
            /*
             * The target *is* the event, so the event's own card rows
             * are the target's. An attribute or object target gets the
             * same shape one section below it, built by the same call —
             * what this panel says about an event should not depend on
             * how the reader arrived at it.
             */
            $event = $this->claimEventFacts($row, $lookups);
            $target['detail'] = $event['detail'];
            $target['tags'] = $event['tags'];
            $target['clusters'] = $event['clusters'];
        } elseif ($kind === 'Attribute') {
            $target['label'] = sprintf('%s · %s', $row['type'],
                $row['value']);
            $target['event'] = $this->claimTargetEvent($row, $lookups);
            $target['facts'] = array($row['category']);
            if (!empty($row['Object']['name'])) {
                // Where in the object, not just which object: an
                // attribute's meaning inside one is its relation.
                $target['facts'][] = sprintf('%s ↦ %s',
                    $row['Object']['name'], $row['object_relation']);
            }
            // No `Type` row: the label above the card is `type · value`,
            // so it would print the first half of it back.
            $target['detail'] = array(
                __('Category') => $row['category'],
                __('IDS flag') => empty($row['to_ids'])
                    ? __('not set')
                    : __('set'),
                __('Comment') => $row['comment'],
                __('First seen') => self::claimSeen($row, 'first_seen'),
                __('Last seen') => self::claimSeen($row, 'last_seen'),
            );
        } elseif ($kind === 'Object') {
            $target['label'] = sprintf('%s · #%s', $row['name'],
                $row['id']);
            $target['event'] = $this->claimTargetEvent($row, $lookups);
            $target['facts'] = array(
                empty($row['meta-category']) ? '' : $row['meta-category'],
            );
            $target['detail'] = array(
                __('Template') => sprintf('%s v%s', $row['name'],
                    $row['template_version']),
                __('Category') => $row['meta-category'],
                __('Comment') => $row['comment'],
                __('First seen') => self::claimSeen($row, 'first_seen'),
                __('Last seen') => self::claimSeen($row, 'last_seen'),
            );
        } elseif ($kind === 'GalaxyCluster') {
            $target['label'] = $row['value'];
            $target['facts'] = array(
                empty($row['Galaxy']['name'])
                    ? $row['type']
                    : $row['Galaxy']['name'],
                empty($row['source']) ? '' : $row['source'],
            );
            $target['detail'] = array(
                __('Tag') => $row['tag_name'],
                __('Description') => self::claimClip($row['description']),
            );
        } else {
            /*
             * A kind this panel has no link and no facts for. It keeps
             * its UUID rather than being drawn as something it is not.
             */
            $target['id'] = null;
            $target['org'] = null;
            $target['distribution'] = null;
            $target['resolved'] = false;
        }
        $target['facts'] = array_values(array_filter($target['facts']));
        // An empty column is not a row. A blank comment would otherwise
        // draw a label with nothing beside it on most attributes.
        $target['detail'] = array_filter($target['detail'], 'strlen');
        return $target;
    }

    /**
     * Prose cut to something a hover card can hold.
     *
     * @param string|null $text
     * @return string
     */
    private static function claimClip($text)
    {
        if (empty($text)) {
            return '';
        }
        if (mb_strlen($text) <= self::CLAIM_PROSE_CAP) {
            return $text;
        }
        return mb_substr($text, 0, self::CLAIM_PROSE_CAP - 1) . '…';
    }

    /**
     * The event a target lives in, when it lives in one.
     *
     * Free apart from its tags: `Relationship::getRelatedElement`
     * contains `Event` for both an Attribute and an Object target, so
     * the whole row is already here.
     *
     * @param array $row An Attribute or Object, as rearranged
     * @param array $lookups
     * @return array|null
     */
    private function claimTargetEvent(array $row, array $lookups)
    {
        if (empty($row['Event']['id'])) {
            return null;
        }
        $event = $this->claimEventFacts($row['Event'], $lookups);
        return array_merge($event, array(
            'id' => (int)$row['Event']['id'],
            'info' => $row['Event']['info'],
        ));
    }

    /**
     * What this panel says about an event, wherever it is drawn.
     *
     * One definition for the two places an event reaches the card — as
     * a claim's target, and as the event an attribute or object target
     * sits in. Two definitions would drift, and the reader would be
     * told different things about the same event depending on which
     * claim they hovered.
     *
     * @param array $row An `Event` row
     * @param array $lookups tags and clusters, keyed for the section
     * @return array detail, distribution, uuid, tags, clusters
     */
    private function claimEventFacts(array $row, array $lookups)
    {
        $id = (int)$row['id'];
        $analysis = $this->model('Event')->analysisLevels;
        $level = (int)$row['analysis'];
        /*
         * `attribute_count` is denormalised and can lag, and it is
         * still the right number to print: it is what MISP's own event
         * index shows for the same event, so a reader who follows the
         * link and counts something else has found a discrepancy in the
         * instance rather than in this card.
         */
        $facts = array(
            'detail' => array(
                __('Date') => $row['date'],
                __('Analysis') => isset($analysis[$level])
                    ? __($analysis[$level])
                    : '',
                __('Attributes') => $row['attribute_count'],
            ),
            'distribution' => isset($row['distribution'])
                ? (int)$row['distribution']
                : null,
            'uuid' => isset($row['uuid']) ? $row['uuid'] : null,
            /*
             * Ordered by the reader's profile, item by item, because
             * this card draws a chip per tag rather than a group per
             * namespace (`04-label-surfaces.md` §1.3, D51). The key a
             * profile lists a tag by is its namespace, which no Tag row
             * carries, so it is stamped on the way past.
             */
            'tags' => self::claimLabels(
                isset($lookups['tags'][$id])
                    ? $lookups['tags'][$id]
                    : array(),
                isset($lookups['plan']) ? $lookups['plan'] : null
            ),
            'clusters' => array(),
        );
        $facts['detail'] = array_filter($facts['detail'], 'strlen');
        /*
         * A galaxy tag names a cluster the reader may not be allowed to
         * read. `fetchGalaxyClusters` is the ACL, so a name with no row
         * behind it is dropped rather than printed raw — the tag string
         * would disclose the cluster this instance is withholding.
         */
        if (empty($lookups['galaxy_by_event'][$id])) {
            return $facts;
        }
        foreach ($lookups['galaxy_by_event'][$id] as $name) {
            if (!isset($lookups['clusters'][$name])) {
                continue;
            }
            $cluster = $lookups['clusters'][$name]['GalaxyCluster'];
            $facts['clusters'][] = array(
                'id' => (int)$cluster['id'],
                'value' => $cluster['value'],
                'galaxy' => empty($cluster['Galaxy']['name'])
                    ? $cluster['type']
                    : $cluster['Galaxy']['name'],
                // The key a profile lists this galaxy by, which the
                // display name beside it is not (`04-label-surfaces.md`
                // §1.3).
                'key' => $cluster['type'],
            );
        }
        $facts['clusters'] = ValueLabelPriority::labels(
            $facts['clusters'],
            isset($lookups['plan']) ? $lookups['plan'] : null,
            ValueLabelPriority::GALAXIES
        );
        return $facts;
    }

    /**
     * A claim card's tag chips, in the reader's order.
     *
     * The card draws one chip per tag, so this is `labels()` and not
     * `order()` — D51's distinction. The namespace is stamped here
     * because a `Tag` row does not carry one and the priority class
     * takes the key from the caller.
     *
     * **No absence is drawn from it** (D54): a pinned taxonomy missing
     * from the event at a claim's far end is a judgment about an event
     * this page is citing rather than assessing, and the value's own
     * context card is where a missing pin is reported.
     *
     * @param array $tags Flat `Tag` rows
     * @param array|null $plan A plan, or null for today's order
     * @return array
     */
    private static function claimLabels(array $tags, $plan)
    {
        if (empty($tags)) {
            return $tags;
        }
        foreach ($tags as $at => $tag) {
            $tags[$at]['key'] = ValueLabelPriority::namespaceOf(
                isset($tag['name']) ? $tag['name'] : null
            );
        }
        return ValueLabelPriority::labels(
            $tags,
            $plan,
            ValueLabelPriority::TAXONOMIES
        );
    }

    /**
     * A first/last seen stamp, only where one was actually recorded.
     *
     * @param array $row
     * @param string $key
     * @return string
     */
    private static function claimSeen(array $row, $key)
    {
        if (empty($row[$key])) {
            return '';
        }
        return substr(str_replace('T', ' ', $row[$key]), 0, 19);
    }

    /**
     * The organisation behind a target, from whichever end carries it.
     *
     * `Relationship::rearrangeData` nests the event's creator
     * organisation under an Attribute or Object target, so those two
     * arrive named. An Event target and a cluster arrive with an id,
     * and `claimTargetOrgs` is what turned that into a name.
     *
     * @param array $row
     * @param array $orgs id => name
     * @return array|null
     */
    private static function claimTargetOrg(array $row, array $orgs)
    {
        if (!empty($row['Organisation']['name'])) {
            return array(
                'id' => (int)$row['Organisation']['id'],
                'name' => $row['Organisation']['name'],
            );
        }
        $id = empty($row['orgc_id']) ? 0 : (int)$row['orgc_id'];
        return isset($orgs[$id])
            ? array('id' => $id, 'name' => $orgs[$id])
            : null;
    }

    /**
     * The engine settings this tab depends on, and where this value
     * stands against each of them.
     *
     * @param array $user
     * @param string $value
     * @return array
     */
    private function relationSettings(array $user, $value)
    {
        return array(
            'correlation_limit' => (int)$this
                ->model('OverCorrelatingValue')->getLimit(),
            'ssdeep_threshold' => $this->ssdeepThreshold(),
            'excluded' => $this->model('Correlation')
                ->isValueExcluded($value),
            'over_correlating' => $this->overCorrelating($value),
            /*
             * Section four is governed by the feed cache rather than by
             * the correlation engine, and its rules are just as
             * invisible from the page: which sources are cached at all,
             * which of them this reader may be told about, and the
             * per-source event cap. Config and role only — no value.
             */
            'external' => $this->externalVisibility($user),
        );
    }

    /**
     * The tab's arithmetic, over whichever sections the caller has
     * already built.
     *
     * `correlations` is co-occurrence plus near-match and never
     * includes the claims — an analyst assertion is a `Relationship`
     * row and not a correlation, which is the distinction the rail
     * card exists to state.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @param array $parts Any of `cooccurrence`, `near`, `asserted`
     * @return array
     */
    private function relationSummary(array $user, $value, array $options,
        array $parts
    ) {
        $cooccurrence = isset($parts['cooccurrence'])
            ? (int)$parts['cooccurrence']['distinct_values']
            : 0;
        /*
         * §10.2's labels, counted beside `correlations` and never into
         * it — the same rule the `external` note below states rather
         * than a new one. `correlations` is *values related to this
         * one*, and a galaxy cluster is no more a value than a remote
         * event is; summing them would invent a strength out of two
         * units, and inflate the one number on the rail that is meant
         * to be comparable between values.
         */
        $labels = isset($parts['cooccurrence']['labels']['total'])
            ? (int)$parts['cooccurrence']['labels']['total']
            : 0;
        $near = isset($parts['near'])
            ? (int)$parts['near']['matches']
            : 0;
        $asserted = isset($parts['asserted'])
            ? (int)$parts['asserted']['total']
            : 0;
        /*
         * Remote events, which is what section four's own header counts,
         * and deliberately not added to `correlations`: that total is
         * *values* related to this one, and an event is not a value.
         * Summing them would invent a strength out of two units, which
         * is the blend §5 of the tab brief exists to prevent.
         */
        $external = isset($parts['external'])
            ? (int)$parts['external']['events']
            : 0;
        /*
         * Object joins and typed references, counted beside the other
         * notions and — like `external` — deliberately not added into
         * `correlations`. A sibling is a value and could be summed; a
         * reference points at an object, which is not one. Keeping the
         * two apart is the same rule that keeps a remote event out of
         * the total.
         */
        $siblings = isset($parts['cooccurrence']['siblings'])
            ? (int)$parts['cooccurrence']['siblings']['total']
            : 0;
        $dated = isset($parts['cooccurrence']['dated'])
            ? (int)$parts['cooccurrence']['dated']['total']
            : 0;
        $references = isset($parts['references'])
            ? (int)$parts['references']['total']
            : 0;
        /*
         * Whether each of the three is a floor rather than a total. The
         * panels themselves print `≥` on a capped join, and the rail
         * card stating a bare number beside a panel qualifying it would
         * be the two disagreeing about how much they saw — which is the
         * one thing this card exists to prevent.
         */
        $siblingsCapped = !empty(
            $parts['cooccurrence']['siblings']['cap']['applied']
        );
        $datedCapped = !empty(
            $parts['cooccurrence']['dated']['cap']['applied']
        );
        $referencesCapped = !empty($parts['references']['cap']['applied']);
        $externalSources = isset($parts['external'])
            ? (int)$parts['external']['counts']['feeds']
                + (int)$parts['external']['counts']['servers']
            : 0;
        return array(
            'correlations' => $cooccurrence + $near,
            'cooccurrence' => $cooccurrence,
            /*
             * §10.2's label neighbours, counted apart from the values
             * for the reason given where they are split.
             */
            'labels' => $labels,
            'near' => $near,
            'external' => $external,
            'external_sources' => $externalSources,
            'asserted' => $asserted,
            'siblings' => $siblings,
            'dated' => $dated,
            'references' => $references,
            'siblings_capped' => $siblingsCapped,
            'dated_capped' => $datedCapped,
            'references_capped' => $referencesCapped,
            /*
             * The viewer's own occurrence count and not
             * `over_correlating_values.occurrence`. That column is
             * instance-wide, so printing it would state a number about
             * rows the reader may not see — §14.6 — and it is 0 on
             * every one of the 1,622 rows the verification instance
             * holds anyway, because it is filled by a separate job.
             */
            'recorded' => $this->summaryFor($user, $value,
                $options)['occurrences'],
        );
    }

    /**
     * The URL-safe encoding `ValuesController` decodes.
     *
     * Duplicated from the controller's private `encodeValue` rather
     * than shared, because sharing it would mean the model importing
     * the controller. Three characters of alphabet; if a third caller
     * appears it moves to `Value`.
     *
     * @param string $value
     * @return string
     */
    private static function b64($value)
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    /**
     * @return int
     */

    /**
     * The Timeline tab: one axis, everything MISP can date onto it, and
     * a strip for what it cannot.
     *
     * One endpoint and one method, and the argument is the brush — a
     * single control driving two regions that must both exist when it
     * fires. Going live changes nothing about that.
     *
     * **The tab's one-array invariant lives here.** The spine's bars,
     * the lanes' counts and the chronology's list were three aggregates
     * over one array derived in the template, so the panel could not
     * state two numbers that disagree. `443` breaks that: 172,426 audit
     * rows before a single sighting is added. So the array is capped at
     * `TIMELINE_ROW_CAP` and the counts come from aggregates over the
     * whole scoped set beside it — two grains of one query rather than
     * two queries, and the panel states both numbers.
     *
     * The rejected alternative was to cap the entry set and let the
     * template keep deriving: a spine drawn from 1,000 of 172,426 rows
     * is a chart of the last fortnight labelled as a year.
     *
     * Every lane's rows come from MISP's own ACL'd fetchers; only the
     * audit counts use an aggregate of their own, over an id set
     * `Value` has already scoped. The context issues one
     * `fetchSimpleEvents` for every event the value sits in, never one
     * call per event.
     *
     * **`window` is what makes the cap survivable.** Without it the
     * fragment is the newest `TIMELINE_ROW_CAP` entries and a reader
     * who brushes the spine past them has a chart with no chronology
     * under it. Measured at the 300 this shipped with: `8.8.8.8`'s
     * newest 300 began at 2025-11-16, so eleven of its 23 bars were
     * unreadable — and that finding is what raised the cap afterwards,
     * which is why the value no longer shows it. With the window the
     * panel can be asked again, and the same cap then means the newest
     * cap-many *of that window*: `193.161.193.99` still needs it at
     * 1,000, being 2,256 entries of which 1,256 land in the first two
     * days of a 280-day range. The counts stay whole either way, so
     * the answer is a different list under the same chart rather than
     * a different chart.
     *
     * @param array $user
     * @param string $value
     * @param array $options `types` reaches `Value`; `window` is a
     *                       `from`/`to` pair of `Y-m-d` scoping the
     *                       listed rows and nothing else
     * @return array
     */
    public function forTimeline(array $user, $value,
        array $options = array()
    ) {
        $this->forget($value);
        $context = $this->timelineContext($user, $value, $options);
        /*
         * A value that exists only as a proposal still has something to
         * place: the proposals the reader can already see listed under
         * the Occurrences tab.
         */
        if (empty($context['occurrences'])
            && empty($this->timelineProposalEntries($user, $value)['entries'])
        ) {
            /*
             * **Null, and deliberately not an empty timeline.** An empty
             * one would be an axis, a set of empty bins and seven lanes
             * over a value this reader holds no occurrence of — which
             * invents a period of silence that never happened, and
             * invents it in the one direction that misleads: a reader
             * cannot tell a value nothing was ever filed about from a
             * value they cannot see.
             *
             * The panel's own no-timeline state says *nothing to place
             * on an axis*, which is true either way, and it is the same
             * sentence for every reader — so it discloses nothing about
             * which of the two it is.
             */
            return array('value' => $value, 'timeline' => null);
        }
        /*
         * The window the caller asked for, or none.
         *
         * It reaches the lanes rather than being applied to their
         * output, because every one of them caps its rows: the cap is
         * *the newest cap-many*, so the newest 1,000 of a busy value
         * are a fortnight and the window a reader brushed two years
         * back would come back empty however the panel filtered
         * afterwards. Filtered on the way in, the same cap means the
         * newest 1,000 of what the reader is looking at.
         *
         * The **counts are never windowed**, and that is what keeps the
         * spine the whole value's: the day map, the per-source totals
         * and the range are tallied over every row each lane found, so
         * a chronology fetched for November 2024 still draws two years
         * of bars above it. `in_window` below is the one count that
         * takes the window, and it is a sum over that same whole map.
         *
         * The seen lane is deliberately not windowed. It caps at 25
         * bars and takes the *oldest* of them, so its rows are cheap to
         * carry whole and the client already filters marks to the
         * window; windowing it would only make its sub-label — three
         * whole-value numbers — start describing a slice.
         */
        $asked = isset($options['window']) && is_array($options['window'])
            ? $options['window']
            : null;
        $audit = $this->timelineAuditLanes($context, $asked);
        $spans = $this->timelineSpanEntries($context);
        $objectDates = $this->timelineObjectDateEntries($user, $context,
            $asked);
        $tagState = $this->timelineTagState($user, $value, $context,
            $options);
        $lanes = array(
            $this->timelineSightingEntries($user, $value, $options, $asked),
            $this->timelinePublicationEntries($context, $asked),
            $this->timelineAnalystEntries($user, $value, $context, $asked),
            $audit[0],
            $audit[1],
            $spans,
            /*
             * The two the coverage survey owed this tab. Both are
             * additive: neither reads anything the six above read, and
             * a reader who was looking at this tab yesterday sees the
             * same seven lanes plus two more.
             */
            $this->timelineProposalEntries($user, $value, $asked),
            $this->timelineReportEntries($user, $context, $asked),
            /*
             * The third place a date about this value lives — the
             * object's own `datetime` fields. Additive like the two
             * above it, and the last source `06-timeline.md` §16 and
             * `24-relationships.md` §26.7 left off this axis.
             */
            $objectDates,
        );
        $entries = array();
        foreach ($lanes as $lane) {
            foreach ($lane['entries'] as $entry) {
                $entries[] = $entry;
            }
        }
        /*
         * Ascending, because that is what the panel's three readings
         * expect: the spine bins forward, the lane axis runs left to
         * right, and the chronology reverses it once for itself.
         */
        usort($entries, function ($a, $b) {
            return strcmp($a['at'], $b['at']);
        });

        /*
         * **Counted before the cap, shipped after it**, and the order
         * is the whole point. The counts describe every dated thing the
         * viewer may see; the array describes what the fragment can
         * carry. Doing it the other way round draws a chart of the last
         * fortnight and labels it a year, and it is not a hypothetical:
         * `443` sits in 1,844 events, so its publication lane alone
         * offered 1,847 uncapped entries.
         */
        $counts = $this->timelineCounts($lanes, $entries);
        /*
         * A requested window is the panel's window; otherwise the
         * value's own default one. `requested` travels with it because
         * the panel says different things about the two: a fragment
         * fetched for a window lists everything in it and states the
         * window's numbers, while the default one lists the newest of
         * the value's and states the value's.
         */
        $window = ($asked === null
            ? $this->timelineWindow($counts)
            : $asked) + array('requested' => $asked !== null);
        $counts['in_window'] = $this->timelineWindowCounts(
            $counts['by_day'],
            $window,
            $counts['spans']
        );
        $entries = $this->timelineCap($entries);
        return array(
            'value' => $value,
            'timeline' => array(
                'entries' => $entries,
                /*
                 * The tag set, dated. Read before `timelineUndated`,
                 * which now lists only the tags this could not place —
                 * one `ownTagsFor` between them, not two.
                 */
                'tags' => $tagState,
                'undated' => $this->timelineUndated($user, $value, $context,
                    $options, $tagState),
                'window' => $window,
                'range' => array(
                    'from' => $counts['first'],
                    'to' => $counts['last'],
                ),
                /*
                 * The axis's left edge answers *when the record of this
                 * value starts*, which is not the same question as
                 * *when did this instance first hold it* — and the
                 * second is the one a reader asks first. Nothing on
                 * this tab named it before.
                 */
                'first_here' => $this->timelineFirstHere(
                    $context,
                    $counts,
                    isset($audit[0]['first_add'])
                        ? $audit[0]['first_add']
                        : null
                ),
                'audit_recorded' => (bool)Configure::read(
                    'MISP.log_new_audit'
                ),
                'counts' => $counts,
                // From the lane itself and not from its index in the
                // list, which a sixth lane has already moved once.
                'spans' => $spans['spans'],
                'objdates' => $objectDates['objdates'],
            ),
        );
    }

    /**
     * What every lane needs, fetched once.
     *
     * Three reads and no more: the occurrence id set, the object id set,
     * and **one** `fetchSimpleEvents` over every event the value sits
     * in. That last one carries five jobs — the publications lane's two
     * columns, the creator organisation every row is attributed to, the
     * event titles the rows name, the event UUIDs the analyst union
     * needs, and the ACL'd event id list the audit reader scopes by —
     * which is why it is one call and not five.
     *
     * The occurrence set is uncapped, and that is deliberate: it is what
     * the audit aggregate and the span count are *of*, so capping it
     * would make both numbers describe a sample while the panel labelled
     * them a total. It costs 1,067 ms on `443` to a site admin and
     * 152 ms to an org admin, and it is the largest number on this
     * endpoint.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array `occurrences`, `objects`, `events`, `scope`
     */
    private function timelineContext(array $user, $value, array $options)
    {
        $valueModel = $this->model('Value');
        $occurrences = $valueModel->occurrenceIdsFor($user, $value, $options);
        $objects = $valueModel->occurrenceObjectIdsFor($user, $value,
            $options);

        $eventIds = array();
        foreach ($occurrences as $occurrence) {
            $eventIds[(int)$occurrence['event_id']] = true;
        }
        $events = array();
        if (!empty($eventIds)) {
            $rows = $this->model('Event')->fetchSimpleEvents(
                $user,
                array('conditions' => array(
                    'Event.id' => array_keys($eventIds),
                )),
                true
            );
            foreach ($rows as $row) {
                $event = $row['Event'];
                $events[(int)$event['id']] = array(
                    'id' => (int)$event['id'],
                    'uuid' => $event['uuid'],
                    'info' => $event['info'],
                    'org' => isset($row['Orgc']['name'])
                        ? $row['Orgc']['name']
                        : __('Unknown organisation'),
                    'published' => !empty($event['published']),
                    'first_publication' => (int)$event['first_publication'],
                    'publish_timestamp' => (int)$event['publish_timestamp'],
                    /*
                     * The level a record on this event inherits when it
                     * states none of its own — which is what an event
                     * report almost always does. Free: this fetch
                     * already reads every event column and the lane
                     * that needs it would otherwise re-read the same
                     * rows.
                     */
                    'distribution' => (int)$event['distribution'],
                    'sharing_group_id' => (int)$event['sharing_group_id'],
                );
            }
        }

        /*
         * The event id list is the one `fetchSimpleEvents` returned and
         * not the one the occurrences named. `Event::createEventConditions`
         * is the same predicate `MispAttribute::buildConditions` embeds,
         * so it can never be stricter and the difference can never be
         * non-empty — taking the narrower of the two anyway is what
         * makes that a checkable claim rather than an assumption.
         */
        return array(
            'occurrences' => $occurrences,
            'objects' => $objects,
            'events' => $events,
            'scope' => array(
                'attributes' => array_map('intval',
                    array_keys($occurrences)),
                'objects' => array_map('intval', array_keys($objects)),
                'events' => array_keys($events),
            ),
            /*
             * Carried here because this is the last point in either
             * tab's call chain that still holds `$user` — the audit
             * lanes and the History sections are both reached through
             * methods that take a context and a window and nothing
             * else. Computing it here also means one `User` read per
             * request rather than one per scope statement.
             */
            'actor_scope' => $this->auditActorScope($user),
        );
    }

    /**
     * The sightings lane, from phase 23's context and no second read.
     *
     * `ValueStatsTool::sightingList` is the same call the Sightings
     * table makes, over the same `sightingContext`, so a sighting on
     * this axis and the row for it one tab over cannot disagree.
     *
     * The count is the viewer's, as every count on this page is, and
     * this tab must not restate it as the instance's.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    private function timelineSightingEntries(array $user, $value,
        array $options, array $window = null
    ) {
        $context = $this->sightingContext($user, $value, $options);
        $rows = ValueStatsTool::sightingList(
            $context['sightings'],
            $context['sighted']
        );
        /*
         * 0, 1, 2 as integers and not as constants, because MISP has
         * none: `Sighting` names its policies and not its types, and
         * `ValueStatsTool` reads `$row['Sighting']['type'] === 1`
         * directly in three places. A private vocabulary here would be
         * a second spelling of a number the tool beside it spells
         * plainly.
         */
        $sources = array(
            0 => 'sighting',
            1 => 'false_positive',
            2 => 'expiration',
        );
        $notes = array(
            1 => __(
                'Type 1. Corroborates nothing: the relevance clock'
                . ' counts type-0 reports only, so a contradiction'
                . ' cannot extend the value\'s lifetime.'
            ),
            2 => __(
                'Type 2. An organisation retiring the value, not'
                . ' contradicting it.'
            ),
        );
        $entries = array();
        $total = count($rows);
        $n = 0;
        foreach ($rows as $row) {
            $n++;
            $type = (int)$row['type'];
            $title = $row['org'];
            if ($row['source'] !== null) {
                $title = sprintf(
                    __('%1$s — source %2$s'),
                    $row['org'],
                    $row['source']
                );
            }
            $entries[] = array(
                'at' => $row['date'] . ':00',
                'source' => isset($sources[$type])
                    ? $sources[$type]
                    : 'sighting',
                'precision' => 'exact',
                'title' => $title,
                'note' => isset($notes[$type])
                    ? $notes[$type]
                    : sprintf(__('Sighting %1$s of %2$s'), $n, $total),
                'org' => $row['org'],
                'ref' => array(
                    'kind' => 'attribute',
                    'attribute' => $row['against']['attribute'],
                    'event' => $row['against']['event'],
                ),
                'span_to' => null,
            );
        }
        return $this->timelineLane(
            $entries,
            array('sighting', 'false_positive', 'expiration'),
            array(),
            $window
        );
    }

    /**
     * Two points per event, and never a history.
     *
     * `events.first_publication` and `events.publish_timestamp` are the
     * only two publications MISP keeps; an event published five times
     * still has exactly these, so *two per event* is a ceiling MISP sets
     * and not a promise this lane makes. Whether `ACTION_PUBLISH` audit
     * rows should fill in the rest is open — the reader below already
     * has those rows in hand, which is what makes it a live question
     * rather than an academic one.
     *
     * **Epoch zero is excluded rather than plotted in 1970**, and it is
     * common: 4,235 of the instance's 4,287 events carry a publish
     * timestamp and only 2,858 a first publication. Three events carry a
     * first publication with no current one, which is why each column is
     * tested on its own rather than one gating the other.
     *
     * @param array $context From `timelineContext`
     * @return array
     */
    private function timelinePublicationEntries(array $context,
        array $window = null
    ) {
        $entries = array();
        foreach ($context['events'] as $event) {
            $first = $event['first_publication'];
            $last = $event['publish_timestamp'];
            $points = array();
            if ($first > 0) {
                $points['first'] = $first;
            }
            if ($last > 0) {
                $points['last'] = $last;
            }
            if (empty($points)) {
                continue;
            }
            $title = sprintf(
                __('event %1$s — %2$s'),
                $event['id'],
                $event['info']
            );
            $once = count($points) === 1
                || $points['first'] === $points['last'];
            foreach ($points as $which => $stamp) {
                if ($once && $which === 'last'
                    && isset($points['first'])
                ) {
                    continue;
                }
                $entries[] = array(
                    'at' => gmdate('Y-m-d H:i:s', $stamp),
                    'source' => 'publication',
                    'precision' => 'first_last',
                    'title' => $title,
                    'note' => $this->publicationNote($which, $points,
                        $once),
                    'org' => $event['org'],
                    'ref' => array(
                        'kind' => 'event',
                        'attribute' => null,
                        'event' => $event['id'],
                    ),
                    'span_to' => null,
                );
            }
        }
        return $this->timelineLane($entries, array('publication'),
            array(), $window);
    }

    /**
     * What one publication point can honestly say about the other.
     *
     * @param string $which `first` or `last`
     * @param array $points Whichever of the two are non-zero
     * @param bool $once
     * @return string
     */
    private function publicationNote($which, array $points, $once)
    {
        if ($once) {
            return __('Its only publication.');
        }
        if ($which === 'first') {
            return sprintf(
                __(
                    'Its first publication. The latest is %s, and'
                    . ' nothing between the two is recorded.'
                ),
                gmdate('Y-m-d', $points['last'])
            );
        }
        if (!isset($points['first'])) {
            /*
             * A publish timestamp with no first publication. 1,429 of the
             * events on the verification instance are in this state, which is
             * what an event published before MISP grew the column looks like.
             */
            return __(
                'Its latest publication. MISP records no first'
                . ' publication for this event.'
            );
        }
        return sprintf(
            __(
                'Its latest publication. The first was %s, and nothing'
                . ' between the two is recorded.'
            ),
            gmdate('Y-m-d', $points['first'])
        );
    }

    /**
     * The edit lane, and which of its two shapes it takes.
     *
     * With `MISP.log_new_audit` on, one row per logged change over the
     * value's own occurrences, objects and events. With it off, one point per
     * occurrence from `attributes.timestamp`, which says *when* an
     * occurrence last changed and never *what* or *how many times*: the
     * title names the occurrence and stops, because an edit row claiming
     * a field and a value would be inventing the record this tab exists
     * to be honest about.
     *
     * **Both branches ship and both are verified.** The hatched one is
     * what a default MISP shows, so it is the more common state in the
     * world and the less common one on the instance this was measured
     * against — which is exactly how it would come to ship untested.
     *
     * @param array $context From `timelineContext`
     * @return array
     */
    private function timelineEditEntries(array $context,
        array $window = null
    ) {
        if (!Configure::read('MISP.log_new_audit')) {
            $entries = array();
            foreach ($context['occurrences'] as $id => $occurrence) {
                $event = isset($context['events'][$occurrence['event_id']])
                    ? $context['events'][$occurrence['event_id']]
                    : null;
                $entries[] = array(
                    'at' => gmdate('Y-m-d H:i:s', $occurrence['timestamp']),
                    'source' => 'edit',
                    'precision' => 'latest',
                    'title' => sprintf(
                        __('attribute %1$s in event %2$s — last modified'),
                        $id,
                        $occurrence['event_id']
                    ),
                    'note' => __(
                        'attributes.timestamp. What changed, and every'
                        . ' earlier edit, is not recorded.'
                    ),
                    'org' => $event === null ? null : $event['org'],
                    'ref' => array(
                        'kind' => 'attribute',
                        'attribute' => (int)$id,
                        'event' => (int)$occurrence['event_id'],
                    ),
                    'span_to' => null,
                );
            }
            return $this->timelineLane(
                $entries,
                array('edit'),
                array('recorded' => false),
                $window
            );
        }

        $counts = $this->auditCountsFor($context['scope']);
        $rows = $this->auditRowsFor(
            $context['scope'],
            array(
                'limit' => self::TIMELINE_ROW_CAP,
                /*
                 * The one lane whose cap is applied by the database
                 * rather than in PHP, so its window has to reach the
                 * query. Without it a windowed fetch would read the
                 * newest 1,000 rows of the whole scoped set and then
                 * find none of them in the window it was asked for.
                 */
                'window' => $window,
                // Who this reader may see named. `27-history.md` §8.
                'actor_scope' => isset($context['actor_scope'])
                    ? $context['actor_scope']
                    : null,
            )
        );
        $entries = array();
        foreach ($rows as $row) {
            $entries[] = $this->timelineEditEntry($row, $context);
        }
        return array(
            'entries' => $entries,
            'total' => $counts['total'],
            'sources' => array('edit'),
            'recorded' => true,
            // Authoritative: the rows above are capped and these are
            // not, so `timelineCounts` bins the spine from here.
            'by_day' => $counts['by_day'],
            'by_action' => $counts['by_action'],
            'first' => $counts['first'],
            'last' => $counts['last'],
            /*
             * For `timelineAuditLanes`, which is this method's only
             * caller and slices these three groups into two lanes. It
             * takes the key back off before the lane ships.
             */
            'audit_counts' => $counts,
        );
    }

    /**
     * The audit log's rows as **two** lanes: what changed the record,
     * and what was tagged onto it.
     *
     * One read and one aggregate, sliced. Attaching a tag is not an
     * edit — it is the one audit action whose subject is something
     * other than the model it names — and on this instance it is also
     * the most common row in the table by two orders of magnitude, so
     * an *Edits* lane carrying them reported a tagged value's history
     * as almost entirely edits while the *Tags* lane beside it said
     * that a tag can be dated only by an `audit_logs` row. Both
     * statements were true and the panel was drawing them in the wrong
     * places.
     *
     * The `tag` and `cluster` sources share one lane because they share
     * one mechanism — a cluster attachment is a tag underneath — and
     * stay two sources because the spine stacks them separately and the
     * key filters on them.
     *
     * With `MISP.log_new_audit` off there is nothing dated to slice:
     * the edit lane falls back to `attributes.timestamp` and the
     * tagging lane is empty and says why, which is the same shape the
     * edit lane's own hatch takes.
     *
     * @param array $context From `timelineContext`
     * @param array|null $window
     * @return array Two lane payloads, edits first
     */
    private function timelineAuditLanes(array $context,
        array $window = null
    ) {
        $edits = $this->timelineEditEntries($context, $window);
        $recorded = !empty($edits['recorded']);
        /*
         * Sliced out of the edit lane's own rows rather than read
         * again. `timelineEditEntries` returns the newest cap-many of
         * the window and both lanes take their share of exactly that,
         * so the two cannot describe row sets the reader never asked
         * for — and the counts each lane states come from the aggregate
         * underneath, which is not capped at all.
         */
        $kept = array();
        $tagged = array();
        foreach ($edits['entries'] as $entry) {
            if ($entry['source'] === 'edit') {
                $kept[] = $entry;
            } else {
                $tagged[] = $entry;
            }
        }
        $edits['entries'] = $kept;

        $byDay = array();
        $total = 0;
        $first = null;
        $last = null;
        if ($recorded) {
            $counts = $edits['audit_counts'];
            foreach ($counts['by_day'] as $day => $byGroup) {
                foreach ($byGroup as $group => $n) {
                    if ($group === 'edit') {
                        continue;
                    }
                    if (!isset($byDay[$day])) {
                        $byDay[$day] = array();
                    }
                    $byDay[$day][$group] = $n;
                    $total += $n;
                }
            }
            foreach (array('tag', 'cluster') as $group) {
                if (isset($counts['first_by_group'][$group])
                    && ($first === null
                        || $counts['first_by_group'][$group] < $first)
                ) {
                    $first = $counts['first_by_group'][$group];
                }
                if (isset($counts['last_by_group'][$group])
                    && ($last === null
                        || $counts['last_by_group'][$group] > $last)
                ) {
                    $last = $counts['last_by_group'][$group];
                }
            }
            /*
             * And the edit lane keeps only its own share of the three,
             * so its count, its range and its band all describe edits.
             */
            $editDays = array();
            foreach ($counts['by_day'] as $day => $byGroup) {
                if (isset($byGroup['edit'])) {
                    $editDays[$day] = array('edit' => $byGroup['edit']);
                }
            }
            $edits['by_day'] = $editDays;
            $edits['total'] = isset($counts['by_group']['edit'])
                ? $counts['by_group']['edit']
                : 0;
            $edits['first'] = isset($counts['first_by_group']['edit'])
                ? $counts['first_by_group']['edit']
                : null;
            $edits['last'] = isset($counts['last_by_group']['edit'])
                ? $counts['last_by_group']['edit']
                : null;
            /*
             * For `timelineFirstHere`, which is the one question asked
             * of a single action rather than of a group.
             */
            $edits['first_add'] = isset($counts['first_by_action']['add'])
                ? $counts['first_by_action']['add']
                : null;
        }
        unset($edits['audit_counts']);

        return array(
            $edits,
            array(
                'entries' => $tagged,
                'total' => $total,
                'sources' => array('tag', 'cluster'),
                'recorded' => $recorded,
                'by_day' => $byDay,
                'first' => $first,
                'last' => $last,
            ),
        );
    }

    /**
     * The tags the value carries now, each placed at the first time it
     * was attached.
     *
     * **One mark per tag, not per attachment.** A tag is attached again
     * on every re-import — `dark-web:structure="test"` five times on
     * one attribute inside half an hour — so the raw stream says how
     * often something re-tagged the value and not when the value
     * became that thing. The first attach is the fact a reader wants:
     * *this has been `c2` since November 2025*.
     *
     * **Removals are not modelled, deliberately.** The set is what the
     * value carries *now*, so a tag that was taken off is simply not
     * here; one that was removed and re-added keeps its first attach,
     * which is when this value first became that thing. The detach
     * rows are in the Tag changes lane, where a stream belongs.
     *
     * Matched on the tag's **name**, because `model_title` is the only
     * handle an audit row gives — and scoped to the occurrence and
     * object rows, never the event ones: an event tag of the same name
     * is the event's claim, and dating this value's own tag from it
     * would be reporting someone else's action as this value's.
     *
     * A tag with no row is kept with `at => null`. It is a tag the log
     * cannot place — attached before the log began, or by an import
     * that did not log — and dropping it would make the lane claim the
     * value was untagged until its oldest datable tag.
     *
     * @param array $user
     * @param string $value
     * @param array $context From `timelineContext`
     * @param array $options
     * @return array Oldest first, undatable last: `name`, `colour`,
     *               `galaxy`, `at`
     */
    private function timelineTagState(array $user, $value,
        array $context, array $options
    ) {
        $found = $this->model('Value')->ownTagsFor(
            $user,
            $value,
            $context['scope']['events'],
            $options
        );
        if (empty($found)) {
            return array();
        }
        $first = $this->tagFirstAttachFor(
            $context['scope'],
            array_keys($found)
        );
        $out = array();
        foreach ($found as $name => $entry) {
            $out[] = array(
                'name' => $name,
                'colour' => $entry['tag']['colour'],
                'galaxy' => !empty($entry['tag']['is_galaxy']),
                'at' => isset($first[$name]) ? $first[$name] : null,
            );
        }
        /*
         * Oldest first, which is the order the lane's chips read in:
         * how the value came to be characterised, in the order it
         * happened. The ones with no date go last rather than first —
         * they are older than every date here, but saying so is the
         * strip's job and leading with them would bury the story.
         */
        usort($out, function ($a, $b) {
            if (($a['at'] === null) !== ($b['at'] === null)) {
                return $a['at'] === null ? 1 : -1;
            }
            if ($a['at'] === $b['at']) {
                return strcasecmp($a['name'], $b['name']);
            }
            return strcmp($a['at'], $b['at']);
        });
        return $out;
    }

    /**
     * The first `tag`/`galaxy` attach per tag name, over the value's
     * own occurrences and objects.
     *
     * One grouped statement per model scope, on the same `model_id`
     * index the rest of the audit reader uses, bounded by the names the
     * value actually carries — so the result is at most one row per
     * tag rather than one per attachment. `193.161.193.99` is the worst
     * case on this instance at 77 distinct tags over 670 attachments.
     *
     * @param array $scope `attributes`, `objects`: id lists
     * @param array $names Tag names to look for
     * @return array name => `Y-m-d H:i:s`
     */
    private function tagFirstAttachFor(array $scope, array $names)
    {
        if (empty($names)) {
            return array();
        }
        $out = array();
        $audit = $this->model('AuditLog');
        foreach (array('Attribute', 'Object') as $model) {
            $key = $model === 'Attribute' ? 'attributes' : 'objects';
            $ids = isset($scope[$key]) ? $scope[$key] : array();
            if (empty($ids)) {
                continue;
            }
            foreach (array_chunk($ids, self::AUDIT_ID_CHUNK) as $chunk) {
                $rows = $audit->find('all', array(
                    'conditions' => array(
                        'AuditLog.model' => $model,
                        'AuditLog.model_id' => $chunk,
                        'AuditLog.action' => array(
                            'tag', 'tag_local', 'galaxy', 'galaxy_local',
                        ),
                        'AuditLog.model_title' => $names,
                    ),
                    'fields' => array(
                        'AuditLog.model_title',
                        'MIN(AuditLog.created) AS first_c',
                    ),
                    'group' => array('AuditLog.model_title'),
                    'recursive' => -1,
                ));
                foreach ($rows as $row) {
                    $name = $row['AuditLog']['model_title'];
                    $at = $row[0]['first_c'];
                    if (!isset($out[$name]) || $at < $out[$name]) {
                        $out[$name] = $at;
                    }
                }
            }
        }
        return $out;
    }

    /**
     * When this value was first recorded on this instance — and
     * whether that is a date or only a bound.
     *
     * **MISP stores no creation date for an attribute.** `timestamp` is
     * the last modification, `first_seen` is an analyst's claim about
     * when the threat was seen in the wild — a different fact, which
     * this tab already draws in a lane of its own — and an event's
     * `date` is the intel's date rather than the record's. So the
     * honest answer comes in two shapes and says which it is:
     *
     * - An `add` row in `audit_logs` over these occurrences, objects or
     *   events dates the creation exactly. It is usable only where it
     *   is no later than every other trace of the value: the audit log
     *   has a start, and a record created before it began leaves the
     *   oldest `add` row describing some *later* arrival.
     * - Otherwise the oldest trace of any kind is a bound — the value
     *   was here by then. That is every dated entry the tab found *that
     *   the instance itself left*, and every occurrence's last-modified
     *   stamp, which is the older of the two on a record nobody has
     *   touched since.
     *
     * **A claim is not a trace**, and the second bullet is where that
     * distinction has to be enforced rather than merely stated. The
     * paragraph above rules `first_seen` out by name; an object's
     * `datetime` field is the same kind of fact and used to walk in
     * anyway, because the bound was read off the axis's left edge.
     * `8.8.8.8` is what that looks like: a `passive-dns` object dated
     * this instance to 2013-01-15, nine years before its oldest
     * occurrence. `TIMELINE_CLAIM_SOURCES` is the list, and
     * `timelineFirstRecord` applies it.
     *
     * Either way the wording on the panel stops at what the row it
     * came from can support, which is why this returns the evidence
     * rather than a sentence.
     *
     * @param array $context From `timelineContext`
     * @param array $counts From `timelineCounts`
     * @param string|null $firstAdd The oldest `add` row, if any
     * @return array|null `at`, `exact`, `from`
     */
    private function timelineFirstHere(array $context, array $counts,
        $firstAdd
    ) {
        /*
         * `first_record` and not `first`: the axis's left edge is every
         * dated thing the tab found, and three of those sources are
         * claims about the world rather than traces of this instance.
         * `TIMELINE_CLAIM_SOURCES` carries the argument.
         */
        $bound = isset($counts['first_record'])
            ? $counts['first_record']
            : null;
        $from = $bound === null ? null : 'record';
        foreach ($context['occurrences'] as $occurrence) {
            if (empty($occurrence['timestamp'])) {
                continue;
            }
            $at = gmdate('Y-m-d H:i:s', (int)$occurrence['timestamp']);
            if ($bound === null || $at < $bound) {
                $bound = $at;
                $from = 'timestamp';
            }
        }
        if ($bound === null) {
            return null;
        }
        if ($firstAdd !== null && $firstAdd <= $bound) {
            return array(
                'at' => $firstAdd,
                'exact' => true,
                'from' => 'audit',
            );
        }
        return array('at' => $bound, 'exact' => false, 'from' => $from);
    }

    /**
     * One audit row as a chronology entry.
     *
     * The row names the occurrence and the action, **never the title**.
     * `model_title` prefers the new value, so an occurrence
     * edited *into* this value carries rows describing what it was
     * before; those are that occurrence's rows and they are shown, and
     * reading the title as the row's subject would report the wrong
     * value for every one of them. A tag or cluster action is the
     * exception the vocabulary already draws — there the title is the
     * tag, not the attribute — and `AUDIT_SUBJECT` is that list.
     *
     * @param array $row From `auditRowsFor`
     * @param array $context
     * @return array
     */
    private function timelineEditEntry(array $row, array $context)
    {
        $meta = AuditActionMeta::forAction($row['action']);
        $eventId = $row['event_id'];
        $event = ($eventId !== null && isset($context['events'][$eventId]))
            ? $context['events'][$eventId]
            : null;
        $target = $row['model'] === 'Event'
            ? sprintf(__('event %s'), $row['model_id'])
            : sprintf(
                __('%1$s %2$s'),
                strtolower($row['model']),
                $row['model_id']
            );
        $title = sprintf(
            __('%1$s — %2$s'),
            $meta['label'],
            $target
        );
        if ($row['subject'] !== null && $row['subject'] !== '') {
            $title = sprintf(
                __('%1$s “%2$s” — %3$s'),
                $meta['label'],
                $row['subject'],
                $target
            );
        }
        $actor = $row['actor'];
        if ($actor === null || $actor === '') {
            $actor = $row['org'] === null
                ? __('an unnamed account')
                : sprintf(__('%s (unnamed)'), $row['org']);
        }
        return array(
            'at' => $row['created'],
            /*
             * The action decides the lane, not the reader of this
             * array: a tag attachment is dated evidence about a tag,
             * and `AuditActionMeta::group` is where that judgement
             * lives so the History tab can read the same one.
             */
            'source' => AuditActionMeta::group($row['action']),
            'precision' => 'exact',
            'title' => $title,
            'note' => sprintf(__('audit_logs · %s'), $actor),
            'org' => $row['org'] === null
                ? ($event === null ? null : $event['org'])
                : $row['org'],
            'ref' => array(
                /*
                 * The audit row's own model, lowercased, and not the
                 * lane it was filed in: a `tag` action on an Object is
                 * drawn in the tag lane and still opens the object tab,
                 * because what the reader is being sent to is the thing
                 * that was tagged.
                 */
                'kind' => strtolower($row['model']),
                'attribute' => $row['attribute_id'],
                'event' => $eventId,
            ),
            'span_to' => null,
        );
    }

    /**
     * The object-date lane: the dates the objects this value sits in
     * record in fields of their own.
     *
     * **The third of the three places a date about a value lives**, and
     * the last one this tab was blind to. The seen lane above draws the
     * two `first_seen`/`last_seen` *columns* — MISP's own, on the
     * attribute and on the object. This draws what an object template
     * puts in a `datetime` *field*: `passive-dns`'s `time_first` and
     * `time_last`, `first-seen`/`last-seen` where a template spells them
     * out, `send-date` on an email, `compilation-timestamp` on a file.
     *
     * It is its own lane and not more rows in the seen one, because the
     * vocabulary is not one notion. On the verification instance the
     * `datetime` rows run `time_generated` 32,892, `first-seen` 11,318,
     * `last-seen` 11,193, `last-submission` 6,744,
     * `time_first`/`time_last` 665 each, then a tail through
     * `compilation-timestamp`, `creation-date` and `send-date` — and a
     * compilation timestamp folded into a lane called *Seen* would be
     * the panel asserting something nobody recorded. Every mark
     * therefore carries the relation that named it.
     *
     * **Paired where the template pairs them.** Two relations that are
     * the two ends of one interval draw one bar; everything else is an
     * instant. The pairs are `TIMELINE_DATE_PAIRS`, and a pair whose
     * far end fell outside the cap degrades to an instant rather than
     * to a bar with a guessed end.
     *
     * Counts from the aggregate and rows from a capped read, §16.1's
     * rule, and this lane is the second reader that needs it as much as
     * the edit lane does: `0.0.0.0` sits in 32,922 objects holding
     * 32,893 `datetime` rows.
     *
     * @param array $user
     * @param array $context From `timelineContext`
     * @param array|null $window
     * @return array One lane, in `forTimeline`'s shape
     */
    private function timelineObjectDateEntries(array $user, array $context,
        array $window = null
    ) {
        $valueModel = $this->model('Value');
        $objectIds = $context['scope']['objects'];
        $counts = $valueModel->objectDateCountsFor($user, $objectIds);
        $lane = array(
            'entries' => array(),
            'total' => $counts['total'],
            'sources' => array('objdate'),
            'by_day' => self::asSourceMap($counts['by_day'], 'objdate'),
            'first' => $counts['first'] === null
                ? null
                : $counts['first'] . ' 00:00:00',
            'last' => $counts['last'] === null
                ? null
                : $counts['last'] . ' 00:00:00',
            /*
             * **No object count here, and that is a decision.** The
             * obvious one — how many objects recorded a date — can only
             * be counted off the rows, and the rows are the newest
             * cap-many: `0.0.0.0` reported *32,893 dates in 1,000
             * objects* on the first cut, where the 1,000 was the cap
             * counting itself. The aggregate groups by day and relation
             * and cannot yield a distinct-object total without a third
             * query, so the lane states what it can count over all the
             * rows and nothing else. §16.1's rule, met by dropping a
             * number rather than by qualifying it.
             */
            'objdates' => array(
                'total' => $counts['total'],
                'shown' => 0,
                'relations' => $counts['by_relation'],
                'cap' => self::TIMELINE_OBJECT_DATE_CAP,
            ),
        );
        if ($counts['total'] === 0) {
            return $lane;
        }

        /*
         * The newest cap-many. The ordering that makes *newest* mean
         * anything belongs to `objectDatesFor` and not to this call —
         * it is a claim about how the column stores a date, which is
         * §14.3's seam and not this file's business.
         */
        $rows = $valueModel->objectDatesFor($user, $objectIds, array(
            'limit' => self::TIMELINE_OBJECT_DATE_CAP,
        ));

        $byObject = array();
        foreach ($rows as $row) {
            $byObject[$row['object_id']][] = $row;
        }
        $entries = array();
        $drawn = 0;
        foreach ($byObject as $objectId => $objectRows) {
            /*
             * One row per relation. A template that files the same
             * relation twice in one object is malformed rather than
             * interesting, and taking the first keeps the pair lookup a
             * lookup rather than a cross product.
             */
            $byRelation = array();
            foreach ($objectRows as $row) {
                if (!isset($byRelation[$row['relation']])) {
                    $byRelation[$row['relation']] = $row;
                }
            }
            foreach (self::TIMELINE_DATE_PAIRS as $from => $to) {
                if (!isset($byRelation[$from]) || !isset($byRelation[$to])) {
                    continue;
                }
                $start = self::plainStamp($byRelation[$from]['at']);
                $end = self::plainStamp($byRelation[$to]['at']);
                unset($byRelation[$from], $byRelation[$to]);
                if ($start === null) {
                    continue;
                }
                $drawn += 2;
                $entries[] = self::objectDateEntry(
                    $context,
                    $objectRows[0],
                    $start,
                    $end === $start ? null : $end,
                    sprintf(__('%1$s → %2$s'), $from, $to)
                );
            }
            foreach ($byRelation as $relation => $row) {
                $at = self::plainStamp($row['at']);
                if ($at === null) {
                    continue;
                }
                $drawn++;
                $entries[] = self::objectDateEntry($context, $row, $at, null,
                    $relation === '' ? __('undeclared field') : $relation);
            }
        }

        $lane['entries'] = self::timelineWindowed($entries, $window);
        $lane['objdates']['shown'] = $drawn;
        return $lane;
    }

    /**
     * One mark or bar for the object-date lane.
     *
     * @param array $context From `timelineContext`
     * @param array $row One `Value::objectDatesFor` record
     * @param string $at
     * @param string|null $to
     * @param string $relation What the template calls this date
     * @return array
     */
    private static function objectDateEntry(array $context, array $row, $at,
        $to, $relation
    ) {
        $event = isset($context['events'][$row['event_id']])
            ? $context['events'][$row['event_id']]
            : null;
        return array(
            'at' => $at,
            'source' => 'objdate',
            'precision' => 'exact',
            'title' => sprintf(
                __('%1$s · %2$s'),
                $row['object'] === '' ? __('object') : $row['object'],
                $relation
            ),
            /*
             * The note carries the whole of what separates this lane
             * from the one above it: the date is the object's own
             * field, so it means whatever the template means by that
             * field — and the panel will not guess which.
             */
            'note' => $to === null
                ? sprintf(
                    __(
                        'The %1$s object records this date in its'
                        . ' %2$s field. What it means is the'
                        . ' template\'s to say, not this page\'s.'
                    ),
                    $row['object'] === '' ? __('containing') : $row['object'],
                    $relation
                )
                : sprintf(
                    __(
                        'Closes %1$s. The %2$s object records this'
                        . ' interval in its own fields.'
                    ),
                    substr($to, 0, 10),
                    $row['object'] === '' ? __('containing') : $row['object']
                ),
            'org' => $event === null ? null : $event['org'],
            'ref' => array(
                /*
                 * The object, not the `datetime` attribute the date was
                 * read off: the row's subject is *what the object
                 * records*, and the object tab is where a reader can see
                 * that field beside the rest of the template.
                 */
                'kind' => 'object',
                'attribute' => $row['id'],
                'event' => $row['event_id'],
            ),
            'span_to' => $to,
        );
    }

    /**
     * The seen-span lane: one row per occurrence carrying a
     * `first_seen`, plus the containing object's span where the
     * occurrence has none — no merging, capped, remainder stated.
     *
     * **Two sources, because MISP records the span at two levels and
     * treats one as the other's default.** `objects.first_seen` and
     * `objects.last_seen` are columns of their own, and
     * `MispObject::saveObject` copies them down onto every attribute
     * saved without a span — but only on the add path.
     * `deltaMerge` calls `syncObjectAndAttributeSeen` with
     * `$applyOnAttribute = false`, so editing an object's span never
     * reaches its attributes, and the two drift apart from there.
     *
     * On the verification instance that drift is nearly the whole
     * population: 319 objects carry a `first_seen` and **280 of them
     * have no member attribute carrying one**, against 36 fully copied
     * down and 3 copied in part. So a lane reading only the attribute
     * column was blind to seven-eighths of the object-level spans on
     * the instance, and blind in the direction that matters — it drew
     * a value as undated when a date was one join away, in a table
     * this reader already joins for the ACL.
     *
     * Merging needs an aggregation rule nobody has agreed on, and this
     * lane invents none: each span stays its own row labelled with the
     * occurrence it came from, and the bound is a cap on how many are
     * drawn rather than a rule for combining them. A cap is not a
     * permission, so the lane says so for every reader.
     *
     * **Instants are instants.** 68,083 of the instance's dated
     * occurrences have `first_seen == last_seen`, against 109,320 real
     * spans and 2,475 open-ended ones. A zero-width bar says nothing, so
     * those draw as marks, in this lane, beside the spans.
     *
     * `first_seen` and `last_seen` are `bigint(20)` microsecond epochs
     * in the database and ISO-8601 by the time `fetchAttributesSimple`
     * hands them back. The conversion is from what the fetcher returns
     * and never from the column, because the fetcher is the seam.
     *
     * @param array $context From `timelineContext`
     * @return array
     */
    private function timelineSpanEntries(array $context)
    {
        $dated = array();
        $total = 0;
        /*
         * The objects whose own span the lane may draw, keyed by object
         * id so one object contributes one bar however many occurrences
         * of this value sit in it.
         *
         * **An object earns a bar only from an occurrence that has no
         * span of its own.** Where the attribute is dated, MISP either
         * copied that date down from the object at save time or the
         * attribute is the more specific claim — either way the object's
         * bar would be a second drawing of a date already on the axis.
         * On the verification instance the two are equal wherever both
         * are set, with one object out of 36 the exception, so this is
         * a de-duplication rule and not a preference between them.
         */
        $viaObject = array();
        $covered = 0;
        foreach ($context['occurrences'] as $id => $occurrence) {
            $total++;
            if (!empty($occurrence['first_seen'])) {
                $dated[(int)$id] = $occurrence;
                continue;
            }
            $objectId = isset($occurrence['object_id'])
                ? (int)$occurrence['object_id']
                : 0;
            if ($objectId === 0 || empty($occurrence['object_first_seen'])) {
                continue;
            }
            $covered++;
            if (!isset($viaObject[$objectId])) {
                $viaObject[$objectId] = array(
                    'id' => $objectId,
                    'first_seen' => $occurrence['object_first_seen'],
                    'last_seen' => $occurrence['object_last_seen'],
                    'event_id' => (int)$occurrence['event_id'],
                    'name' => isset($context['objects'][$objectId]['name'])
                        ? $context['objects'][$objectId]['name']
                        : '',
                );
            }
        }
        uasort($dated, function ($a, $b) {
            return strcmp((string)$a['first_seen'], (string)$b['first_seen']);
        });
        uasort($viaObject, function ($a, $b) {
            return strcmp((string)$a['first_seen'], (string)$b['first_seen']);
        });
        $with = count($dated);
        $shown = array_slice($dated, 0, self::TIMELINE_SPAN_CAP, true);
        /*
         * Its own budget rather than a share of the attribute cap: the
         * two answer different questions, and a value with 25 dated
         * occurrences should not thereby lose every object-level span
         * it has. Both are stated in the lane's sub-label.
         */
        $shownObjects = array_slice($viaObject, 0,
            self::TIMELINE_SPAN_CAP, true);

        /*
         * Over every dated occurrence and not only the drawn ones, for
         * the reason the edit lane's map exists: this lane caps its bars
         * at `TIMELINE_SPAN_CAP`, so binning the spine from what it drew
         * would hide the months the other spans are in.
         * `143.14.244.37` is 32 spans drawn 25 at a time.
         */
        $byDay = array();
        $first = null;
        $last = null;
        /*
         * Two sources into one map, because the lane stacks them: the
         * spine's segment for an object-level span has to be its own
         * colour, or a reader cannot tell the axis's densest month from
         * a month of dates the objects supplied.
         */
        $tallies = array(
            array('seen', $dated),
            array('seen_object', $viaObject),
        );
        foreach ($tallies as $tally) {
            list($source, $rows) = $tally;
            foreach ($rows as $row) {
                $at = self::plainStamp($row['first_seen']);
                if ($at === null) {
                    continue;
                }
                $day = substr($at, 0, 10);
                if (!isset($byDay[$day])) {
                    $byDay[$day] = array();
                }
                $byDay[$day][$source] = (isset($byDay[$day][$source])
                    ? $byDay[$day][$source]
                    : 0) + 1;
                if ($first === null || $at < $first) {
                    $first = $at;
                }
                if ($last === null || $at > $last) {
                    $last = $at;
                }
            }
        }
        ksort($byDay);

        $entries = array();
        foreach ($shown as $id => $occurrence) {
            $from = self::plainStamp($occurrence['first_seen']);
            if ($from === null) {
                continue;
            }
            $to = empty($occurrence['last_seen'])
                ? null
                : self::plainStamp($occurrence['last_seen']);
            if ($to === $from) {
                $to = null;
                $note = __(
                    'One instant, not a span. A claim about the value,'
                    . ' not a change to the record.'
                );
            } elseif ($to === null) {
                $note = __(
                    'The span is open — no last_seen. A claim about the'
                    . ' value, not a change to the record.'
                );
            } else {
                $note = sprintf(
                    __(
                        'Closes %s. A claim about the value, not a'
                        . ' change to the record.'
                    ),
                    substr($to, 0, 10)
                );
            }
            $event = isset($context['events'][$occurrence['event_id']])
                ? $context['events'][$occurrence['event_id']]
                : null;
            $entries[] = array(
                'at' => $from,
                'source' => 'seen',
                'precision' => 'exact',
                'title' => sprintf(__('attribute %1$s — first seen'), $id),
                'note' => $note,
                'org' => $event === null ? null : $event['org'],
                'ref' => array(
                    'kind' => 'attribute',
                    'attribute' => (int)$id,
                    'event' => (int)$occurrence['event_id'],
                ),
                'span_to' => $to,
            );
        }

        /*
         * The object-level bars, after the attribute ones so that a
         * reader scanning the chronology meets the direct claim first.
         * Every one of these says *the object this value sits in was
         * seen then*, which is a weaker claim than the bars above and
         * is labelled as one on every mark.
         */
        $drawnObjects = 0;
        foreach ($shownObjects as $objectId => $object) {
            $from = self::plainStamp($object['first_seen']);
            if ($from === null) {
                continue;
            }
            $to = empty($object['last_seen'])
                ? null
                : self::plainStamp($object['last_seen']);
            if ($to === $from) {
                $to = null;
            }
            $drawnObjects++;
            $event = isset($context['events'][$object['event_id']])
                ? $context['events'][$object['event_id']]
                : null;
            $entries[] = array(
                'at' => $from,
                'source' => 'seen_object',
                'precision' => 'exact',
                'title' => $object['name'] === ''
                    ? sprintf(__('object %s — first seen'), $objectId)
                    : sprintf(
                        __('%1$s object %2$s — first seen'),
                        $object['name'],
                        $objectId
                    ),
                /*
                 * The note carries the whole of the weaker claim,
                 * because this is the one place a reader meets it: the
                 * date is the object's, the value has none of its own,
                 * and MISP would have copied this down had the object
                 * been saved with it.
                 */
                'note' => $to === null
                    ? __(
                        'The object carries this date, the occurrence'
                        . ' carries none. A claim about the object this'
                        . ' value sits in.'
                    )
                    : sprintf(
                        __(
                            'Closes %s. The object carries this span,'
                            . ' the occurrence carries none. A claim'
                            . ' about the object this value sits in.'
                        ),
                        substr($to, 0, 10)
                    ),
                'org' => $event === null ? null : $event['org'],
                'ref' => array(
                    'kind' => 'object',
                    'attribute' => null,
                    'event' => (int)$object['event_id'],
                ),
                'span_to' => $to,
            );
        }

        return array(
            'entries' => $entries,
            'total' => $with + count($viaObject),
            'sources' => array('seen', 'seen_object'),
            // Its own map, and not `timelineLane`'s: this lane caps at
            // 25 bars rather than at the chronology's 300, so the map
            // has to be tallied over the dated occurrences and never
            // over the entries built from them.
            'by_day' => $byDay,
            'first' => $first,
            'last' => $last,
            'spans' => array(
                // What the lane's sub-label states, and the three are
                // three different answers: how many occurrences the
                // viewer can see, how many of those are dated, and how
                // many of those this lane drew.
                'occurrences' => $total,
                'with' => $with,
                'shown' => count($entries) - $drawnObjects,
                'cap' => self::TIMELINE_SPAN_CAP,
                /*
                 * The object half, and the three numbers answer the
                 * same three questions one level up: how many
                 * occurrences have no span but sit in an object that
                 * does, how many distinct objects that is, and how many
                 * of those the lane drew.
                 */
                'covered' => $covered,
                'objects' => count($viaObject),
                'objects_shown' => $drawnObjects,
            ),
        );
    }

    /**
     * `2026-06-30T07:14:08+00:00` or `2026-06-30 07:14:08` to the one
     * shape every entry on this axis shares.
     *
     * The chronology sorts and bins on plain strings, and what reaches
     * here depends on the fetcher rather than on the column: MISP stores
     * `first_seen` as a microsecond epoch and `fetchAttributesSimple`
     * hands back ISO-8601.
     *
     * @param string|null $stamp
     * @return string|null
     */
    private static function plainStamp($stamp)
    {
        if ($stamp === null || $stamp === '') {
            return null;
        }
        $time = strtotime((string)$stamp);
        return $time === false
            ? null
            : gmdate('Y-m-d H:i:s', $time);
    }

    /**
     * What the panel states beside every number it cannot derive from
     * the rows it was sent.
     *
     * The invariant, kept: the spine's bars and the lanes' totals come
     * from here, the chronology comes from `entries`, and the panel says
     * both numbers where they differ. Every lane whose rows are all
     * present contributes its counts *from those rows*, so it cannot
     * disagree with itself by construction; only the edit lane, which is
     * the one that can run to 172,426, carries a total from an aggregate
     * instead.
     *
     * @param array $lanes Per-lane results, in `forTimeline`'s order
     * @param array $entries The merged, capped, ascending array
     * @return array
     */
    private function timelineCounts(array $lanes, array $entries)
    {
        /*
         * **Nothing here is tallied from `$entries`.** Every lane hands
         * up a day map over all of its rows, so the spine and the lane
         * grid are counted before any cap was applied and `$entries` is
         * only ever the list. The edit lane is why the rule has to be
         * absolute rather than case-by-case: it ships 1,000 rows and
         * 172,426 of them happened, so tallying its rows would draw
         * eleven months of history as one afternoon — and a lane that
         * *happens* to fit today is a lane that stops fitting on a
         * bigger instance without anything saying so.
         *
         * A source with no rows at all is left out rather than carried
         * as a zero: the spine draws one stack segment per source
         * present, and a segment for a source nobody ever filed is a
         * legend entry teaching the reader a colour they will never
         * meet again.
         */
        $bySource = array();
        $byDay = array();
        foreach ($lanes as $lane) {
            foreach ($lane['by_day'] as $day => $bySourceOnDay) {
                if (!isset($byDay[$day])) {
                    $byDay[$day] = array();
                }
                foreach ($bySourceOnDay as $source => $n) {
                    $byDay[$day][$source] = (isset($byDay[$day][$source])
                        ? $byDay[$day][$source]
                        : 0) + $n;
                    $bySource[$source] = (isset($bySource[$source])
                        ? $bySource[$source]
                        : 0) + $n;
                }
            }
        }
        ksort($byDay);

        $total = 0;
        foreach ($lanes as $lane) {
            $total += $lane['total'];
        }
        $first = null;
        $last = null;
        foreach ($entries as $entry) {
            if ($first === null || $entry['at'] < $first) {
                $first = $entry['at'];
            }
            if ($last === null || $entry['at'] > $last) {
                $last = $entry['at'];
            }
        }
        /*
         * A grouped lane also knows a range its capped rows cannot show:
         * the edit aggregate carries the first and last logged change
         * over the whole scoped set, which on `443` is eleven months
         * where the 1,000 rows drawn are one afternoon.
         */
        foreach ($lanes as $lane) {
            if (empty($lane['first']) && empty($lane['last'])) {
                continue;
            }
            if (!empty($lane['first'])
                && ($first === null || $lane['first'] < $first)
            ) {
                $first = $lane['first'];
            }
            if (!empty($lane['last'])
                && ($last === null || $lane['last'] > $last)
            ) {
                $last = $lane['last'];
            }
        }
        /*
         * The spans, kept apart from the day map because a day map
         * cannot hold one. Every other fact on this axis is an instant
         * and a `Y-m-d => n` tally states it exactly; an interval has a
         * middle, and the middle is what the tally drops.
         *
         * Only the ends of the interval are recorded here. What the
         * window makes of them is `timelineWindowCounts`' business,
         * and the rule it applies cannot be pushed into the map
         * without inventing a count for every day in between.
         *
         * These come off the lanes' rows rather than off an aggregate,
         * which is a departure from §16.1 and a bounded one: both lanes
         * that produce spans cap their rows and both state the cap in
         * their own sub-label, so a span the cap dropped is a span the
         * reader was already told about.
         */
        $spans = array();
        foreach ($lanes as $lane) {
            foreach ($lane['entries'] as $entry) {
                if (empty($entry['span_to'])) {
                    continue;
                }
                $spans[] = array(
                    'source' => $entry['source'],
                    'from' => substr($entry['at'], 0, 10),
                    'to' => substr($entry['span_to'], 0, 10),
                );
            }
        }
        $shown = min(count($entries), self::TIMELINE_ROW_CAP);
        return array(
            'total' => $total,
            'shown' => $shown,
            'by_source' => $bySource,
            'by_day' => $byDay,
            'spans' => $spans,
            'first' => $first,
            'last' => $last,
            'first_record' => self::timelineFirstRecord($lanes, $entries),
            'capped' => $total > $shown,
            'cap' => self::TIMELINE_ROW_CAP,
        );
    }

    /**
     * The oldest trace this *instance* left, ignoring what anyone
     * claimed about the world.
     *
     * `first` above is the axis's left edge and takes every dated thing
     * the tab found, which is right for an axis and wrong for the one
     * question the panel asks beside it: how long has this been here.
     * `8.8.8.8` is the case that showed it. A `passive-dns` object
     * filed in 2022 carries `time_first = 2013-01-15`, so the axis
     * began in 2013 — correctly, the object does record that date — and
     * the panel went on to state *on this instance by 2013-01-15*,
     * which is Farsight's observation window read as this instance's
     * age. Nine years of it. The oldest record trace is an occurrence's
     * `timestamp` of 2022-06-28.
     *
     * `TIMELINE_CLAIM_SOURCES` is the exclusion, and it is the same
     * distinction `timelineFirstHere` already drew in prose for
     * `first_seen` without the code drawing it anywhere.
     *
     * @param array $lanes
     * @param array $entries
     * @return string|null
     */
    private static function timelineFirstRecord(array $lanes, array $entries)
    {
        $first = null;
        foreach ($entries as $entry) {
            if (in_array($entry['source'], self::TIMELINE_CLAIM_SOURCES,
                true)
            ) {
                continue;
            }
            if ($first === null || $entry['at'] < $first) {
                $first = $entry['at'];
            }
        }
        /*
         * A grouped lane's aggregate range, on the same terms: the edit
         * lane's 172,426 changes reach back further than the 1,000 rows
         * it ships, and dropping that would date the record from
         * whichever afternoon the cap happened to land on.
         */
        foreach ($lanes as $lane) {
            if (empty($lane['first'])) {
                continue;
            }
            if (array_diff($lane['sources'], self::TIMELINE_CLAIM_SOURCES)
                === array()
            ) {
                continue;
            }
            if ($first === null || $lane['first'] < $first) {
                $first = $lane['first'];
            }
        }
        return $first;
    }

    /**
     * What the lane grid states beside each lane: how much of that
     * source falls inside the window.
     *
     * Summed from the day map and never from the entries, which is the
     * one thing that makes the number survive the cap. The lanes' counts
     * used to be a tally over the rendered rows, and on any value where
     * the cap bites that reads as a lane going quiet: `443` ships 300
     * rows all inside three days, so a tally over them would report
     * every other lane as empty for a window they are not empty in.
     *
     * The day grain is what lets this be exact for a window that
     * straddles two months, which the default one usually does.
     *
     * **A span is counted where it is drawn**, which the day map alone
     * could not do. An interval whose two ends both fall outside the
     * window still crosses it, the lane draws a bar right across, and
     * the column beside that bar used to read zero. So a span the
     * window touches but neither end of which lands inside it adds one,
     * and a span with an end inside is left to the map, which already
     * counted that end and would otherwise count it twice.
     *
     * One, not the days it covers. The reader is being told how many
     * dated things this lane has here, and a `passive-dns` pair is one
     * thing however many months it spans.
     *
     * @param array $byDay `Y-m-d` => source => n
     * @param array $window `from`, `to`
     * @param array $spans From `timelineCounts`, each `source`, `from`,
     *                     `to`
     * @return array `total` and one entry per source present
     */
    private function timelineWindowCounts(array $byDay, array $window,
        array $spans = array()
    ) {
        $counts = array('total' => 0);
        $add = function ($source, $n) use (&$counts) {
            if (!isset($counts[$source])) {
                $counts[$source] = 0;
            }
            $counts[$source] += $n;
            $counts['total'] += $n;
        };
        foreach ($byDay as $day => $bySource) {
            if ($day < $window['from'] || $day > $window['to']) {
                continue;
            }
            foreach ($bySource as $source => $n) {
                $add($source, $n);
            }
        }
        foreach ($spans as $span) {
            if ($span['to'] < $window['from']
                || $span['from'] > $window['to']
            ) {
                continue;
            }
            $endInside = ($span['from'] >= $window['from']
                    && $span['from'] <= $window['to'])
                || ($span['to'] >= $window['from']
                    && $span['to'] <= $window['to']);
            if ($endInside) {
                continue;
            }
            $add($span['source'], 1);
        }
        return $counts;
    }

    /**
     * A flat `day => n` tally, keyed under the one source it counts.
     *
     * Two lanes tally without walking their own entries — the edit
     * lane's map comes from SQL and the seen lane's from the occurrence
     * rows — and both count exactly one source. This is where they join
     * the shape every other lane produces, so nothing downstream has to
     * know which kind of lane it is looking at.
     *
     * @param array $flat `Y-m-d` => n
     * @param string $source
     * @return array `Y-m-d` => source => n
     */
    private static function asSourceMap(array $flat, $source)
    {
        $out = array();
        foreach ($flat as $day => $n) {
            $out[$day] = array($source => $n);
        }
        return $out;
    }

    /**
     * One lane's result: its day map over every row, and only the
     * newest `TIMELINE_ROW_CAP` of the rows themselves.
     *
     * **Every lane is bounded here, not just the ones that looked
     * dangerous.** The merge keeps the newest cap-many of the union, so
     * a lane that hands over more than that many rows is building an
     * array to have it thrown away — and two lanes do it on real
     * values: with the audit log off the edit lane is one row per
     * occurrence, which is 48,255 on `443`, and the publication lane is
     * up to two rows per event, which is 1,847. The day map is tallied
     * over all of them first, so bounding the rows costs no count.
     *
     * The bound is per lane and equal to the global one, which is what
     * keeps the merge exact rather than approximate: the newest n of a
     * union is a subset of the union of each part's newest n.
     *
     * The map is per day **and per source**, because a lane is not a
     * source: the sightings lane owns three of them and the analyst
     * lane two, so a flat per-lane tally would report four false
     * positives as four sightings — the same colour on the spine, the
     * wrong word in the lane's breakdown, and no way to tell from the
     * outside.
     *
     * @param array $entries Every row the lane found, any order
     * @param array $sources The source keys this lane owns
     * @param array $extra Merged into the result, e.g. `spans`
     * @param array|null $window `from` and `to`; the rows only
     * @return array
     */
    private function timelineLane(array $entries, array $sources,
        array $extra = array(), array $window = null
    ) {
        $byDay = array();
        $first = null;
        $last = null;
        foreach ($entries as $entry) {
            $day = substr($entry['at'], 0, 10);
            $source = $entry['source'];
            if (!isset($byDay[$day])) {
                $byDay[$day] = array();
            }
            $byDay[$day][$source] = (isset($byDay[$day][$source])
                ? $byDay[$day][$source]
                : 0) + 1;
            if ($first === null || $entry['at'] < $first) {
                $first = $entry['at'];
            }
            if ($last === null || $entry['at'] > $last) {
                $last = $entry['at'];
            }
        }
        ksort($byDay);
        $total = count($entries);
        /*
         * **The window narrows the rows and nothing else.** Everything
         * above it — the day map, the total, the range — was tallied
         * over every row the lane found, because those are what the
         * spine and the lane grid are drawn from and they describe the
         * whole value however narrow the reader's window is.
         *
         * The order matters and is the whole of what makes a windowed
         * fetch work: filtering before the cap means the newest
         * cap-many *of the window*, where filtering after it would be
         * the window's share of the newest cap-many overall — nothing
         * at all, for any window older than the cap reaches.
         */
        $rows = self::timelineWindowed($entries, $window);
        if (count($rows) > self::TIMELINE_ROW_CAP) {
            usort($rows, function ($a, $b) {
                return strcmp($a['at'], $b['at']);
            });
            $rows = array_slice($rows, -self::TIMELINE_ROW_CAP);
        }
        return array(
            'entries' => $rows,
            'total' => $total,
            'sources' => $sources,
            'by_day' => $byDay,
            'first' => $first,
            'last' => $last,
        ) + $extra;
    }

    /**
     * The entries the window touches, or all of them when there is no
     * window.
     *
     * By day and not by timestamp, because that is what both readers of
     * this set compare on — the template's own filter and
     * `tlRefreshList`'s in the browser — and a window is two dates.
     *
     * @param array $entries Each with an `at` of `Y-m-d H:i:s`
     * @param array|null $window `from` and `to`, `Y-m-d`
     * @return array
     */
    private static function timelineWindowed(array $entries,
        array $window = null
    ) {
        if ($window === null) {
            return $entries;
        }
        $out = array();
        foreach ($entries as $entry) {
            if (self::timelineTouches($entry, $window)) {
                $out[] = $entry;
            }
        }
        return $out;
    }

    /**
     * Whether one entry falls in a window — **overlap, not start.**
     *
     * An instant is in a window when its day is. A span is in one when
     * the two intervals meet, which is a different test and the one
     * this tab got wrong: `8.8.8.8` carries a `passive-dns` pair
     * running 2013-01-15 to 2018-09-30, and a window anywhere inside
     * those five years shares no *day* with either end. Filtering on
     * the start day dropped it, so the lane drew nothing, the
     * chronology listed nothing, and the panel reported a covered span
     * of time as empty — a bar that exists precisely to say *this was
     * observed throughout here*.
     *
     * A span with no far end is its own end, so instants take the same
     * path and there is one rule rather than two.
     *
     * @param array $entry With `at` and optionally `span_to`
     * @param array $window `from`, `to`
     * @return bool
     */
    private static function timelineTouches(array $entry, array $window)
    {
        $from = substr($entry['at'], 0, 10);
        $to = empty($entry['span_to'])
            ? $from
            : substr($entry['span_to'], 0, 10);
        return $to >= $window['from'] && $from <= $window['to'];
    }

    /**
     * The newest `TIMELINE_ROW_CAP` entries, back in ascending order.
     *
     * The cap is on the whole merged array and not on any one lane,
     * because the fragment's weight is the sum: the audit reader caps
     * itself at the same number, and `443` still offered 2,173 entries
     * once 1,844 events had each contributed a publication.
     *
     * Newest rather than a slice from anywhere else, for the reason
     * phase 22 gave the occurrence table: a value's newest activity is
     * what a reader opening this tab came for, and it is also what makes
     * the panel's *showing 1,000 of 174,299* true rather than merely
     * arithmetic.
     *
     * @param array $entries Ascending
     * @return array Ascending, at most `TIMELINE_ROW_CAP` long
     */
    private function timelineCap(array $entries)
    {
        if (count($entries) <= self::TIMELINE_ROW_CAP) {
            return $entries;
        }
        return array_slice($entries, -self::TIMELINE_ROW_CAP);
    }

    /**
     * The brush's default window.
     *
     * `TIMELINE_WINDOW_DAYS` ending at the value's newest dated entry,
     * clamped to its oldest — so it is a recent slice of a wider spine
     * on a value with years of history, and the whole of a value with
     * less than a month of it. Ending at the newest entry rather than at
     * today, because a value whose last activity was in 2020 should open
     * on its activity and not on an empty present.
     *
     * A value with nothing dated at all gets the last
     * `TIMELINE_WINDOW_DAYS` up to today, and the panel then renders as
     * the panel where nothing is dated — a state it has to draw anyway.
     *
     * @param array $counts From `timelineCounts`
     * @return array `from`, `to`
     */
    private function timelineWindow(array $counts)
    {
        $utc = new DateTimeZone('UTC');
        $end = $counts['last'] === null
            ? gmdate('Y-m-d')
            : substr($counts['last'], 0, 10);
        $from = (new DateTimeImmutable($end . ' 00:00:00', $utc))
            ->modify('-' . (self::TIMELINE_WINDOW_DAYS - 1) . ' days')
            ->format('Y-m-d');
        if ($counts['first'] !== null) {
            $earliest = substr($counts['first'], 0, 10);
            if ($earliest > $from) {
                $from = $earliest;
            }
        }
        return array('from' => $from, 'to' => $end);
    }

    /**
     * Notes and opinions, over the value's occurrences **and its
     * events**, with every row naming its target.
     *
     * There is a union at all because notes hang off an `object_uuid`:
     * the value's own, one per spelling, and those of the things the
     * value is *in*.
     *
     * **Both halves, because either alone is wrong.** The instance holds
     * 75 notes and 43 opinions; 9 notes and 3 opinions are on attributes
     * and none of those is on a candidate value's occurrence, while
     * `8.8.8.8`'s events carry 2 notes, `1.1.1.1`'s 4 and `2.2.2.2`'s 1.
     * Take only the occurrence-level ones and this lane is empty on
     * every value worth verifying; take both and most of what it draws
     * is about an event rather than about the value. So both, and
     * **every row names its target** — *note on event 3753* is a
     * different claim from *note on attribute 481920*, the tab's whole
     * charter is provenance, and a union that flattened the two would
     * promote an event's narrative into a statement about the value.
     *
     * `fetchForUuids` contains `Org`, `Orgc` and `SharingGroup`, which
     * is what keeps `AnalystData::rearrangeOrganisation` from
     * re-querying per row — phase 24 recorded that failure mode, and it
     * is every row silently reporting *Unknown organisation*.
     *
     * One anomaly, carried and not fixed: one `notes` row holds
     * `object_type = 'Event1556'`, a type that is not a type —
     * presumably an id concatenated onto the model name by whatever
     * wrote it. The union therefore keys on the UUID it resolved and
     * never on `object_type`, so a bad type cannot mislabel a row; it
     * can only fail to match, which is what it does.
     *
     * @param array $user
     * @param string $value
     * @param array $context From `timelineContext`
     * @return array
     */
    private function timelineAnalystEntries(array $user, $value,
        array $context, array $window = null
    ) {
        $targets = array();
        foreach ($context['events'] as $event) {
            if (empty($event['uuid'])) {
                continue;
            }
            $targets[$event['uuid']] = array(
                'kind' => 'event',
                'id' => $event['id'],
                'event' => $event['id'],
                'label' => sprintf(__('event %s'), $event['id']),
            );
        }
        $occurrences = $this->model('Value')->occurrenceUuidsFor(
            $user,
            $value,
            array(
                'limit' => self::TIMELINE_ANALYST_CAP,
                'order' => self::OCCURRENCE_ORDER,
            )
        );
        foreach ($occurrences as $uuid => $occurrence) {
            $targets[$uuid] = array(
                'kind' => 'attribute',
                'id' => (int)$occurrence['id'],
                'event' => (int)$occurrence['event_id'],
                'label' => sprintf(
                    __('attribute %s'),
                    $occurrence['id']
                ),
            );
        }
        foreach ($this->valueAnchorUuids($user, $value) as $uuid => $spelling) {
            $targets[$uuid] = array(
                'kind' => 'value',
                'id' => null,
                'event' => null,
                'label' => $spelling === (string)$value
                    ? __('this value')
                    : sprintf(__('this value, spelled %s'), $spelling),
            );
        }
        if (empty($targets)) {
            return $this->timelineLane(
                array(),
                array('note', 'opinion'),
                array(),
                $window
            );
        }

        $uuids = array_keys($targets);
        $entries = array();
        foreach (array('Note', 'Opinion') as $type) {
            $found = $this->model($type)->fetchForUuids($uuids, $user);
            foreach ($found as $uuid => $byType) {
                if (!isset($byType[$type]) || !isset($targets[$uuid])) {
                    continue;
                }
                foreach ($byType[$type] as $row) {
                    $entries[] = $this->timelineAnalystEntry(
                        $type,
                        $row,
                        $targets[$uuid]
                    );
                }
            }
        }
        return $this->timelineLane($entries, array('note', 'opinion'),
            array(), $window);
    }

    /**
     * One note or opinion as a chronology entry.
     *
     * @param string $type `Note` or `Opinion`
     * @param array $row One `fetchForUuids` record
     * @param array $target `kind`, `id`, `label`
     * @return array
     */
    private function timelineAnalystEntry($type, array $row, array $target)
    {
        $org = isset($row['Orgc']['name'])
            ? $row['Orgc']['name']
            : (isset($row['Org']['name'])
                ? $row['Org']['name']
                : __('Unknown organisation'));
        if ($type === 'Note') {
            $title = sprintf(
                __('%1$s — “%2$s”'),
                $org,
                $row['note']
            );
            $note = sprintf(
                /*
                 * The target, in the note rather than in the title,
                 * because the title is the claim and this is what the
                 * claim is about — and a reader scanning the lane needs
                 * to be able to tell the two apart at a glance.
                 */
                __('analyst note on %s'),
                $target['label']
            );
        } else {
            $title = sprintf(
                __('%1$s — %2$s / 100, “%3$s”'),
                $org,
                $row['opinion'],
                $row['comment']
            );
            $note = sprintf(
                __('analyst opinion on %s'),
                $target['label']
            );
        }
        return array(
            'at' => $row['created'],
            'source' => $type === 'Note' ? 'note' : 'opinion',
            'precision' => 'exact',
            'title' => $title,
            'note' => $note,
            'org' => $org,
            'ref' => array(
                'kind' => $target['kind'],
                'attribute' => $target['kind'] === 'attribute'
                    ? $target['id']
                    : null,
                /*
                 * The event either way. It used to be null on a note
                 * about an attribute, which was true of *the target*
                 * and useless to the only consumer this key has ever
                 * had: the link, which opens an event and cannot be
                 * built without one.
                 */
                'event' => $target['event'],
            ),
            'span_to' => null,
        );
    }

    /**
     * Proposals about this value, from either direction.
     *
     * `Value::proposalsFor` is the union and the argument for it; this
     * turns each row into a claim. The lane is thin — 23 proposals on
     * the whole instance — and real, which is why it is a lane and not
     * a chip: a proposal is dated, and every other dated thing on this
     * tab has an axis.
     *
     * **Every row is `latest` and not `exact`.** `shadow_attributes`
     * has no `created` column; it has one `timestamp`, and MISP
     * rewrites it on every change to the proposal. So the mark is where
     * the proposal *last moved*, and the precision chip is the tab's
     * existing way of saying exactly that.
     *
     * **`deleted = 1` means resolved, and cannot say how.** Accepting a
     * proposal and discarding one both end at `setDeleted`
     * (`ShadowAttribute.php:510`, reached from the accept path at
     * `:991` and `:1024` and from discard at `:1075`), and that method
     * writes `deleted = 1` **and stamps `timestamp` with the moment it
     * ran**. Two consequences the rows carry rather than smooth over:
     * a resolved proposal sits on the axis at its resolution and not at
     * its proposal, and no row may say *withdrawn*, because the schema
     * that would tell withdrawn from accepted does not exist.
     *
     * Epoch zero is excluded rather than plotted in 1970, as the
     * publications lane excludes it. `timestamp` is `NOT NULL
     * DEFAULT 0`, so the row is possible; none of this instance's 23 is
     * one, which makes it a branch written from the schema rather than
     * from an observation.
     *
     * @param array $user
     * @param string $value
     * @param array|null $window
     * @return array
     */
    private function timelineProposalEntries(array $user, $value,
        array $window = null
    ) {
        $rows = $this->model('Value')->proposalsFor($user, $value);
        $entries = array();
        foreach ($rows as $row) {
            if ($row['timestamp'] <= 0) {
                continue;
            }
            $entries[] = array(
                'at' => gmdate('Y-m-d H:i:s', $row['timestamp']),
                'source' => 'proposal',
                'precision' => 'latest',
                'title' => $this->proposalClaim($row),
                'note' => $this->proposalNote($row),
                'org' => $row['org'],
                'ref' => array(
                    /*
                     * A standalone addition proposes a value no
                     * attribute holds yet, so the reader is sent to the
                     * event's proposal list rather than to a record
                     * that does not exist — `value-intelligence-coverage.md`
                     * §2.2's state, reaching the link as well as the
                     * row.
                     */
                    'kind' => $row['target'] === null
                        ? 'event'
                        : 'attribute',
                    /*
                     * The attribute it proposes against, which is null
                     * for a standalone addition — the state
                     * `value-intelligence-coverage.md` §2.2 found the rest
                     * of this page blind to, and the one row shape here
                     * that has no attribute to point at.
                     */
                    'attribute' => $row['target'] === null
                        ? null
                        : $row['target']['id'],
                    'event' => $row['event_id'],
                ),
                'span_to' => null,
            );
        }
        return $this->timelineLane($entries, array('proposal'), array(),
            $window);
    }

    /**
     * What one proposal proposes, in a phrase.
     *
     * Four shapes, and the third is the one the union exists for: a
     * proposal that would replace one value with another is about both
     * of them, and the arrow is what tells the reader which end of it
     * they are standing on.
     *
     * @param array $row One `Value::proposalsFor` record
     * @return string
     */
    private function proposalClaim(array $row)
    {
        if ($row['to_delete']) {
            return sprintf(
                __('%1$s — proposes deleting %2$s'),
                $row['org'],
                $row['value']
            );
        }
        if ($row['target'] === null) {
            return sprintf(
                __('%1$s — proposes adding %2$s %3$s'),
                $row['org'],
                $row['type'],
                $row['value']
            );
        }
        if ($row['target']['value'] !== $row['value']) {
            return sprintf(
                __('%1$s — proposes %2$s → %3$s'),
                $row['org'],
                $row['target']['value'],
                $row['value']
            );
        }
        return sprintf(
            __('%1$s — proposes editing %2$s'),
            $row['org'],
            $row['value']
        );
    }

    /**
     * Whether the proposal is still open, and what it hangs off.
     *
     * @param array $row One `Value::proposalsFor` record
     * @return string
     */
    private function proposalNote(array $row)
    {
        $state = $row['deleted']
            ? __(
                'Resolved on this date — accepted or discarded, and'
                . ' MISP records only that it closed.'
            )
            : __('Still open.');
        $where = $row['target'] === null
            ? __('A standalone addition, which no attribute stands'
                . ' behind.')
            : sprintf(
                __('Proposed against attribute %s.'),
                $row['target']['id']
            );
        return $state . ' ' . $where;
    }

    /**
     * Event reports on the events this value sits in.
     *
     * The same union half the analyst lane takes and for the same
     * reason: a report is written about an event, nothing addresses a
     * value, and what this tab can honestly place on an axis is *a
     * report was written about an event this value is in*. So every row
     * names its event, exactly as an event-level note does.
     *
     * **Through `fetchReports` and never `attachReportCountsToEvents`.**
     * That method's non-site-admin branch ANDs
     * `distribution IN (1,2,3,5)` with `distribution = 4` where an
     * `'OR' =>` was intended (`EventReport.php:392-407`), so it returns
     * 0 for every event the viewer's org does not own. It ships, it is
     * visible on the event index and the event view, it is on the
     * standing do-not-fix list — and this lane reads through the
     * correct `buildACLConditions` rather than inheriting the defect
     * into a fifth surface.
     *
     * **`latest`, like the proposals lane and for a weaker reason.**
     * `event_reports` has no `created` either; `timestamp` is set on
     * create and rewritten by `EventReport::touch()` on every edit. The
     * asymmetry with proposals is worth knowing: a soft-deleted report
     * saves only its `deleted` column, so a withdrawn report keeps the
     * date of its last content edit, where a resolved proposal is
     * stamped with its resolution.
     *
     * @param array $user
     * @param array $context From `timelineContext`
     * @param array|null $window
     * @return array
     */
    private function timelineReportEntries(array $user, array $context,
        array $window = null
    ) {
        if (empty($context['scope']['events'])) {
            return $this->timelineLane(array(), array('report'), array(),
                $window);
        }
        $rows = $this->model('EventReport')->fetchReports(
            $user,
            array('conditions' => array(
                'EventReport.event_id' => $context['scope']['events'],
            ))
        );
        /*
         * The events that actually carry a report, and no wider: the
         * levels feed `sharingGroupNames`, whose whole promise is that
         * it queries only when a row could need a name. No fetch of its
         * own — `timelineContext` already read every event in scope.
         */
        $events = array();
        foreach ($rows as $row) {
            $id = (int)$row['EventReport']['event_id'];
            if (!isset($context['events'][$id])) {
                continue;
            }
            $events[$id] = array(
                'distribution' => $context['events'][$id]['distribution'],
                'sharing_group_id' =>
                    $context['events'][$id]['sharing_group_id'],
            );
        }
        $names = $this->sharingGroupNames(
            $user,
            array(),
            self::reportChainLevels($rows, $events)
        );
        $entries = array();
        foreach ($rows as $row) {
            $report = $row['EventReport'];
            $stamp = (int)$report['timestamp'];
            if ($stamp <= 0) {
                continue;
            }
            $eventId = (int)$report['event_id'];
            /*
             * The creator organisation off the contained event, which
             * is the same attribution every other row on this tab
             * carries — and the report has no org of its own to offer.
             */
            $org = isset($row['Event']['Orgc']['name'])
                ? $row['Event']['Orgc']['name']
                : __('Unknown organisation');
            $entries[] = array(
                'at' => gmdate('Y-m-d H:i:s', $stamp),
                'source' => 'report',
                'precision' => 'latest',
                'title' => sprintf(
                    __('%1$s — “%2$s”'),
                    $org,
                    $report['name']
                ),
                'note' => self::timelineReportNote(
                    $report,
                    $eventId,
                    isset($events[$eventId]) ? $events[$eventId] : null,
                    $names
                ),
                'org' => $org,
                'ref' => array(
                    'kind' => 'report',
                    'attribute' => null,
                    'event' => $eventId,
                ),
                'span_to' => null,
            );
        }
        return $this->timelineLane($entries, array('report'), array(),
            $window);
    }

    /**
     * What a report row says under its title.
     *
     * The Collaboration tab's report list resolves who can see a report
     * rather than print its own `distribution`, which is `5` on every
     * report nobody narrowed. These are the same records on a second
     * surface, and a chronology whose report rows say nothing about
     * reach beside a panel whose rows do is the page disagreeing with
     * itself about what a row owes the reader.
     *
     * **A clause and not a badge.** The row is already a grid of four
     * parts — time, source chip, title, precision chip — and a badge on
     * the one lane of ten that could carry one would make the list
     * ragged for a fact that is not the reason anybody is reading a
     * chronology. The note line is where a row explains itself, and it
     * takes the audience in the same lowercase voice as the rest of it.
     *
     * The other lanes are left alone deliberately: an audit row's
     * record has a level this fetch does not hold, a sighting has
     * visibility rules and no distribution column, and analyst data at
     * level 5 is not *inherit* at all — `AnalystData::buildConditions`
     * excludes it, so a note stored at 5 is org-only and reading it as
     * inheritance would be a new claim rather than a resolved one.
     *
     * @param array $report The `EventReport` row
     * @param int $eventId
     * @param array|null $event distribution, sharing_group_id
     * @param array $names id => name, for the groups this viewer sees
     * @return string
     */
    private static function timelineReportNote(array $report, $eventId,
        $event, array $names
    ) {
        $audience = self::reportAudience($report, $event, $names);
        $reach = ValueStatsTool::levelLabel(
            $audience['level'],
            $audience['sharing_group_name']
        );
        /*
         * The level words join a lowercase clause; a sharing group's
         * name is somebody's proper noun and keeps the case they gave
         * it.
         */
        if ((int)$audience['level'] !== 4) {
            $reach = mb_strtolower($reach);
        }
        if ($audience['source'] === 'event') {
            $reach = sprintf(__('%s, from the event'), $reach);
        }
        return sprintf(
            empty($report['deleted'])
                ? __('event report on event %1$s · %2$s')
                : __('withdrawn event report on event %1$s · %2$s'),
            $eventId,
            $reach
        );
    }

    /**
     * What the tab promises and MISP cannot place on any axis.
     *
     * Three kinds, and they are not the same kind of missing. Tags and
     * galaxy clusters have no date column in any schema MISP ships, so
     * no setting and no upgrade would date them. Feed appearances have
     * exactly one timestamp per feed, rewritten on every refresh
     * (`Feed.php:1573`), which dates the *fetch* rather than the value —
     * a real timestamp answering a different question, which is why it
     * is carried as `as_of` and never as `at`.
     *
     * **Every row carries a stable `key` beside its translated
     * `kind`**, and the template matches on the key: a match on the
     * translated string breaks in any locale that translates the two
     * `__()` calls differently.
     *
     * **The tags are the value's own**, from `attribute_tags` through
     * `Value::ownTagsFor`. An event tag is the event's claim and not the
     * value's, and the strip says *nothing has tagged this value* — so
     * folding `8.8.8.8`'s 69 event-tag rows in would make that sentence
     * false about a value nothing has tagged.
     *
     * @param array $user
     * @param string $value
     * @param array $context
     * @param array $options
     * @return array
     */
    private function timelineUndated(array $user, $value, array $context,
        array $options, array $tagState = array()
    ) {
        $tags = array();
        $clusters = array();
        /*
         * Only the ones the audit log cannot place. A tag with a first
         * attach is on the axis now (§22.7) and listing it here as
         * *never on this axis* would be the panel contradicting itself
         * — and would keep the *named but undatable* count describing
         * rows that are drawn three lines further down.
         */
        foreach ($tagState as $tag) {
            if ($tag['at'] !== null) {
                continue;
            }
            $chip = array(
                'label' => $tag['name'],
                'colour' => $tag['colour'],
            );
            if ($tag['galaxy']) {
                $clusters[] = $chip;
            } else {
                $tags[] = $chip;
            }
        }

        $out = array();
        if (!empty($tags)) {
            $out[] = $this->undatedRow('tags', __('Tags'), $tags, __(
                'Tags the audit log cannot place: nothing dates a tag'
                . ' but an audit row, and these were attached before'
                . ' the log began or by a path that did not log.'
            ), __('no audit row'));
        }
        if (!empty($clusters)) {
            $out[] = $this->undatedRow('clusters', __('Galaxy clusters'),
                $clusters, __(
                    'Clusters the audit log cannot place. A cluster'
                    . ' attachment is a tag underneath and inherits the'
                    . ' same gap.'
                ), __('no audit row'));
        }

        $external = $this->externalPresence($user, $value);
        $feeds = array();
        $feedIds = array();
        foreach ($external['sources'] as $source) {
            $feeds[] = array('label' => $source['name'], 'colour' => null);
            if ($source['scope'] === 'feed') {
                $feedIds[] = $source['id'];
            }
        }
        if (!empty($feeds)) {
            $row = $this->undatedRow('feeds', __('Feed appearances'),
                $feeds, __(
                    'The feed cache is a Redis set of hashes with one'
                    . ' timestamp for the whole feed, rewritten on every'
                    . ' refresh. It dates the fetch, not the value.'
                ));
            $row['as_of'] = $this->feedCacheAsOf($feedIds);
            $out[] = $row;
        }
        return $out;
    }

    /**
     * One off-axis row, with its chips bounded and the bound stated.
     *
     * `193.161.193.99` carries 670 attribute-tag rows, so the strip
     * needs a bound. `count` is the whole number and `chips` is what is drawn:
     * a cap is not a permission, so the difference is something the
     * strip says out loud rather than something it hides.
     *
     * @param string $key Stable, and what the template matches on —
     *                    never the translated `kind`
     * @param string $kind Translated, displayed
     * @param array $chips
     * @param string $reason
     * @return array
     */
    private function undatedRow($key, $kind, array $chips, $reason,
        $suffix = null
    ) {
        return array(
            'key' => $key,
            'kind' => $kind,
            'count' => count($chips),
            'reason' => $reason,
            'chips' => array_slice($chips, 0, self::TIMELINE_CHIP_CAP),
            'as_of' => null,
            /*
             * The three words after the count on the strip. It used to
             * be *no date column* for everything, which stopped being
             * true of a tag the moment §22.7 dated the tag set from the
             * audit log: these are the ones with no row, not a kind
             * MISP cannot date.
             */
            'suffix' => $suffix,
        );
    }

    /**
     * The newest cache timestamp across the feeds holding this value.
     *
     * The newest and not each feed's own, because the row is one row:
     * what it can say honestly is *no fetch is newer than this*, and a
     * per-feed date would be a column the strip has no room for and no
     * question for.
     *
     * `Feed::attachFeedCacheTimestamps` rather than a Redis call of its
     * own — one pipeline, and the key stays spelled in the model that
     * writes it.
     *
     * @param array $feedIds
     * @return string|null `Y-m-d H:i:s`
     */
    private function feedCacheAsOf(array $feedIds)
    {
        if (empty($feedIds)) {
            return null;
        }
        $stubs = array();
        foreach ($feedIds as $id) {
            $stubs[] = array('Feed' => array('id' => $id));
        }
        $newest = null;
        $stamped = $this->model('Feed')->attachFeedCacheTimestamps($stubs);
        foreach ($stamped as $stub) {
            $stamp = (int)$stub['Feed']['cache_timestamp'];
            if ($stamp > 0 && ($newest === null || $stamp > $newest)) {
                $newest = $stamp;
            }
        }
        return $newest === null
            ? null
            : gmdate('Y-m-d H:i:s', $newest);
    }

    /* ==================================================================
     * History
     * ==================================================================
     * One endpoint, one element, and a reader phase 25 built in this
     * tab's shape. `27-history.md` is the phase; §3 there is why three
     * of the design's assumptions do not survive real data, and §7 is
     * which read every key below comes from.
     */

    /**
     * The value's audit history, grouped by occurrence.
     *
     * **Two reads and never one.** The corpus totals, the activity
     * chart and the log's own span describe the *whole* history and are
     * tallied by `auditCountsFor`; the rows the panel draws are the
     * window's and come from `auditRowsFor`. That is phase 25's split
     * (`25-timeline.md` §6) reused wholesale, and it is why this panel
     * can draw two years of bars above eight rows without either number
     * being wrong.
     *
     * **The sections are built from the entries, not from the
     * occurrences.** Walking the occurrence list is a read of 48,255
     * rows on `443`; the window returns entries, and the occurrences
     * they name are a handful — measured at 8 on `443` and 4 on
     * `8.8.8.8`.
     *
     * @param array $user
     * @param string $value
     * @param array $options `window`: `all`, a from/to pair of `Y-m-d`,
     *                       or absent for the default period
     * @return array
     */
    public function forHistory(array $user, $value, array $options = array())
    {
        $this->forget($value);
        $window = self::historyWindow(
            isset($options['window']) ? $options['window'] : null
        );
        /*
         * The one key on this panel that is a fact about the instance
         * rather than about the value, and the one that decides whether
         * anything else runs. `MISP.log_new_audit` defaults to false
         * (`Server.php:6649`), so state 2 is what a default instance
         * renders and it costs nothing to reach.
         */
        $recorded = (bool)Configure::read('MISP.log_new_audit');
        $context = $this->timelineContext($user, $value, $options);
        $visible = count($context['occurrences']);
        if (!$recorded || $visible === 0) {
            return array(
                'value' => $value,
                'history' => $this->historyShell($user, $value, $context,
                    $recorded, $window),
            );
        }

        $scope = $context['scope'];
        /*
         * The two the coverage survey owes this tab, and the only part
         * of the scope the Timeline never assembles. Both are id lists
         * from accessors that have already applied MISP's own gate.
         */
        $scope['proposals'] = array_map(
            'intval',
            array_keys($this->model('Value')->proposalsFor($user, $value))
        );
        $scope['reports'] = $this->historyReportIds($user, $context);

        $counts = $this->auditCountsFor($scope);
        $rows = $this->auditRowsFor($scope, array(
            'limit' => self::HISTORY_ROW_CAP,
            'window' => $window,
            /*
             * The diff, paid for here rather than fetched per row by
             * `AuditLogsController::fullChange` — which cannot serve
             * this panel at all, because it applies `__applyAuditAcl`
             * and would answer 404 for a non-site-admin on rows this
             * page has just rendered. `27-history.md` §9.
             */
            'change' => true,
            'actor_scope' => $context['actor_scope'],
        ));

        return array(
            'value' => $value,
            'history' => $this->historyPanel($rows, $counts, $context,
                $scope, $window, (int)$user['org_id']),
        );
    }

    /**
     * The window this panel renders, resolved.
     *
     * @param mixed $spec `all` for the whole log, a from/to pair of
     *                    `Y-m-d`, or null for the default period
     * @return array|null Null means the whole log
     */
    private static function historyWindow($spec)
    {
        if ($spec === 'all') {
            return null;
        }
        if (is_array($spec) && isset($spec['from']) && isset($spec['to'])) {
            return array(
                'from' => (string)$spec['from'],
                'to' => (string)$spec['to'],
            );
        }
        return self::historyDefaultWindow();
    }

    /**
     * The period the tab lands on, as days rather than as a count.
     *
     * **Kept at 30 days knowing what it renders.** Measured on this
     * instance it leaves `8.8.8.8` — the richest audit history of the
     * demo set — showing 8 rows of 353, and `443` showing 8 of 162,539:
     * the audit log arrives in import bursts, so any fixed window is a
     * lottery and a wider one only moves which month it gambles on. The
     * chart above the control draws the whole span regardless, so what
     * lies outside is visible rather than inferred, and `show all time`
     * is one click. `27-history.md` §3.2.
     *
     * @return array `from`, `to`
     */
    private static function historyDefaultWindow()
    {
        $to = date('Y-m-d');
        return array(
            'from' => date(
                'Y-m-d',
                strtotime(
                    sprintf('-%d days', self::HISTORY_WINDOW_DAYS - 1),
                    strtotime($to)
                )
            ),
            'to' => $to,
        );
    }

    /**
     * The panel where there is nothing to read: the log is off, or this
     * reader holds no occurrence of the value.
     *
     * **The two render identically from `visible === 0` onwards**, which
     * is §14.6 being applied rather than a shortcut. The suppressed
     * state this tab used to draw named the number of occurrences it
     * could not show, and a band that appears only when something is
     * hidden is the same disclosure at one bit — its presence is the
     * signal. So a value whose every occurrence is invisible now renders
     * exactly what a value nobody ever logged renders.
     *
     * `knowable` is state 2's rail card and it is only built for state
     * 2. It costs a sightings read, which is affordable precisely
     * because this branch does no audit work at all: on an instance
     * with `MISP.log_new_audit` off, it is the only query this tab runs.
     *
     * @param array $user
     * @param string $value
     * @param array $context From `timelineContext`
     * @param bool $recorded
     * @param array|null $window
     * @return array
     */
    private function historyShell(array $user, $value, array $context,
        $recorded, $window
    ) {
        $shell = array(
            'recorded' => $recorded,
            'window' => $window,
            'default_window' => self::historyDefaultWindow(),
            'span' => null,
            'chart' => null,
            'entries' => 0,
            'shown' => 0,
            'occurrences' => 0,
            'outside' => 0,
            'visible' => count($context['occurrences']),
            'events' => 0,
            'capped' => false,
            /*
             * The same four groups the populated panel returns, empty
             * rather than absent: a shape that changes between states
             * is a shape every reader of it has to test for.
             */
            'facets' => self::historyFacets(array()),
            'vocab' => self::historyVocab(),
            'groups' => array(),
            'event_entries' => array(),
            'regroups' => array('orgs' => array(), 'fields' => array()),
        );
        if ($recorded) {
            return $shell;
        }
        $edited = null;
        foreach ($context['occurrences'] as $occurrence) {
            $stamp = (int)$occurrence['timestamp'];
            if ($stamp > 0 && ($edited === null || $stamp > $edited)) {
                $edited = $stamp;
            }
        }
        $publications = array();
        foreach ($context['events'] as $event) {
            foreach (array('first_publication', 'publish_timestamp')
                as $key
            ) {
                if (!empty($event[$key])) {
                    $publications[] = (int)$event[$key];
                }
            }
        }
        sort($publications);
        $sightings = $this->sightingContext($user, $value);
        $shell['knowable'] = array(
            'occurrences' => count($context['occurrences']),
            'edited' => $edited,
            'publications' => $publications,
            'sightings' => count($sightings['sightings']),
        );
        return $shell;
    }

    /**
     * The populated panel.
     *
     * @param array $rows From `auditRowsFor` — the window's
     * @param array $counts From `auditCountsFor` — the whole log's
     * @param array $context From `timelineContext`
     * @param array $scope The five id lists
     * @param array|null $window
     * @return array
     */
    private function historyPanel(array $rows, array $counts,
        array $context, array $scope, $window, $viewerOrg = 0
    ) {
        $groups = array();
        $eventEntries = array();
        foreach ($rows as $row) {
            /*
             * An occurrence's own row, or the value's. `auditRow` sets
             * `attribute_id` for `model = 'Attribute'` and nothing else,
             * so the test is the model's and needs no second list — and
             * everything else lands in the section below the rule:
             * event actions, the containing object's, proposals and
             * event reports. All four are things that happened to this
             * value and to no single copy of it, which is the argument
             * `07-history.md` §1 made for the event-level section and
             * which the two new scopes join rather than widen.
             */
            $id = $row['attribute_id'];
            if ($id === null || !isset($context['occurrences'][$id])) {
                $eventEntries[] = $this->historyDecorate($row, $context);
                continue;
            }
            if (!isset($groups[$id])) {
                $occurrence = $context['occurrences'][$id];
                $event = isset($context['events'][$occurrence['event_id']])
                    ? $context['events'][$occurrence['event_id']]
                    : null;
                $groups[$id] = array(
                    'attribute_id' => $id,
                    'event_id' => (int)$occurrence['event_id'],
                    'event_info' => $event === null
                        ? __('Unknown event')
                        : $event['info'],
                    'org' => $event === null
                        ? __('Unknown organisation')
                        : $event['org'],
                    'deleted' => !empty($occurrence['deleted']),
                    'count' => 0,
                    'total' => 0,
                    'last' => null,
                    'mix' => array(),
                    'entries' => array(),
                );
            }
            $row = $this->historyDecorate($row, $context);
            $groups[$id]['entries'][] = $row;
            $groups[$id]['count']++;
            $action = $row['action'];
            $groups[$id]['mix'][$action] = (
                isset($groups[$id]['mix'][$action])
                    ? $groups[$id]['mix'][$action]
                    : 0
            ) + 1;
            if ($groups[$id]['last'] === null
                || $row['created'] > $groups[$id]['last']
            ) {
                $groups[$id]['last'] = $row['created'];
            }
        }

        /*
         * The occurrence's whole-log count, so a section header can say
         * *3 of 11 changes* rather than imply the window is all there
         * is. Bounded by construction: the ids are the sections the
         * window produced, which is single digits on every value
         * measured, where the same question asked of every occurrence
         * is a grouped read over 48,255 of them on `443`.
         */
        $totals = $this->historyOccurrenceTotals(array_keys($groups));
        foreach ($groups as $id => $group) {
            $groups[$id]['total'] = isset($totals[$id])
                ? $totals[$id]
                : $group['count'];
        }
        $groups = array_values($groups);
        usort($groups, function ($a, $b) {
            return strcmp((string)$b['last'], (string)$a['last']);
        });

        $all = array_merge($eventEntries, array());
        foreach ($groups as $group) {
            foreach ($group['entries'] as $row) {
                $all[] = $row;
            }
        }
        $events = array();
        foreach ($all as $row) {
            if ($row['event_id'] !== null) {
                $events[$row['event_id']] = true;
            }
        }
        $visible = count($context['occurrences']);
        return array(
            'recorded' => true,
            'window' => $window,
            'default_window' => self::historyDefaultWindow(),
            /*
             * The log's own bounds and the whole-span chart, both from
             * the aggregate and never from the window: an input that
             * only reached the month the reader has already landed on
             * could not reach the rest of the log.
             */
            'span' => self::historySpan($counts),
            'chart' => self::historyChart($counts),
            'entries' => (int)$counts['total'],
            'shown' => count($all),
            'occurrences' => count($groups),
            /*
             * **Occurrences with no entry in this period**, with no separate
             * count of those never touched at all. That one measured zero on
             * every value on this instance, and the mechanism is why:
             * `AuditLogBehavior` writes an `add` row when an attribute is
             * created, so an occurrence with no history is one that predates
             * the log. Keeping the distinction would cost a grouped read over
             * every occurrence to report a zero, so the panel states the one
             * thing it can state for nothing and that is true either way.
             */
            'outside' => $visible - count($groups),
            'visible' => $visible,
            'events' => count($events),
            /*
             * **Whether the read hit `HISTORY_ROW_CAP`**, and the panel
             * needs it to explain `outside` honestly rather than to
             * apologise for the cap. `outside` is *occurrences with no
             * section*, and there are two reasons an occurrence can
             * have none: nothing of its own in the period, or the cap
             * cut it. Only the first is the period's doing, so a line
             * naming the period while the cap is what bit would be
             * false rather than merely unhelpful — the same mistake
             * §16.2 caught at all time, one step further in.
             */
            'capped' => count($rows) >= self::HISTORY_ROW_CAP,
            'facets' => self::historyFacets($all),
            'vocab' => self::historyVocab(),
            'groups' => $groups,
            'event_entries' => $eventEntries,
            'regroups' => self::historyRegroups($all, (int)$viewerOrg),
        );
    }

    /**
     * The event the row belongs to, named.
     *
     * @param array $row From `auditRow`
     * @param array $context From `timelineContext`
     * @return array
     */
    private function historyDecorate(array $row, array $context)
    {
        $event = $row['event_id'] !== null
                && isset($context['events'][$row['event_id']])
            ? $context['events'][$row['event_id']]
            : null;
        if ($event !== null) {
            $row['event_info'] = $event['info'];
        }
        /*
         * The acting organisation or none. The event's creator is a
         * different organisation, and filing the row under it would
         * put it in the wrong card when grouped by organisation.
         */
        if ($row['org'] === null) {
            $row['org'] = __('Unknown organisation');
            $row['org_id'] = 0;
        }
        $row['field_key'] = self::historyFieldKey($row);
        return $row;
    }

    /**
     * What a row is filed under when the panel groups by field: the
     * fields an edit changed, or for anything else the kind of action.
     *
     * An edit that changed several fields is filed once, under all of
     * them, so every entry still sits in exactly one section.
     *
     * @param array $row
     * @return array `key`, `label`
     */
    private static function historyFieldKey(array $row)
    {
        if ($row['action'] === 'edit' && !empty($row['change'])) {
            $fields = array_column($row['change'], 'field');
            sort($fields);
            return array(
                'key' => 'field:' . implode(',', $fields),
                'label' => implode(', ', $fields),
            );
        }
        $group = AuditActionMeta::group($row['action']);
        if ($group === 'tag') {
            return array('key' => 'kind:tag', 'label' => __('Tags'));
        }
        if ($group === 'cluster') {
            return array(
                'key' => 'kind:cluster',
                'label' => __('Galaxy clusters'),
            );
        }
        return array(
            'key' => 'action:' . $row['action'],
            'label' => AuditActionMeta::label($row['action']),
        );
    }

    /**
     * The sections the panel can regroup its rows into, each tallied
     * over the rendered rows: one per acting organisation, and one per
     * field key.
     *
     * @param array $rows Every rendered row
     * @param int $viewerOrg
     * @return array `orgs`, `fields`
     */
    private static function historyRegroups(array $rows, $viewerOrg)
    {
        $orgs = array();
        $fields = array();
        foreach ($rows as $row) {
            $orgKey = $row['org_id'];
            if (!isset($orgs[$orgKey])) {
                $orgs[$orgKey] = array(
                    'id' => $orgKey,
                    'name' => $row['org'],
                    'own' => $orgKey !== 0 && $orgKey === $viewerOrg,
                    'count' => 0,
                    'last' => null,
                    'mix' => array(),
                    'actors' => array(),
                );
            }
            $fieldKey = $row['field_key']['key'];
            if (!isset($fields[$fieldKey])) {
                $fields[$fieldKey] = array(
                    'key' => $fieldKey,
                    'label' => $row['field_key']['label'],
                    'count' => 0,
                    'last' => null,
                    'mix' => array(),
                );
            }
            foreach (array(&$orgs[$orgKey], &$fields[$fieldKey]) as &$group) {
                $group['count']++;
                $group['mix'][$row['action']] =
                    ($group['mix'][$row['action']] ?? 0) + 1;
                if ($group['last'] === null
                    || $row['created'] > $group['last']
                ) {
                    $group['last'] = $row['created'];
                }
            }
            unset($group);
            if ($row['actor'] !== null) {
                $orgs[$orgKey]['actors'][$row['actor']] = true;
            }
        }
        foreach ($orgs as &$org) {
            $org['actors'] = count($org['actors']);
        }
        unset($org);
        $byCount = function ($a, $b) {
            return $b['count'] - $a['count']
                ?: strcmp((string)$b['last'], (string)$a['last']);
        };
        $orgs = array_values($orgs);
        $fields = array_values($fields);
        usort($orgs, $byCount);
        usort($fields, $byCount);
        return array('orgs' => $orgs, 'fields' => $fields);
    }

    /**
     * Each named occurrence's whole-log entry count.
     *
     * @param array $ids Attribute ids — the sections that were built
     * @return array id => n
     */
    private function historyOccurrenceTotals(array $ids)
    {
        if (empty($ids)) {
            return array();
        }
        $rows = $this->model('AuditLog')->find('all', array(
            'conditions' => array(
                'AuditLog.model' => 'Attribute',
                'AuditLog.model_id' => array_map('intval', $ids),
            ),
            'fields' => array(
                'AuditLog.model_id',
                'COUNT(*) AS n',
            ),
            'group' => array('AuditLog.model_id'),
            'recursive' => -1,
        ));
        $out = array();
        foreach ($rows as $row) {
            $out[(int)$row['AuditLog']['model_id']] = (int)$row[0]['n'];
        }
        return $out;
    }

    /**
     * The ids of the event reports this reader may see on the value's
     * events.
     *
     * @param array $user
     * @param array $context From `timelineContext`
     * @return array
     */
    private function historyReportIds(array $user, array $context)
    {
        if (empty($context['scope']['events'])) {
            return array();
        }
        $rows = $this->model('EventReport')->fetchReports(
            $user,
            array('conditions' => array(
                'EventReport.event_id' => $context['scope']['events'],
            ))
        );
        $ids = array();
        foreach ($rows as $row) {
            $ids[] = (int)$row['EventReport']['id'];
        }
        return $ids;
    }

    /**
     * The log's own bounds for this value, as days.
     *
     * @param array $counts From `auditCountsFor`
     * @return array|null
     */
    private static function historySpan(array $counts)
    {
        if (empty($counts['first']) || empty($counts['last'])) {
            return null;
        }
        return array(
            'from' => substr((string)$counts['first'], 0, 10),
            'to' => substr((string)$counts['last'], 0, 10),
        );
    }

    /**
     * The activity chart, over the whole log.
     *
     * Free: `auditCountsFor` already grouped by day, so this is a fold
     * over rows the aggregate returned rather than a read of its own.
     * The day map is keyed by action *group* for the Timeline's lanes,
     * so it is flattened back to a per-day total here.
     *
     * @param array $counts From `auditCountsFor`
     * @return array|null
     */
    private static function historyChart(array $counts)
    {
        $span = self::historySpan($counts);
        if ($span === null) {
            return null;
        }
        $today = date('Y-m-d');
        $plan = ValueIntelligenceBuckets::plan(
            $span['from'],
            $today,
            self::HISTORY_CHART_RULE
        );
        $days = array();
        foreach ($counts['by_day'] as $day => $byGroup) {
            $days[$day] = array_sum($byGroup);
        }
        $plan['counts'] = ValueIntelligenceBuckets::tally(
            $span['from'],
            $today,
            $days
        );
        return $plan;
    }

    /**
     * The rail, tallied over the rendered rows.
     *
     * The counts describe the period the reader is in, which phase 19's
     * decision 7 settled: the corpus total is on screen once, in the
     * header, and the chart above the control is the signal that
     * activity exists outside the window.
     *
     * @param array $rows The rendered rows
     * @return array
     */
    private static function historyFacets(array $rows)
    {
        $vocab = self::historyVocab();
        $tallies = array(
            'action' => array_fill_keys($vocab['action'], 0),
            'model' => array_fill_keys($vocab['model'], 0),
            'org' => array(),
            'actor' => array(),
        );
        foreach ($rows as $row) {
            foreach (array('action', 'model', 'org') as $key) {
                $key_value = (string)$row[$key];
                $tallies[$key][$key_value] = (
                    isset($tallies[$key][$key_value])
                        ? $tallies[$key][$key_value]
                        : 0
                ) + 1;
            }
            $actor = empty($row['actor'])
                ? sprintf(__('%s (unnamed)'), $row['org'])
                : $row['actor'];
            $tallies['actor'][$actor] = (
                isset($tallies['actor'][$actor])
                    ? $tallies['actor'][$actor]
                    : 0
            ) + 1;
        }
        arsort($tallies['org']);
        arsort($tallies['actor']);
        $out = array();
        foreach ($tallies as $key => $counts) {
            $group = array();
            foreach ($counts as $name => $count) {
                $group[] = array(
                    'label' => $key === 'action'
                        ? AuditActionMeta::label($name)
                        : $name,
                    'value' => trim(preg_replace(
                        '/[^a-z0-9]+/',
                        '-',
                        strtolower((string)$name)
                    ), '-'),
                    'count' => $count,
                );
            }
            $out[$key] = $group;
        }
        return $out;
    }

    /**
     * What the rail orders its rows by, and which of them get a zero
     * row rather than no row.
     *
     * **Read from `AuditActionMeta` rather than listed here**, which is
     * the same single-source move phase 25 made for the lane grouping.
     * A hand-kept list misses actions such as `tag_local` or
     * `publish_sightings`, which then arrive tallied but sorted after
     * the zeros.
     *
     * `undelete` keeps its zero row on this instance, and that is the
     * point of zero rows: *undelete 0* tells the reader nothing was
     * ever undeleted, where an absent row tells them nothing at all.
     *
     * @return array `action`, `model`
     */
    private static function historyVocab()
    {
        return array(
            'action' => AuditActionMeta::actions(),
            'model' => array(
                'Attribute', 'Event', 'Object', 'ShadowAttribute',
                'EventReport',
            ),
        );
    }

    /**
     * The value's audit history: the rows about the objects this viewer
     * may already see, scoped by id.
     *
     * **Neither of the two ACL models MISP ships is adopted whole**,
     * and the History tab inherits this reader rather than negotiating
     * a second one. `AuditLogsController::__applyAuditAcl`
     * (`:356`) restricts a non-admin to their own `user_id`, which is
     * not a scoping of the value's history but a different subject —
     * *my* actions, filtered to this value — and on the verification
     * instance every one of `8.8.8.8`'s 54 rows carries `org_id` ADMIN,
     * so under it every other reader gets an empty tab and no way to
     * tell that from a quiet value. `__createEventIndexConditions`
     * (`:488`) is the right subject and the wrong cost: it runs a full
     * `fetchEvent()` per event to enumerate the ids the viewer may see,
     * and then reads the events' whole audit history — 204
     * `fetchEvent()` calls over 816,041 rows on `193.161.193.99`, of
     * which 1,007 are about the value.
     *
     * So: three model scopes over id sets `Value` has already run
     * `buildConditions($user)` over.
     *
     * ```
     * model = 'Attribute' AND model_id IN $scope['attributes']
     * model = 'Object'    AND model_id IN $scope['objects']
     * model = 'Event'     AND model_id IN $scope['events']
     * ```
     *
     * **One statement per scope, merged in PHP, and both the split and
     * the third line's column are measured rather than tidy** —
     * `auditScopeQueries` has why each is 10× to 100× the whole cost of
     * this reader on `443`.
     *
     * **Why this is safe and not merely cheap.** For any viewer and any
     * event this returns a *subset* of what
     * `__createEventIndexConditions` would hand them on that event's
     * own audit index: that model grants every `model = 'Event'` row
     * plus the rows for the attributes, objects, proposals and
     * references the viewer may see, and this asks for the same thing
     * narrowed to the occurrences of one value. The page discloses
     * nothing MISP does not already disclose on a page that ships. It
     * costs no `fetchEvent()` because the narrowing that model pays
     * `fetchEvent()` to compute is the narrowing `Value`'s accessors
     * have already done. The claim is a subset claim, which is why it
     * is falsifiable: a viewer class for whom this returns *more* than
     * that model would grant on the same event reopens the decision.
     *
     * **What it drops, and the tab says so.** Sibling rows — an edit to
     * another attribute in an event this value sits in is not this
     * value's history. `ShadowAttribute` and `ObjectReference` rows,
     * which that model includes for an event: proposals reach the
     * Timeline as their own dated lane and need no audit row, and
     * object references do not reach it. And nothing is scoped by
     * `model_title`: an occurrence edited *into* this value carries
     * rows describing what it was before, they are that occurrence's
     * rows and they are shown, and the row names the occurrence and the
     * action rather than the title. Scoping by title would be both
     * wrong — `model_title` prefers the new value — and a scan, since
     * it is an unindexed `text` column.
     *
     * The rows come from a plain read and the counts from an aggregate,
     * and both take the id set from `Value`, so permissions were settled
     * before `audit_logs` was touched.
     *
     * @param array $scope `attributes`, `objects`, `events`: id lists
     * @param array $options `limit` (rows; null for no cap), `change`
     *                       to pay for the diff blobs, `order`
     * @return array History-shaped rows, newest first
     */
    private function auditRowsFor(array $scope, array $options = array())
    {
        $cap = array_key_exists('limit', $options)
            ? $options['limit']
            : null;
        $rows = array();
        foreach ($this->auditScopeQueries($scope) as $query) {
            foreach ($this->auditRead($query, $cap, $options) as $row) {
                $rows[] = $row;
            }
        }
        /*
         * Each scope was read newest-first under the same cap, so the
         * global newest `$cap` rows are a subset of the union of the
         * per-scope newest `$cap` — which is what makes merging in PHP
         * here exact rather than approximate. The merged set is at most
         * three chunks' worth of caps, so this sorts hundreds of rows
         * and never the 172,426 the aggregate counted.
         */
        usort($rows, function ($a, $b) {
            if ($a['created'] === $b['created']) {
                return $b['id'] - $a['id'];
            }
            return strcmp($b['created'], $a['created']);
        });
        if ($cap !== null && count($rows) > $cap) {
            $rows = array_slice($rows, 0, (int)$cap);
        }
        return $rows;
    }

    /**
     * One scope's worth of rows.
     *
     * @param array $query From `auditScopeQueries`
     * @param int|null $cap
     * @param array $options As `auditRowsFor`
     * @return array
     */
    private function auditRead(array $query, $cap, array $options)
    {
        $audit = $this->model('AuditLog');
        /*
         * `change` is a brotli blob that `AuditLog::afterFind` decodes
         * per row, so it is opt-in: the Timeline's chronology names the
         * occurrence and the action and never the diff, and making it
         * pay 1,000 decompressions for a column it does not
         * render is the kind of cost that hides inside a shared
         * reader.
         * The History tab, whose rows *are* the diff, asks for it.
         */
        $fields = array(
            'AuditLog.id',
            'AuditLog.created',
            'AuditLog.action',
            'AuditLog.model',
            'AuditLog.model_id',
            'AuditLog.model_title',
            'AuditLog.event_id',
            'AuditLog.org_id',
            'AuditLog.user_id',
            'AuditLog.request_type',
        );
        if (!empty($options['change'])) {
            $fields[] = 'AuditLog.change';
        }
        $params = array(
            'conditions' => $query['conditions'],
            'fields' => $fields,
            'contain' => array(
                // Both, and for the reason phase 24 recorded against
                // `AnalystData::rearrangeOrganisation`: a reader that
                // re-queries per row for the name reports every row as
                // an unknown organisation the moment the association
                // is absent.
                'Organisation' => array('fields' => array(
                    'Organisation.id',
                    'Organisation.name',
                )),
                'User' => array('fields' => array(
                    'User.id',
                    'User.email',
                )),
            ),
            /*
             * `id DESC` and not `created DESC`. Neither column is
             * indexed on `audit_logs`, so both sort; `id` is the
             * primary key, it is monotonic in `created` because the
             * table is append-only, and ordering by it lets a tie
             * inside one second come out in the order it happened.
             */
            'order' => isset($options['order'])
                ? $options['order']
                : array('AuditLog.id' => 'DESC'),
            'recursive' => -1,
        );
        /*
         * A window narrows the read rather than the result, and it has
         * to: the cap below is a `LIMIT` on an `id DESC` read, so a
         * caller that filtered afterwards would be filtering the newest
         * cap-many rows of the whole scoped set — and find none of them
         * in any window older than that reaches.
         *
         * `created` is not indexed (see the order note above), so this
         * buys no speed. The scan is already bounded by the
         * `model`/`model_id` index to the value's own rows, which is
         * what `auditCountsFor` scans to count them.
         */
        if (!empty($options['window'])) {
            $params['conditions']['AuditLog.created >='] =
                $options['window']['from'] . ' 00:00:00';
            $params['conditions']['AuditLog.created <='] =
                $options['window']['to'] . ' 23:59:59';
        }
        if ($cap !== null) {
            $params['limit'] = (int)$cap;
        }
        $rows = array();
        $actorScope = array_key_exists('actor_scope', $options)
            ? $options['actor_scope']
            : null;
        foreach ($audit->find('all', $params) as $row) {
            $rows[] = $this->auditRow($row, $actorScope);
        }
        return $rows;
    }

    /**
     * The diff, in the field/was/is shape the History tab renders.
     *
     * **The row carries it and no second request fetches it.**
     * `07-history.md` §10 nominated `AuditLogsController::fullChange`
     * for this, and that endpoint cannot serve this panel: its first
     * line is `__applyAuditAcl`, which restricts a non-site-admin to
     * their own `user_id`, so against an instance where one
     * organisation wrote 98% of the audit log it answers 404 for almost
     * every diff the panel has just rendered. `27-history.md` §9.
     *
     * `AuditLog::afterFind` has already decompressed and JSON-decoded
     * the blob into `field => values`, where `values` is `[was, is]` on
     * an edit and a bare value on an add or a removal. It answers the
     * literal string `Compressed` where the row was brotli-compressed
     * and the extension is absent — 11.8% of this instance's rows are
     * above `AuditLog::COMPRESS_MIN_LENGTH`, so that is a real branch
     * and not a defensive one.
     *
     * @param array $log One `AuditLog` row, `change` decoded
     * @return array|null
     */
    private static function auditChangeRows(array $log)
    {
        $change = $log['change'];
        if (empty($change) || !is_array($change)) {
            return null;
        }
        $removes = in_array($log['action'], self::AUDIT_REMOVES, true);
        $rows = array();
        foreach ($change as $field => $values) {
            if (is_array($values)) {
                $was = isset($values[0]) ? $values[0] : '';
                $is = isset($values[1]) ? $values[1] : '';
            } elseif ($removes) {
                $was = $values;
                $is = '';
            } else {
                $was = '';
                $is = $values;
            }
            $rows[] = array(
                'field' => (string)$field,
                'was' => self::auditChangeValue($field, $was),
                'is' => self::auditChangeValue($field, $is),
            );
        }
        return empty($rows) ? null : $rows;
    }

    /**
     * One side of a diff, rendered the way MISP's own change element
     * renders it — so the same edit reads the same on both pages.
     *
     * @param string $field
     * @param mixed $value
     * @return string
     */
    private static function auditChangeValue($field, $value)
    {
        if ($value === '' || $value === null) {
            return '';
        }
        if (is_array($value)) {
            return JsonTool::encode($value);
        }
        if (is_numeric($value)
            && (strpos($field, 'timestamp') !== false
                || in_array($field, self::AUDIT_DATE_FIELDS, true))
        ) {
            $at = date('Y-m-d H:i:s', (int)$value);
            return $at === false ? (string)$value : $at;
        }
        if (is_numeric($value)
            && ($field === 'first_seen' || $field === 'last_seen')
        ) {
            // Microsecond epochs, the same arithmetic
            // `Elements/AuditLog/change.ctp` does.
            return gmdate('Y-m-d\TH:i:s', (int)((int)$value / 1000000))
                . '.' . str_pad((string)((int)$value % 1000000), 6, '0',
                    STR_PAD_LEFT);
        }
        return (string)$value;
    }

    /**
     * Which actors this reader may be named to, as a set of user ids.
     *
     * **Null means every actor**, which is what a site admin gets and
     * what `AuditLogsController::eventIndex` gives them by skipping its
     * own redaction entirely. For everyone else it is the ids of the
     * users in their own organisation — the same
     * `User.find('column')` that controller runs, hoisted so a
     * multi-scope read pays for it once instead of once per statement.
     *
     * A row whose actor is not in the set keeps its organisation and
     * loses its address, which is the shape `auditRow`'s null path and
     * both panels' *`<org> (unnamed)`* wording already handle — chosen
     * in phase 25 for the deleted-account case, and the same answer for
     * the same reason: which organisation acted is the part that
     * survives.
     *
     * @param array $user
     * @return array|null id => true, or null for no redaction
     */
    private function auditActorScope(array $user)
    {
        if (!empty($user['Role']['perm_site_admin'])) {
            return null;
        }
        $ids = $this->model('User')->find('column', array(
            'conditions' => array('User.org_id' => $user['org_id']),
            'fields' => array('User.id'),
        ));
        $scope = array();
        foreach ($ids as $id) {
            $scope[(int)$id] = true;
        }
        return $scope;
    }

    /**
     * The same three scopes, grouped rather than read.
     *
     * An aggregate rather than a read, and the reasons are that the
     * answer is a group, the id set was ACL'd before it ran, and
     * materialising `443`'s 162,539 rows to count them in PHP is the
     * wrong shape — a tally over the fetched page also stops being
     * honest the moment the list paginates.
     *
     * **Grouped by day**, and the grain is the whole reason this is
     * affordable rather than three queries. A day answers every
     * question the panel asks — the spine bins days into whatever width
     * its range wants, the lane grid sums the days inside the window,
     * and the header sums all of them — where a month grain answers
     * only the last of those and would need a second, date-bounded
     * aggregate for a window that straddles two months, which the
     * default one does. `443`'s eleven months come back as roughly two
     * thousand rows, which is a few kilobytes and one round trip.
     *
     * Also grouped by action, because the edit lane's own breakdown
     * reads it and a stack segment is a source.
     *
     * **And the day map is keyed by `AuditActionMeta::group`**, which
     * costs nothing here — the grouping was already by day *and*
     * action, so the split is a different fold over the same rows —
     * and is what lets three lanes come out of one aggregate. A flat
     * per-day total cannot be divided afterwards.
     *
     * `first_by_action` is per action rather than per group, because
     * the one question asked of it is about `add` alone: when this
     * value's oldest surviving record was created here.
     *
     * @param array $scope As `auditRowsFor`
     * @return array `total`, `by_day` (`Y-m-d` => group => n),
     *               `by_action`, `by_group`, `first_by_action`,
     *               `first`, `last`
     */
    private function auditCountsFor(array $scope)
    {
        $counts = array(
            'total' => 0,
            'by_day' => array(),
            'by_action' => array(),
            'by_group' => array(),
            'first_by_action' => array(),
            'first_by_group' => array(),
            'last_by_group' => array(),
            'first' => null,
            'last' => null,
        );
        $audit = $this->model('AuditLog');
        foreach ($this->auditScopeQueries($scope) as $query) {
            $rows = $audit->find('all', array(
                'conditions' => $query['conditions'],
                'fields' => array(
                    'DATE(AuditLog.created) AS day',
                    'AuditLog.action',
                    'COUNT(*) AS n',
                    'MIN(AuditLog.created) AS first_c',
                    'MAX(AuditLog.created) AS last_c',
                ),
                'group' => array('day', 'AuditLog.action'),
                'order' => array('day' => 'ASC'),
                'recursive' => -1,
            ));
            foreach ($rows as $row) {
                $day = $row[0]['day'];
                $action = $row['AuditLog']['action'];
                $group = AuditActionMeta::group($action);
                $n = (int)$row[0]['n'];
                $counts['total'] += $n;
                if (!isset($counts['by_day'][$day])) {
                    $counts['by_day'][$day] = array();
                }
                $counts['by_day'][$day][$group] = (
                    isset($counts['by_day'][$day][$group])
                        ? $counts['by_day'][$day][$group]
                        : 0
                ) + $n;
                if (!isset($counts['by_action'][$action])) {
                    $counts['by_action'][$action] = 0;
                }
                $counts['by_action'][$action] += $n;
                if (!isset($counts['by_group'][$group])) {
                    $counts['by_group'][$group] = 0;
                }
                $counts['by_group'][$group] += $n;
                if (!isset($counts['first_by_action'][$action])
                    || $row[0]['first_c']
                        < $counts['first_by_action'][$action]
                ) {
                    $counts['first_by_action'][$action]
                        = $row[0]['first_c'];
                }
                /*
                 * Each group's own range, because each is now a lane
                 * and a lane's range is what bands the span its capped
                 * rows could not reach (§19). The global pair below
                 * stays, since the range the spine covers is the union.
                 */
                if (!isset($counts['first_by_group'][$group])
                    || $row[0]['first_c']
                        < $counts['first_by_group'][$group]
                ) {
                    $counts['first_by_group'][$group]
                        = $row[0]['first_c'];
                }
                if (!isset($counts['last_by_group'][$group])
                    || $row[0]['last_c']
                        > $counts['last_by_group'][$group]
                ) {
                    $counts['last_by_group'][$group] = $row[0]['last_c'];
                }
                if ($counts['first'] === null
                    || $row[0]['first_c'] < $counts['first']
                ) {
                    $counts['first'] = $row[0]['first_c'];
                }
                if ($counts['last'] === null
                    || $row[0]['last_c'] > $counts['last']
                ) {
                    $counts['last'] = $row[0]['last_c'];
                }
            }
        }
        ksort($counts['by_day']);
        return $counts;
    }

    /**
     * The three model scopes, one query each — never OR-ed.
     *
     * An empty list yields no query at all, which is the difference
     * between *this value has no history* and *every row in
     * `audit_logs`*: an empty `IN` set rendered into a condition would
     * read the whole table.
     *
     * **Both columns are `model_id`, including the event scope**, where
     * `event_id` is the obvious name and the wrong one. `event_id` is
     * indexed and `model` is not, so it looks like the column to use;
     * but MISP writes it on *every* model's rows — an `Attribute` row
     * carries the event it belongs to — so `event_id IN (…)` matches the
     * whole audit history of those events and filters `model` from each
     * row afterwards. On `443`'s 1,844 events that is 816,041 rows read
     * to return 9,493: **14,330 ms**, against **129 ms** for `model_id`
     * over the same ids. It is sound because `event_id` and `model_id`
     * are the same
     * number on every `model = 'Event'` row — verified over all 28,048
     * of them, none null — and the two forms return the identical
     * 9,493 rows.
     *
     * @param array $scope `attributes`, `objects`, `events`: id lists
     * @return array One entry per statement: `model`, `conditions`
     */
    private function auditScopeQueries(array $scope)
    {
        $byModel = array(
            'Attribute' => isset($scope['attributes'])
                ? $scope['attributes']
                : array(),
            'Object' => isset($scope['objects'])
                ? $scope['objects']
                : array(),
            'Event' => isset($scope['events'])
                ? $scope['events']
                : array(),
            /*
             * The two the coverage survey owes the History tab, and
             * absent from every Timeline call — that tab reaches
             * proposals and reports as their own dated lanes and needs
             * no audit row for either. A caller that passes neither key
             * gets exactly the three statements phase 25 measured.
             *
             * Both are gated before they arrive: the proposal ids come
             * from `Value::proposalsFor`, which applies
             * `ShadowAttribute::buildConditions`, and the report ids
             * from `EventReport::fetchReports`. `27-history.md` §13.
             */
            'ShadowAttribute' => isset($scope['proposals'])
                ? $scope['proposals']
                : array(),
            'EventReport' => isset($scope['reports'])
                ? $scope['reports']
                : array(),
        );
        $queries = array();
        foreach ($byModel as $model => $ids) {
            $ids = array_values(array_unique(array_map('intval', $ids)));
            if (empty($ids)) {
                continue;
            }
            foreach (array_chunk($ids, self::AUDIT_ID_CHUNK) as $chunk) {
                $queries[] = array(
                    'model' => $model,
                    'conditions' => array(
                        'AuditLog.model' => $model,
                        'AuditLog.model_id' => $chunk,
                    ),
                );
            }
        }
        return $queries;
    }

    /**
     * One `audit_logs` row in the shape both tabs read.
     *
     * The shape is the History tab's, so both tabs render one row the
     * same way.
     *
     * @param array $row From `AuditLog::find`
     * @param array|null $actorScope From `auditActorScope`: null where
     *                               every actor may be named, otherwise
     *                               a set of user ids that may be,
     *                               keyed by id
     * @return array
     */
    private function auditRow(array $row, $actorScope = null)
    {
        $log = $row['AuditLog'];
        $org = isset($row['Organisation']['name'])
            ? $row['Organisation']['name']
            : null;
        $actor = isset($row['User']['email'])
            ? $row['User']['email']
            : null;
        /*
         * The redaction `AuditLogsController::eventIndex` applies, and
         * the reason it has to be applied here too. That controller
         * strips `User` from every row whose actor is outside the
         * viewer's organisation, for any non-site-admin — after
         * `paginate()`, in the controller, and **not** in
         * `__createEventIndexConditions`. So a reader that inherits
         * that model's *conditions* inherits none of its redaction, and
         * phase 25's subset claim — which is a claim about which rows —
         * does not cover what each row carries. Measured on this
         * instance: three ADMIN users wrote 9,325,454 of 9,512,515
         * rows, so without this a CIRCL org admin reads
         * `admin@admin.test` on rows MISP's own audit index shows them
         * no actor for at all. `27-history.md` §8.
         */
        if ($actorScope !== null
            && $actor !== null
            && !isset($actorScope[(int)$log['user_id']])
        ) {
            $actor = null;
        }
        return array(
            /*
             * Carried, and not only for completeness: the three-scope
             * merge breaks a same-second tie on it, and it is the only
             * stable identity an audit row has.
             */
            'id' => (int)$log['id'],
            'created' => $log['created'],
            'action' => $log['action'],
            'model' => $log['model'],
            'model_id' => (int)$log['model_id'],
            'model_title' => $log['model_title'],
            /*
             * Null where the row's user is gone, and the caller says
             * *<org> (unnamed)* rather than *unknown*: which
             * organisation acted is the part that survived a deleted
             * account, and it is also all a non-site-admin gets from
             * `__applyAuditAcl` for anyone outside their own org.
             */
            'actor' => $actor,
            'org' => $org,
            'org_id' => empty($log['org_id']) ? 0 : (int)$log['org_id'],
            'request_type' => (int)$log['request_type'],
            /*
             * A tag or galaxy row's blob is the join row's ids; the
             * subject already names what was attached.
             */
            'change' => array_key_exists('change', $log)
                    && !in_array($log['action'], self::AUDIT_SUBJECT, true)
                ? self::auditChangeRows($log)
                : null,
            'renamed' => false,
            'subject' => in_array($log['action'], self::AUDIT_SUBJECT, true)
                ? $log['model_title']
                : null,
            'note' => null,
            'event_id' => $log['event_id'] === null
                ? null
                : (int)$log['event_id'],
            'event_info' => null,
            'attribute_id' => $log['model'] === 'Attribute'
                ? (int)$log['model_id']
                : null,
        );
    }

    /* ==================================================================
     * Analyst data
     * ==================================================================
     * Notes and opinions hang off an `object_uuid`. A value's is
     * `Value::uuidFor()` of its text, one per spelling, so both panels
     * are a union assembled here over the value's spellings and the
     * things the value is *in*; there is no single query behind either
     * of them, and there is no pagination across them.
     */

    /**
     * Where the organisations stand on this value.
     *
     * **Reads the whole thread, not only the opinions.** Two of the
     * ledger's columns are properties of the thread rather than of the
     * opinion — how many notes an organisation wrote, and when it was
     * last heard from — so an endpoint that read opinions alone would
     * ship a *Notes* column counting nothing. The note above these two
     * actions in `ValuesController` expected this panel to be the cheap
     * one; live, it is the same union as the thread's.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forAnalystStanding(array $user, $value,
        array $options = array()
    ) {
        return array(
            'value' => $value,
            'analyst' => $this->analystContext($user, $value, $options),
        );
    }

    /**
     * The argument, in the order it happened.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forAnalystThread(array $user, $value,
        array $options = array()
    ) {
        $context = $this->analystContext($user, $value, $options);
        return array(
            'value' => $value,
            'analyst' => $context,
            /*
             * The composer's disabled *Attach to* picker states how
             * many occurrences it would offer. Counted off the union
             * this request already read rather than fetched again, so
             * the number the picker names and the set the notes were
             * looked up against cannot disagree.
             */
            'occurrence_stats' => array(
                'shown' => $context['occurrences'],
            ),
        );
    }

    /**
     * The Overview's preview of the Collaboration tab.
     *
     * **Off `analystContext` and never its own union**, so a reader
     * never meets one set of counts on the Overview and a different set
     * one tab across. Two readings of one union cannot disagree; two
     * unions can.
     *
     * **The cost is the tab's, and this card can afford it** for the
     * reason the tab bar's badge could not (§11 of `26-analyst.md`, and
     * the pill question settled the same way on 2026-09-05). The union
     * is five anchor kinds over two tables, 5 to 26 queries — a price
     * for a lazily-loaded panel a reader is looking at, and not for a
     * number on a tab bar that renders on every page load whether or
     * not anybody opens the tab.
     *
     * **Notes and opinions, and proposals only as a count.** The card
     * draws what it says it draws; a proposal is somebody's edit rather
     * than somebody's writing, and the change strip that makes one
     * legible is the tab's. But the *empty* state has to know about
     * them, because *nobody has written about this value* over a value
     * carrying three open proposals is the one sentence this card must
     * not print. They come free — the union already holds them.
     *
     * **Event reports, also only as a count, and that one is not
     * free.** `29-overview.md` §10 routed the count to the Overview and
     * the list to the tab, and named this card over a seventh fact cell
     * because it already mirrors the tab that holds the list; §14.8
     * deferred it as an amendment to a built panel. It costs the one
     * query `analystReportCount` runs, over the event ids the anchor
     * read already returned.
     *
     * **And the standing, since phase 35, which is free.** The card
     * draws the tab's tug-bar over it — the one object on the
     * Collaboration tab that is a shape rather than a list, and the
     * one thing on this card that is not capped at four items. A value
     * with two notes and six opinions can fill the preview with notes
     * and show the reader no opinion at all; the bar is over every
     * opinion either way.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forAnalystPreview(array $user, $value,
        array $options = array()
    ) {
        $context = $this->analystContext($user, $value, $options);
        $context['preview'] = self::analystPreviewItems($context['thread']);
        $context['counts']['reports'] = $this->analystReportCount(
            $user,
            $context['events']
        );
        /*
         * The thread is dropped on the way out. The card renders four
         * items and the union can hold hundreds; carrying the rest so
         * the template can ignore them is the Overview paying the
         * tab's memory for a panel that shows a handful.
         *
         * **The ledger is kept, and phase 35 is what gave it a
         * reader.** It was built and then discarded here, which the
         * note this replaces called the cheaper mistake; the card now
         * draws the tug-bar off it. It is one row per opinion that
         * rates the value — four on the flagship, one on `127.0.0.1`,
         * none at all on four of the five values `31-query-count.php`
         * measures — so keeping it costs no query and no meaningful
         * memory, and it is the *same* array the tab reads rather
         * than a second count of the same opinions.
         */
        unset($context['thread'], $context['events']);
        return array(
            'value' => $value,
            'analyst' => $context,
        );
    }

    /**
     * The newest few notes and opinions, in one order.
     *
     * **Newest first across both kinds.** Drawing every note above
     * every opinion would have a card titled *the most recent* put a
     * two-year-old note above yesterday's opinion. One union, read
     * newest first, is what the thread beside it already does.
     *
     * Roots only, and proposals excluded. A reply is a statement about
     * the item above it rather than about the value, and the card has
     * no room to draw what it answers — the same exclusion the standing
     * panel's aggregate makes, and for the same reason.
     *
     * @param array $thread From `analystContext`
     * @return array
     */
    private static function analystPreviewItems(array $thread)
    {
        $items = array();
        foreach ($thread as $item) {
            if ($item['kind'] === 'proposal') {
                continue;
            }
            // The replies go with them, so "roots only" is a property
            // of what leaves this method rather than of what the
            // template remembers not to draw.
            unset($item['children'], $item['max_depth_reached']);
            $items[] = $item;
            if (count($items) >= self::ANALYST_PREVIEW_CAP) {
                break;
            }
        }
        return $items;
    }

    /**
     * The event reports written about this value's events.
     *
     * **The third panel on the tab, and the one that is a list rather
     * than an argument.** `value-intelligence-coverage.md` §4.5 places
     * reports here — narrative analyst content about the value's
     * context, beside the notes and opinions — and it is a separate
     * panel rather than more thread items because a report is a
     * document, not a turn in a conversation: dropping a 5,000-word
     * report between two one-line notes buries both.
     *
     * **Every row is about an event, and says so.** Nothing addresses
     * a value, so what this panel can honestly state is *a report was
     * written about an event this value is in* — the same half-union
     * the thread's event anchors take, and the same sentence phase 25's
     * report lane carries.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forAnalystReports(array $user, $value,
        array $options = array()
    ) {
        $events = $this->analystEventIds($user, $value, $options);
        return array(
            'value' => $value,
            'analyst_reports' => $this->analystReports(
                $user,
                $events['ids']
            ) + array('occurrence_capped' => $events['capped']),
        );
    }

    /**
     * The tab's fourth panel: what analysts typed into the `comment`
     * column of this value's occurrences.
     *
     * **The one thing written *about the value itself* on this page.**
     * Every other item on this tab is anchored to a uuid — a note on an
     * event, an opinion on a note, a report on an event — and the tab
     * spends a chip per row saying so. A comment is a column on the
     * occurrence, so for once the sentence *somebody wrote this about
     * this value* needs no qualification. It is also, on this instance,
     * by far the most common form of analyst writing: 2,108,595
     * attributes carry a comment against 75 notes and 43 opinions in
     * total.
     *
     * **One row per distinct sentence, not per occurrence.**
     * `Value::commentsFor` carries the argument and the instance's own
     * numbers; what it means here is that the panel is a table of
     * statements with counts, rather than 1,459 repetitions of one.
     *
     * **A comment has no author and no date of its own.** Its only
     * attribution is the creating organisation of the event its
     * attribute sits in, and its only date is the occurrence's — which
     * is a row write, moved by any later edit to any other column. Both
     * are stated in those words on the panel rather than dressed up as
     * *written by* and *written on*.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function forAnalystComments(array $user, $value,
        array $options = array()
    ) {
        $valueModel = $this->model('Value');
        $summary = $valueModel->commentSummaryFor($user, $value, $options);
        $groups = $valueModel->commentsFor(
            $user,
            $value,
            array_merge($options, array(
                'limit' => self::ANALYST_COMMENT_CAP,
            ))
        );
        $orgIds = array();
        $eventIds = array();
        foreach ($groups as $group) {
            $orgIds[] = $group['orgc_id'];
            $eventIds[$group['event_id']] = true;
        }
        $orgs = $this->organisationNames(array(), $orgIds);
        $events = $this->commentEventNames($user, array_keys($eventIds));
        $rows = array();
        foreach ($groups as $group) {
            $eventId = $group['event_id'];
            /*
             * A group whose named event did not survive
             * `fetchSimpleEvents` keeps its counts and loses its link.
             * Unreachable in practice — the ids come from a read the
             * same viewer's ACL already passed — and the alternative is
             * dropping a sentence somebody wrote over a belt-and-braces
             * check disagreeing with the braces.
             */
            $resolved = isset($orgs[$group['orgc_id']]);
            $rows[] = $group + array(
                'org' => $resolved
                    ? $orgs[$group['orgc_id']]
                    : __('Unknown organisation'),
                /*
                 * The id the cell links on, and null where there is
                 * nothing to open — an event whose `orgc_id` names an
                 * organisation that no longer exists. Stated as its own
                 * key rather than left to the template to derive from
                 * `orgc_id`, because *which organisation wrote this*
                 * and *is there a page for it* are two questions and
                 * the grouped read answers only the first: `orgc_id` is
                 * always set, since it is what the rows were grouped
                 * by. Same shape and same guard as the report list's.
                 */
                'org_id' => $resolved ? $group['orgc_id'] : null,
                'event' => isset($events[$eventId])
                    ? $events[$eventId]
                    : null,
            );
        }
        return array(
            'value' => $value,
            'analyst_comments' => array(
                'rows' => $rows,
                /*
                 * How many distinct sentences exist, not how many this
                 * table drew — the aggregate's own number, so a capped
                 * list states the remainder it is short by rather than
                 * reporting its own length as the total.
                 */
                'total' => $summary['comments'],
                'capped' => $summary['comments'] > count($rows),
                /*
                 * And how many rows carry one, which is a different
                 * number and the one a reader compares against the
                 * occurrence count in the fact strip.
                 */
                'occurrences' => $summary['occurrences'],
                'events' => $summary['events'],
            ),
        );
    }

    /**
     * The events the comment table links to, by id.
     *
     * `fetchSimpleEvents` rather than the ids alone, for the two things
     * a link needs that an aggregate cannot carry: the event's `info`,
     * so the chip names what it opens, and a second pass of
     * `createEventConditions` over ids that came from an ACL'd read.
     * One call for the whole table — §14.4's commitment is never one
     * call per row.
     *
     * @param array $user
     * @param array $ids
     * @return array event id => ['id' => int, 'info' => string]
     */
    private function commentEventNames(array $user, array $ids)
    {
        if (empty($ids)) {
            return array();
        }
        $events = $this->model('Event')->fetchSimpleEvents(
            $user,
            array('conditions' => array('Event.id' => $ids)),
            true
        );
        $out = array();
        foreach ($events as $event) {
            $out[(int)$event['Event']['id']] = array(
                'id' => (int)$event['Event']['id'],
                'info' => isset($event['Event']['info'])
                    ? $event['Event']['info']
                    : null,
            );
        }
        return $out;
    }

    /**
     * How many event reports the tab's third panel will list.
     *
     * The Overview's preview of the Collaboration tab states this as a
     * number and the tab states it as documents, so what this must not
     * be is a second opinion: it runs `EventReport::buildACLConditions`
     * — the conditions `fetchReports` itself applies, and the reason
     * both routed around `attachReportCountsToEvents` — over the event
     * ids the preview's own anchor read returned. Same reader, same
     * events, same predicate, so the card's count and the panel's
     * headline agree by construction rather than by luck.
     *
     * **A count and not the rows.** `analystReports` materialises every
     * report to render four lines of each; this needs one integer, and
     * fetching rows to call `count()` on them is the trap `22-occurrences
     * .md` §4.1 names. `find('count')` contains `Event` because the ACL
     * conditions are spelled on its columns and are not expressible
     * without the join.
     *
     * **Withdrawn reports are in it**, because the number this mirrors
     * is the panel's `total`, which counts them and then qualifies
     * itself with *N withdrawn* beside it. A subtitle chip has no room
     * for the qualifier, and a count that silently meant something
     * narrower than the panel's would be the cross-panel disagreement
     * this whole card exists to have stopped.
     *
     * @param array $user
     * @param array $eventIds From `analystAnchors`
     * @return int
     */
    private function analystReportCount(array $user, array $eventIds)
    {
        if (empty($eventIds)) {
            return 0;
        }
        $model = $this->model('EventReport');
        $conditions = $model->buildACLConditions($user);
        $conditions['AND'][] = array(
            'EventReport.event_id' => $eventIds,
        );
        return (int)$model->find('count', array(
            'conditions' => $conditions,
            'contain' => array('Event'),
            'recursive' => -1,
        ));
    }

    /**
     * The events this value occurs in, for a panel that needs no other
     * anchor. One query, and never the cluster resolution the thread's
     * union pays for.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array ids => event ids, capped => whether the occurrence
     *               read stopped at its cap
     */
    private function analystEventIds(array $user, $value,
        array $options = array()
    ) {
        $occurrences = $this->model('Value')->occurrenceUuidsFor(
            $user,
            $value,
            array_merge($options, array(
                'limit' => self::ANALYST_OCCURRENCE_CAP,
                'order' => self::OCCURRENCE_ORDER,
            ))
        );
        $ids = array();
        foreach ($occurrences as $occurrence) {
            $ids[$occurrence['event_id']] = true;
        }
        return array(
            'ids' => array_keys($ids),
            'capped' => count($occurrences)
                >= self::ANALYST_OCCURRENCE_CAP,
        );
    }

    /**
     * The reports, newest first.
     *
     * **Through `fetchReports` and never
     * `EventReport::attachReportCountsToEvents`.** That method's
     * non-site-admin branch ANDs `distribution IN (1,2,3,5)` with
     * `distribution = 4` where an `'OR' =>` was intended
     * (`EventReport.php:392-407`), so it returns 0 for every event the
     * viewer's org does not own. It ships and it is on the standing
     * do-not-fix list; phase 25's report lane routed around it and this
     * panel does the same rather than inherit the defect into a fifth
     * surface.
     *
     * **`timestamp` is when the report last changed, not when it was
     * written.** `event_reports` has no `created` column and
     * `EventReport::touch()` rewrites the one it has on every edit. A
     * soft-deleted report saves only its `deleted` column, so a
     * withdrawn report keeps the date of its last content edit — the
     * asymmetry with a resolved proposal, which *is* stamped at
     * resolution, is worth knowing and both rows say which they are.
     *
     * @param array $user
     * @param array $eventIds
     * @return array
     */
    private function analystReports(array $user, array $eventIds)
    {
        $out = array(
            'rows' => array(),
            'events' => count($eventIds),
            'total' => 0,
            'withdrawn' => 0,
            'capped' => false,
        );
        if (empty($eventIds)) {
            return $out;
        }
        $rows = $this->model('EventReport')->fetchReports(
            $user,
            array('conditions' => array(
                'EventReport.event_id' => $eventIds,
            ))
        );
        $events = $this->reportEventAudiences($user, $rows);
        $names = $this->sharingGroupNames(
            $user,
            array(),
            self::reportChainLevels($rows, $events)
        );
        $reports = array();
        foreach ($rows as $row) {
            $report = $row['EventReport'];
            $withdrawn = !empty($report['deleted']);
            if ($withdrawn) {
                $out['withdrawn']++;
            }
            $content = (string)$report['content'];
            $eventId = (int)$report['event_id'];
            $event = isset($events[$eventId]) ? $events[$eventId] : null;
            $reports[] = array(
                'id' => (int)$report['id'],
                'name' => $report['name'],
                'event' => array(
                    'id' => $eventId,
                    'info' => isset($row['Event']['info'])
                        ? $row['Event']['info']
                        : null,
                    'distribution' => $event === null
                        ? null
                        : $event['distribution'],
                    'sharing_group' => $event !== null
                            && $event['distribution'] === 4
                            && isset($names[$event['sharing_group_id']])
                        ? $names[$event['sharing_group_id']]
                        : null,
                ),
                /*
                 * Who can actually see the report, rather than what its
                 * own column says — which is `5`, *inherit*, on every
                 * report nobody narrowed, because that is the shipped
                 * default (`EventReport.php:91`). The chain is report →
                 * event and `EventReport::buildACLConditions` enforces
                 * the conjunction of the two, so it resolves through
                 * the same helper an occurrence's three links do.
                 */
                'audience' => self::reportAudience(
                    $report,
                    $event,
                    $names
                ),
                'org' => isset($row['Event']['Orgc']['name'])
                    ? $row['Event']['Orgc']['name']
                    : __('Unknown organisation'),
                // The event's creator org, which is a report's only
                // attribution — it has no organisation of its own.
                'org_id' => empty($row['Event']['Orgc']['id'])
                    ? null
                    : (int)$row['Event']['Orgc']['id'],
                'at' => (int)$report['timestamp'] > 0
                    ? gmdate('Y-m-d', (int)$report['timestamp'])
                    : null,
                'distribution' => (int)$report['distribution'],
                'sharing_group' => isset($row['SharingGroup']['name'])
                    ? $row['SharingGroup']['name']
                    : null,
                'withdrawn' => $withdrawn,
                /*
                 * The head of the report rather than the report. A
                 * report has no length limit and this panel shows a
                 * list; carrying every byte of every one of them to
                 * render four lines of each is the cost that would make
                 * the panel worth not opening.
                 */
                'head' => mb_substr($content, 0, self::ANALYST_REPORT_HEAD),
                'length' => mb_strlen($content),
            );
        }
        $out['total'] = count($reports);
        usort($reports, function ($a, $b) {
            $byDate = strcmp((string)$b['at'], (string)$a['at']);
            return $byDate !== 0 ? $byDate : $a['id'] - $b['id'];
        });
        if (count($reports) > self::ANALYST_REPORT_CAP) {
            $out['capped'] = true;
            $reports = array_slice($reports, 0,
                self::ANALYST_REPORT_CAP);
        }
        $out['rows'] = $reports;
        return $out;
    }

    /**
     * What each report's event states about its own audience.
     *
     * `EventReport::DEFAULT_CONTAIN` fetches six event columns and
     * `distribution` is not among them, so the level a report defers to
     * is not on the row `fetchReports` returns. One keyed read of the
     * events that actually carry a report — a handful, against the
     * value's whole event scope — rather than widening a contain four
     * other surfaces share.
     *
     * Through `fetchSimpleEvents`, which re-applies
     * `createEventConditions`. The ids came from an ACL'd read already,
     * so this is belt and braces rather than the barrier; it costs one
     * primary-key lookup and means no event's level can be read off a
     * row this viewer should not have.
     *
     * @param array $user
     * @param array $rows fetchReports-shaped
     * @return array event id => distribution, sharing_group_id
     */
    private function reportEventAudiences(array $user, array $rows)
    {
        $ids = array();
        foreach ($rows as $row) {
            $ids[(int)$row['EventReport']['event_id']] = true;
        }
        if (empty($ids)) {
            return array();
        }
        $events = $this->model('Event')->fetchSimpleEvents(
            $user,
            array('conditions' => array('Event.id' => array_keys($ids)))
        );
        $out = array();
        foreach ($events as $event) {
            $out[(int)$event['Event']['id']] = array(
                'distribution' => (int)$event['Event']['distribution'],
                'sharing_group_id' =>
                    (int)$event['Event']['sharing_group_id'],
            );
        }
        return $out;
    }

    /**
     * Every level the reports panel could resolve to, so
     * `sharingGroupNames` can decide whether any of them needs a name.
     *
     * @param array $rows fetchReports-shaped
     * @param array $events From `reportEventAudiences`
     * @return array
     */
    private static function reportChainLevels(array $rows, array $events)
    {
        $levels = array();
        foreach ($rows as $row) {
            $levels[] = (int)$row['EventReport']['distribution'];
        }
        foreach ($events as $event) {
            $levels[] = $event['distribution'];
        }
        return $levels;
    }

    /**
     * Who can see one report, resolved against the event it is on.
     *
     * A report at level 5 states nothing and defers outward, exactly as
     * an attribute does — and unlike an attribute it is *usually* at 5,
     * because that is what `MISP.default_eventreport_distribution`
     * ships as. A badge reading `Inherit event` on nearly every row is
     * a badge that never answers the question it occupies space to ask.
     *
     * The event link is dropped where the event did not resolve rather
     * than assumed: `resolveChain` then reports a null level, and the
     * panel says the report defers without naming a level nobody
     * confirmed.
     *
     * @param array $report The `EventReport` row
     * @param array|null $event From `reportEventAudiences`
     * @param array $names id => name, for the groups this viewer sees
     * @return array As `ValueStatsTool::resolveChain`
     */
    private static function reportAudience(array $report, $event,
        array $names
    ) {
        $links = array(array(
            'scope' => 'report',
            'label' => __('Report'),
            'level' => (int)$report['distribution'],
            'sharing_group_id' => isset($report['sharing_group_id'])
                ? (int)$report['sharing_group_id']
                : null,
        ));
        if ($event !== null) {
            $links[] = array(
                'scope' => 'event',
                'label' => __('Event'),
                'level' => $event['distribution'],
                'sharing_group_id' => $event['sharing_group_id'],
            );
        }
        return ValueStatsTool::resolveChain($links, $names);
    }

    /**
     * The union, the thread over it, and the two readings of it.
     *
     * One method for both endpoints because they are two readings of
     * one set: a standing panel assembled from a different union than
     * the thread beside it would be a panel a reader could catch out by
     * counting.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    private function analystContext(array $user, $value,
        array $options = array()
    ) {
        $anchors = $this->analystAnchors($user, $value, $options);
        $thread = self::analystNewestFirst(array_merge(
            $this->analystThreadItems($user, $anchors['targets']),
            $this->analystProposalItems($user, $value)
        ));
        return array(
            'occurrences' => $anchors['occurrences'],
            'capped' => $anchors['capped'],
            'counts' => $this->analystCounts($thread),
            'standing' => $this->analystStanding($thread),
            'thread' => $thread,
            // The anchor read's events, for the one caller that counts
            // something attached to an event rather than to a uuid.
            'events' => $anchors['events'],
        );
    }

    /**
     * Everything a note or an opinion about this value can hang off.
     *
     * Phase 24's triple — the occurrence, the event it is in, the
     * object it sits in — widened by the value's galaxy clusters.
     * `26-analyst.md` D1. The triple costs no query beyond the
     * occurrence read: `occurrenceUuidsFor` already joins `Event` and
     * `Object` to satisfy the ACL, so their uuids come back with it.
     *
     * **Keyed by uuid and never by `object_type`.** One `notes` row on
     * the verification instance carries `object_type = 'Event1556'`, a
     * type that is not a type, and its `object_uuid` resolves to no
     * event, attribute or object at all — MISP's own UI wrote it. Any
     * reader that switched on the type would have to treat that set as
     * closed, and it is not.
     *
     * **Relationships are deliberately not an anchor.** Two opinions on
     * this instance rate a `Relationship`, and neither is reachable
     * from here: D1's set is the triple plus clusters, and a claim
     * about the value is phase 24's panel rather than this tab's. The
     * cost is those two rows, and it is named in `26-analyst.md` §5.1
     * rather than absorbed.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array targets => uuid => attachment, occurrences => int
     */
    private function analystAnchors(array $user, $value,
        array $options = array()
    ) {
        $occurrences = $this->model('Value')->occurrenceUuidsFor(
            $user,
            $value,
            array_merge($options, array(
                'limit' => self::ANALYST_OCCURRENCE_CAP,
                'order' => self::OCCURRENCE_ORDER,
            ))
        );
        $targets = array();
        foreach ($this->valueAnchorUuids($user, $value) as $uuid => $spelling) {
            $targets[$uuid] = array(
                'kind' => 'value',
                'value' => $spelling,
                'spelled' => $spelling === (string)$value ? null : $spelling,
            );
        }
        $attributeIds = array();
        $eventIds = array();
        foreach ($occurrences as $uuid => $occurrence) {
            $targets[$uuid] = array(
                'kind' => 'attribute',
                'type' => $occurrence['type'],
                'event' => $occurrence['event_id'],
            );
            $attributeIds[$occurrence['id']] = true;
            $eventIds[$occurrence['event_id']] = true;
            if (!empty($occurrence['event_uuid'])
                && !isset($targets[$occurrence['event_uuid']])
            ) {
                $targets[$occurrence['event_uuid']] = array(
                    'kind' => 'event',
                    'event' => $occurrence['event_id'],
                );
            }
            if (!empty($occurrence['object_uuid'])
                && !isset($targets[$occurrence['object_uuid']])
            ) {
                $targets[$occurrence['object_uuid']] = array(
                    'kind' => 'object',
                    'name' => $occurrence['object_name'],
                    'event' => $occurrence['event_id'],
                );
            }
        }
        return array(
            'targets' => $targets + $this->analystClusterAnchors(
                $user,
                array_keys($attributeIds),
                array_keys($eventIds)
            ),
            /*
             * The events this read reached, handed out rather than
             * recomputed. The preview's report count is over exactly
             * this set, and a second occurrence read to rebuild it
             * could return a different one — the cap orders by
             * timestamp, so the count would be over events the union
             * beside it did not look for notes on.
             */
            'events' => array_keys($eventIds),
            'occurrences' => count($occurrences),
            /*
             * The union is built from the newest cap-many occurrences,
             * so on a value past the cap a note written on one this
             * read did not reach is a note the tab cannot show. `443`
             * has 48,255 occurrences and reaches 19 events; the panel
             * says so rather than presenting a slice as the whole.
             */
            'capped' => count($occurrences) >= self::ANALYST_OCCURRENCE_CAP,
        );
    }

    /**
     * The uuids analyst data names this value by: its own spelling's, and
     * those of the other spellings of its group that an attribute the
     * reader can see holds. Only visibly held spellings, so a note on a
     * spelling nobody visibly holds cannot say the instance stores it.
     *
     * @param array $user
     * @param string $value
     * @return array uuid => spelling, the page's own spelling first
     */
    private function valueAnchorUuids(array $user, $value)
    {
        $value = (string)$value;
        $spellings = array($value);
        $dictionary = $this->model('AttributeValue');
        $ids = $dictionary->resolveCi(array($value))[$value] ?? array();
        if (!empty($ids)) {
            $visible = $this->model('MispAttribute')->visibleValueIds(
                $user,
                $ids,
                count($ids)
            );
            foreach (empty($visible) ? array() : $dictionary->fetchValues($visible) as $text) {
                $spellings[] = (string)$text;
            }
        }
        $uuids = array();
        foreach ($spellings as $spelling) {
            $uuid = Value::uuidFor($spelling);
            if (!isset($uuids[$uuid])) {
                $uuids[$uuid] = $spelling;
            }
        }
        return $uuids;
    }

    /**
     * The value's galaxy clusters, as anchors.
     *
     * Six notes and opinions on the verification instance are written
     * about a `GalaxyCluster`, and phase 24's claim reader already
     * counts a plain galaxy *tag* on the value's events — so counting
     * the tag while dropping an authored statement about the cluster it
     * names was the omission this closes.
     *
     * Both levels of tag, because both are the value's: a galaxy tag on
     * the occurrence classifies the value itself, and one on its event
     * classifies the neighbourhood the value is part of, which is the
     * same argument that admits event-level notes at all.
     *
     * `fetchGalaxyClusters` rather than a `galaxy_clusters` read,
     * because a cluster has its own distribution and this is the reader
     * that applies it.
     *
     * @param array $user
     * @param array $attributeIds
     * @param array $eventIds
     * @return array uuid => attachment
     */
    private function analystClusterAnchors(array $user,
        array $attributeIds, array $eventIds
    ) {
        $names = array();
        $collect = function ($rows) use (&$names) {
            foreach ($rows as $row) {
                if (!empty($row['Tag']['is_galaxy'])
                    && !empty($row['Tag']['name'])
                ) {
                    $names[$row['Tag']['name']] = true;
                }
            }
        };
        $tagFields = array(
            'Tag' => array('fields' => array('Tag.name', 'Tag.is_galaxy')),
        );
        if (!empty($attributeIds)) {
            $collect($this->model('AttributeTag')->find('all', array(
                'conditions' => array(
                    'AttributeTag.attribute_id' => $attributeIds,
                ),
                'recursive' => -1,
                'contain' => $tagFields,
            )));
        }
        if (!empty($eventIds)) {
            $collect($this->model('EventTag')->find('all', array(
                'conditions' => array('EventTag.event_id' => $eventIds),
                'recursive' => -1,
                'contain' => $tagFields,
            )));
        }
        if (empty($names)) {
            return array();
        }
        $rows = $this->model('GalaxyCluster')->fetchGalaxyClusters(
            $user,
            array('conditions' => array(
                'GalaxyCluster.tag_name' => array_slice(
                    array_keys($names),
                    0,
                    self::ANALYST_GALAXY_TAG_CAP
                ),
            ))
        );
        $targets = array();
        foreach ($rows as $row) {
            $cluster = $row['GalaxyCluster'];
            if (empty($cluster['uuid'])) {
                continue;
            }
            $targets[$cluster['uuid']] = array(
                'kind' => 'cluster',
                'name' => empty($cluster['value'])
                    ? $cluster['tag_name']
                    : $cluster['value'],
                'event' => null,
                /*
                 * So the chip can open the cluster. `galaxy_clusters/view/<id>`
                 * is the address three other panels on this page already
                 * use for the same record.
                 */
                'id' => (int)$cluster['id'],
            );
        }
        return $targets;
    }

    /**
     * The thread, read one level at a time.
     *
     * **Never `AnalystData::fetchChildNotesAndOpinions`**, and the
     * second reason is the one that matters. It is two finds per item
     * per level, which is the cost phase 24 already recorded on
     * `Relationship`; and `$fetchedUUIDFromRecursion`
     * (`AnalystData.php:65`) is instance state that nothing clears
     * within a request, so a second walk over a uuid already seen
     * returns no children. For MISP's own view, which walks one root,
     * that is a correct cycle guard. For a union over many anchors it
     * means the replies a page draws depend on the order it happened to
     * iterate — an output that changes for a reason the reader cannot
     * see. Routed around here and reported rather than patched:
     * `26-analyst.md` §7.2.
     *
     * One read per level over the whole frontier, plus one past the
     * last rendered level — which is what makes the template's *anything
     * written below this one is flagged but not fetched* a measurement
     * rather than an assumption.
     *
     * @param array $user
     * @param array $targets From `analystAnchors`
     * @return array Root items, newest first, children nested
     */
    private function analystThreadItems(array $user, array $targets)
    {
        if (empty($targets)) {
            return array();
        }
        $items = array();
        $roots = array();
        $children = array();
        $frontier = array_keys($targets);
        for ($depth = 0; $depth <= self::ANALYST_THREAD_DEPTH; $depth++) {
            $next = array();
            foreach ($this->analystRowsFor($user, $frontier) as
                $parent => $byType
            ) {
                foreach ($byType as $type => $rows) {
                    foreach ($rows as $row) {
                        if (empty($row['uuid'])
                            || isset($items[$row['uuid']])
                        ) {
                            continue;
                        }
                        $items[$row['uuid']] = $this->analystItemFrom(
                            $type,
                            $row,
                            $depth === 0
                                ? (isset($targets[$parent])
                                    ? $targets[$parent]
                                    : null)
                                : array(
                                    'kind' => 'reply',
                                    'to' => isset($items[$parent])
                                        ? $items[$parent]['kind']
                                        : 'note',
                                )
                        );
                        if ($depth === 0) {
                            $roots[] = $row['uuid'];
                        } else {
                            $children[$parent][] = $row['uuid'];
                        }
                        $next[] = $row['uuid'];
                    }
                }
            }
            $frontier = $next;
            if (empty($frontier)) {
                return $this->analystNest($items, $roots, $children);
            }
        }
        foreach ($this->analystRowsFor($user, $frontier) as
            $parent => $ignored
        ) {
            if (isset($items[$parent])) {
                $items[$parent]['max_depth_reached'] = true;
            }
        }
        return $this->analystNest($items, $roots, $children);
    }

    /**
     * Every note and opinion written on any of these uuids.
     *
     * Two queries whatever the frontier's width, which is the whole
     * point of reading per level.
     *
     * @param array $user
     * @param array $uuids
     * @return array parent uuid => type => rows
     */
    private function analystRowsFor(array $user, array $uuids)
    {
        $found = array();
        foreach (array('Note', 'Opinion') as $type) {
            $rows = $this->model($type)->fetchForUuids($uuids, $user);
            foreach ($rows as $parent => $byType) {
                if (empty($byType[$type])) {
                    continue;
                }
                $found[$parent][$type] = $byType[$type];
            }
        }
        return $found;
    }

    /**
     * One `notes` or `opinions` row as a thread item.
     *
     * **What an opinion rates is decided here** (`26-analyst.md` D4):
     * an opinion written on a note, or on another opinion, rates *that
     * row*. It is drawn, because a disagreement about a disagreement is
     * part of who says what; and it is kept out of the aggregate,
     * because the aggregate answers the narrower question of where
     * organisations stand on the value. The standing panel says so, so
     * that a reader counting opinions in the thread finds the
     * difference explained rather than apparent.
     *
     * `$target` is null only where an anchor resolved to nothing. The
     * row is still drawn, with an unresolved target — D5. Dropping it
     * would let a write the instance accepted vanish from the one page
     * whose subject is who said what.
     *
     * @param string $type `Note` or `Opinion`
     * @param array $row One `fetchForUuids` record
     * @param array|null $target The attachment, or null if unresolved
     * @return array
     */
    private function analystItemFrom($type, array $row, $target)
    {
        $isOpinion = $type === 'Opinion';
        $score = $isOpinion ? (int)$row['opinion'] : null;
        $ratesValue = $target !== null && $target['kind'] !== 'reply';
        /*
         * **Named from the row, grouped by the uuid.** Eleven of this
         * instance's 75 notes carry an `orgc_uuid` that matches no
         * organisation — the org was deleted, and the contained
         * association comes back empty — so *Unknown organisation* is
         * a path live data takes rather than a defensive branch. Two
         * such organisations must not merge into one lane on the
         * ledger merely because neither has a name left to tell them
         * apart, so the grouping key is the uuid and the label is only
         * what gets printed.
         */
        $org = __('Unknown organisation');
        foreach (array('Orgc', 'Org') as $which) {
            if (!empty($row[$which]['name'])) {
                $org = $row[$which]['name'];
                break;
            }
        }
        $key = __('Unknown organisation');
        foreach (array('orgc_uuid', 'org_uuid') as $which) {
            if (!empty($row[$which])) {
                $key = $row[$which];
                break;
            }
        }
        // Null where the organisation no longer resolves, which is the
        // same eleven rows §6.4 is about: no name to print and no page
        // to open either.
        $orgId = null;
        foreach (array('Orgc', 'Org') as $which) {
            if (!empty($row[$which]['id'])) {
                $orgId = (int)$row[$which]['id'];
                break;
            }
        }
        return array(
            'kind' => $isOpinion ? 'opinion' : 'note',
            'org' => $org,
            'org_key' => $key,
            'org_id' => $orgId,
            'author' => empty($row['authors'])
                ? __('unattributed')
                : $row['authors'],
            'date' => substr($row['created'], 0, 10),
            'distribution' => (int)$row['distribution'],
            'sharing_group' => empty($row['SharingGroup']['name'])
                ? null
                : $row['SharingGroup']['name'],
            /*
             * `language` defaults to `en` in the schema and is a
             * natural-language code, not a markup flag — the chip only
             * earns its place when the author changed it.
             */
            'language' => $isOpinion || empty($row['language'])
                || $row['language'] === 'en'
                    ? null
                    : $row['language'],
            'score' => $score,
            'rates' => $ratesValue ? 'value' : 'note',
            'body' => $isOpinion
                ? (string)$row['comment']
                : (string)$row['note'],
            'attached_to' => $target === null
                ? array('kind' => 'unresolved', 'event' => null)
                : $target,
            'children' => array(),
            'max_depth_reached' => false,
            'label' => $isOpinion ? self::opinionBandFor($score) : null,
            'reads' => $isOpinion && $ratesValue
                ? self::opinionReadsFor($score)
                : 'none',
        );
    }

    /**
     * The flat set, nested and ordered newest first at every level.
     *
     * @param array $items uuid => item
     * @param array $roots
     * @param array $children parent uuid => child uuids
     * @return array
     */
    private function analystNest(array $items, array $roots,
        array $children
    ) {
        $build = function ($uuid) use (&$build, $items, $children) {
            $item = $items[$uuid];
            if (!empty($children[$uuid])) {
                foreach ($children[$uuid] as $child) {
                    $item['children'][] = $build($child);
                }
                $item['children'] = self::analystNewestFirst(
                    $item['children']
                );
            }
            return $item;
        };
        $out = array();
        foreach ($roots as $uuid) {
            $out[] = $build($uuid);
        }
        return self::analystNewestFirst($out);
    }

    /**
     * @param array $items
     * @return array
     */
    private static function analystNewestFirst(array $items)
    {
        usort($items, function ($a, $b) {
            return strcmp($b['date'], $a['date']);
        });
        return $items;
    }

    /**
     * What the thread contains, counted rather than declared.
     *
     * Top-level items are what the tab counts, because a reply is
     * written on an item and not on the value.
     *
     * @param array $thread
     * @return array
     */
    private function analystCounts(array $thread)
    {
        $counts = array(
            'items' => count($thread),
            'opinions' => 0,
            'notes' => 0,
            'proposals' => 0,
            'replies' => 0,
        );
        foreach ($thread as $item) {
            if ($item['kind'] === 'opinion') {
                $counts['opinions']++;
            } elseif ($item['kind'] === 'proposal') {
                $counts['proposals']++;
            } else {
                $counts['notes']++;
            }
        }
        self::analystWalk($thread, function ($item) use (&$counts) {
            $counts['replies'] += count($item['children']);
        });
        return $counts;
    }

    /**
     * @param array $thread
     * @param callable $fn Called with every item at every depth
     * @return void
     */
    private static function analystWalk(array $thread, $fn)
    {
        foreach ($thread as $item) {
            $fn($item);
            if (!empty($item['children'])) {
                self::analystWalk($item['children'], $fn);
            }
        }
    }

    /**
     * The ledger and the aggregate over it.
     *
     * **A row is an opinion, not an organisation**, and that is a
     * finding rather than a preference. The built ledger
     * (`05-analyst.md` §16.3) draws one lane per organisation, which
     * assumes an organisation holds one position; on this instance the
     * campaign's own default value carries four opinions and all four
     * are ADMIN's — 100, 100, 80, then 10. Rolled up to one lane that
     * value would draw a single disputing organisation over a set that
     * is three-quarters agreement, and the tug-bar's clause would read
     * *every organisation disputes*. So every opinion gets its lane,
     * an organisation's lanes sit together, and the sub-line's *N
     * opinions from M organisations* is what tells the reader the two
     * counts differ.
     *
     * Groups are ordered by their strongest opinion and the rows inside
     * a group by score, so the panel still reads highest-first as a
     * scale — which is what the third sort click restores.
     *
     * @param array $thread
     * @return array orgs => rows, aggregate => array|null
     */
    private function analystStanding(array $thread)
    {
        $notes = array();
        $last = array();
        $opinions = array();
        self::analystWalk($thread, function ($item) use (
            &$notes,
            &$last,
            &$opinions
        ) {
            /*
             * A proposal is not a position on the value and not a
             * note, and its date is when it last *moved* — so it
             * neither counts in the Notes column nor sets an
             * organisation's last activity.
             */
            if ($item['kind'] === 'proposal') {
                return;
            }
            $org = self::analystOrgKey($item);
            if (!isset($notes[$org])) {
                $notes[$org] = 0;
                $last[$org] = $item['date'];
            }
            if ($item['kind'] === 'note') {
                $notes[$org]++;
            } elseif ($item['rates'] === 'value') {
                $opinions[] = $item;
            }
            if ($item['date'] > $last[$org]) {
                $last[$org] = $item['date'];
            }
        });
        if (empty($opinions)) {
            return array('orgs' => array(), 'aggregate' => null);
        }

        $byOrg = array();
        foreach ($opinions as $item) {
            $byOrg[self::analystOrgKey($item)][] = $item;
        }
        $strongest = array();
        foreach ($byOrg as $org => $held) {
            usort($held, function ($a, $b) {
                $byScore = $b['score'] - $a['score'];
                return $byScore !== 0
                    ? $byScore
                    : strcmp($b['date'], $a['date']);
            });
            $byOrg[$org] = $held;
            $strongest[$org] = $held[0]['score'];
        }
        arsort($strongest);

        $rows = array();
        $scores = array();
        foreach (array_keys($strongest) as $org) {
            foreach ($byOrg[$org] as $item) {
                $scores[] = $item['score'];
                $rows[] = array(
                    'org' => $item['org'],
                    'org_id' => $item['org_id'],
                    'score' => $item['score'],
                    'label' => $item['label'],
                    'reads' => $item['reads'],
                    'date' => $item['date'],
                    'notes' => $notes[$org],
                    'last' => $last[$org],
                    'days' => self::analystDaysSince($last[$org]),
                );
            }
        }
        return array(
            'orgs' => $rows,
            'aggregate' => $this->analystAggregate(
                $scores,
                count($byOrg)
            ),
        );
    }

    /**
     * Proposals about this value, as thread items.
     *
     * **Included, and labelled.** `value-intelligence-coverage.md` §5 is the
     * argument: a proposal is how MISP let a third party disagree
     * before analyst data existed, and this thread's subject is who
     * says what about the value. Its conclusion was that the tab either
     * includes them or excludes them *in words*, because silently
     * omitting them leaves the thread claiming to show every
     * organisation's view while dropping the oldest mechanism for
     * expressing one.
     *
     * They are drawn and they touch nothing else: no score, no place in
     * the aggregate, and no row on the ledger. A proposal is a change
     * somebody wants made to a row, not a position on the value, and
     * the standing panel answers the narrower question.
     *
     * **Every date is when the proposal last moved.**
     * `shadow_attributes` has no `created` column — it has one
     * `timestamp`, which `ShadowAttribute::setDeleted` rewrites at the
     * moment a proposal is accepted *or* discarded. So a resolved
     * proposal sits at its resolution rather than at its proposal, and
     * no row may say *withdrawn*: the schema that would tell the two
     * apart does not exist. Phase 25's proposals lane records the same
     * two facts.
     *
     * @param array $user
     * @param string $value
     * @return array
     */
    private function analystProposalItems(array $user, $value)
    {
        $items = array();
        $rows = $this->model('Value')->proposalsFor($user, $value);
        foreach ($rows as $row) {
            $items[] = array(
                'kind' => 'proposal',
                'org' => $row['org'],
                'org_key' => $row['org'],
                'org_id' => $row['org_id'],
                /*
                 * `shadow_attributes` carries an `email` column that
                 * `proposalsFor` does not read, and it is the proposer
                 * rather than a free-text author list. The meta line
                 * drops the field rather than inventing one.
                 */
                'author' => null,
                'date' => date('Y-m-d', $row['timestamp']),
                // No distribution column is fetched, and a proposal
                // inherits its event's reach rather than declaring one.
                'distribution' => null,
                'sharing_group' => null,
                'language' => null,
                'score' => null,
                'rates' => 'proposal',
                'body' => (string)$row['comment'],
                'attached_to' => $row['target'] === null
                    ? array('kind' => 'event', 'event' => $row['event_id'])
                    : array(
                        'kind' => 'attribute',
                        'type' => $row['type'],
                        'event' => $row['event_id'],
                    ),
                'children' => array(),
                'max_depth_reached' => false,
                'label' => null,
                'reads' => 'none',
                /*
                 * What the proposal actually proposes, kept out of the
                 * body: the body goes through the markdown renderer,
                 * and a value containing `*` or `_` is not emphasis.
                 */
                'proposal' => array(
                    'id' => $row['id'],
                    'type' => $row['type'],
                    'category' => $row['category'],
                    'value' => $row['value'],
                    'target' => $row['target'],
                    'to_delete' => $row['to_delete'],
                    'resolved' => $row['deleted'],
                    'event' => $row['event_id'],
                    /*
                     * Which of the four things a proposal can be, named
                     * here rather than re-derived in the template: a
                     * deletion, a standalone addition, a change of
                     * value, or a re-filing that leaves the value
                     * alone and moves its type or category. The panel
                     * draws each one differently, so the branch is a
                     * property of the row.
                     */
                    'op' => self::proposalOp($row),
                ),
            );
        }
        return $items;
    }

    /**
     * Which of the four things a proposal is.
     *
     * `shadow_attributes` says this in three columns rather than one —
     * `proposal_to_delete`, `old_id`, and whether the proposed value
     * differs from the value the target holds now — so the reading is
     * assembled rather than looked up.
     *
     * @param array $row One `Value::proposalsFor` row
     * @return string delete | add | replace | refile
     */
    private static function proposalOp(array $row)
    {
        if (!empty($row['to_delete'])) {
            return 'delete';
        }
        if ($row['target'] === null) {
            // `old_id = 0`: an addition standing behind no attribute.
            return 'add';
        }
        /*
         * A proposal that carries the value the target already holds is
         * proposing something else about it — its category or its type.
         * Drawing that as a value change would show the reader the same
         * string twice with an arrow between them.
         */
        return $row['target']['value'] === $row['value']
            ? 'refile'
            : 'replace';
    }

    /**
     * What the ledger groups an item under.
     *
     * The organisation's uuid where the row has one, so two
     * organisations that no longer resolve to a name cannot merge into
     * one lane group.
     *
     * @param array $item
     * @return string
     */
    private static function analystOrgKey(array $item)
    {
        return $item['org_key'];
    }

    /**
     * Whole days between a date and today, on the real clock.
     *
     * The clock is the point: an opinion held for three months and one
     * written yesterday are different evidence.
     *
     * @param string $date `Y-m-d`
     * @return int
     */
    private static function analystDaysSince($date)
    {
        $at = strtotime($date);
        if ($at === false) {
            return 0;
        }
        return (int)floor((strtotime('today') - $at) / 86400);
    }

    /**
     * Everything the standing panel states about the set as a whole.
     *
     * **Nothing in MISP computes any of this** — no mean, no buckets,
     * no per-organisation rollup, anywhere — which is why the panel
     * carries a `computed at render` chip rather than presenting these
     * as figures it looked up. `26-analyst.md` D3.
     *
     * The gap is *measured*, never assumed. The instance-wide
     * distribution has nothing between 30 and 70; a value with three
     * opinions has whatever shape three opinions have, up to
     * and including no empty band at all.
     *
     * @param array $scores Every admitted opinion, unsorted
     * @param int $orgs Distinct organisations behind them
     * @return array
     */
    private function analystAggregate(array $scores, $orgs)
    {
        sort($scores);
        $n = count($scores);

        $buckets = array();
        foreach (self::opinionBucketLabels() as $label) {
            $buckets[] = array('label' => $label, 'count' => 0);
        }
        foreach ($scores as $score) {
            $buckets[self::opinionBucketFor($score)]['count']++;
        }
        $empty = 0;
        foreach ($buckets as $bucket) {
            if ($bucket['count'] === 0) {
                $empty++;
            }
        }

        $mean = array_sum($scores) / $n;
        /*
         * One decimal only when the mean is not a whole number. `62.5`
         * is a fact about four opinions; `63` would be a rounding this
         * panel has no reason to perform on the one number it is
         * already asking the reader to distrust.
         */
        $meanLabel = $mean == (int)$mean
            ? (string)(int)$mean
            : (string)round($mean, 1);

        $gap = null;
        for ($i = 1; $i < $n; $i++) {
            $span = $scores[$i] - $scores[$i - 1];
            if ($gap === null || $span > $gap['points']) {
                $gap = array(
                    'from' => $scores[$i - 1],
                    'to' => $scores[$i],
                    'points' => $span,
                );
            }
        }

        $nearest = null;
        foreach ($scores as $score) {
            $distance = abs($mean - $score);
            if ($nearest === null || $distance < $nearest) {
                $nearest = $distance;
            }
        }

        $clusters = self::opinionClustersFor($scores, $gap);
        return array(
            'n' => $n,
            'orgs' => $orgs,
            'mean' => $mean,
            'mean_label' => $meanLabel,
            'mean_nearest' => $nearest,
            /*
             * Whether the mean describes a reading nobody holds. Five
             * points is half a band: closer than that and striking the
             * number through would be theatre, further and it is the
             * panel's whole point.
             */
            'mean_orphan' => $nearest !== null && $nearest >= 5,
            'buckets' => $buckets,
            'empty_bands' => $empty,
            'gap' => $gap,
            'clusters' => $clusters,
            'note' => self::opinionNoteFor($clusters, $gap, $n, $orgs),
        );
    }

    /**
     * The five bands MISP itself uses for an opinion, so the word on
     * this page is the word the product uses.
     *
     * @param int $score
     * @return string
     */
    private static function opinionBandFor($score)
    {
        if ($score >= 81) {
            return __('Strongly agree');
        }
        if ($score >= 61) {
            return __('Agree');
        }
        if ($score >= 41) {
            return __('Neutral');
        }
        if ($score >= 21) {
            return __('Disagree');
        }
        return __('Strongly disagree');
    }

    /**
     * Which way an opinion argues about the value.
     *
     * The band word and the reading are two different things: MISP
     * calls 61-80 *Agree*, and what it agrees with is the claim that
     * the value is hostile. The Verdict tab's histogram already reads
     * the axis this way and this tab follows it.
     *
     * @param int $score
     * @return string malicious | benign | none
     */
    private static function opinionReadsFor($score)
    {
        if ($score > 50) {
            return 'malicious';
        }
        if ($score < 50) {
            return 'benign';
        }
        // Exactly 50 argues neither way, and inventing a side for it
        // would be the page's own claim rather than the analyst's.
        return 'none';
    }

    /**
     * Which of the ten bands a score falls in. 0-10 is the first and
     * every band after it is ten wide, which is what makes 100 the
     * last band rather than an eleventh.
     *
     * @param int $score
     * @return int 0-9
     */
    private static function opinionBucketFor($score)
    {
        $score = max(0, min(100, (int)$score));
        return $score <= 10 ? 0 : (int)ceil($score / 10) - 1;
    }

    /**
     * @return array The ten band labels, in the Verdict tab's spelling
     *               so the two histograms read as one object.
     */
    private static function opinionBucketLabels()
    {
        return array(
            '0–10', '11–20', '21–30', '31–40', '41–50',
            '51–60', '61–70', '71–80', '81–90', '91–100',
        );
    }

    /**
     * The two positions, or the one.
     *
     * Split at the widest gap and nowhere else. Splitting at every gap
     * over some width turns four opinions into four clusters and says
     * nothing; the reader's question is where the set divides, and a
     * set divides in one place.
     *
     * @param array $scores Sorted ascending
     * @param array|null $gap
     * @return array
     */
    private static function opinionClustersFor(array $scores, $gap)
    {
        if ($gap === null || $gap['points'] < 20) {
            return array($scores);
        }
        $low = array();
        $high = array();
        foreach ($scores as $score) {
            if ($score <= $gap['from']) {
                $low[] = $score;
            } else {
                $high[] = $score;
            }
        }
        return array($low, $high);
    }

    /**
     * The sub-line under the panel title, shaped by what the numbers
     * turned out to be rather than written once and left to go stale.
     *
     * @param array $clusters
     * @param array|null $gap
     * @param int $n
     * @param int $orgs
     * @return string
     */
    private static function opinionNoteFor(array $clusters, $gap, $n,
        $orgs
    ) {
        $bits = array();
        $bits[] = sprintf(
            __('%1$s from %2$s'),
            sprintf(__n('%s opinion', '%s opinions', $n), $n),
            sprintf(
                __n('%s organisation', '%s organisations', $orgs),
                $orgs
            )
        );
        if (count($clusters) < 2 || $gap === null) {
            $bits[] = __('one position, no disagreement to read');
            return implode(' · ', $bits);
        }
        $bits[] = sprintf(
            __('two positions %s apart'),
            sprintf(
                __n('%s point', '%s points', $gap['points']),
                $gap['points']
            )
        );
        $bits[] = sprintf(
            __('nothing between %1$s and %2$s'),
            $gap['from'],
            $gap['to']
        );
        return implode(' · ', $bits);
    }

    private function ssdeepThreshold()
    {
        $threshold = Configure::read(
            'MISP.ssdeep_correlation_threshold'
        );
        return empty($threshold) ? 40 : (int)$threshold;
    }

    /* ==================================================================
     * Enrichment
     * ==================================================================
     * **The only tab that reads nothing.** Every other panel on this
     * page answers from the database; this one answers from an HTTP
     * service that is not MISP, and its whole content is what a third
     * party said when asked. So the tier vocabulary of §14.4 does not
     * apply here any more than it did to `viewExternal`, and the
     * question a reviewer should ask of this section is not how many
     * queries it issues but *what leaves the building, on whose press.*
     *
     * **Stateless, by the 2026-09-06 decision.** Nothing stores that a
     * module ran. `Module` is `useTable = false` and there is no
     * per-value per-module store anywhere, so this section has no
     * memory: a run is a request and its result lives in the response.
     * Everything phase 12 drew that depended on remembering — the
     * staleness chips, the group headers, the delta band, dismissals,
     * the awaiting-review count — is not implemented here.
     *
     * **Nothing here writes, and that is verified rather than
     * asserted.** `Module::queryModuleServer()` is the non-writing
     * call — the one `AttributesController::hoverEnrichment` uses. The
     * writing wrapper is `Event::enrichment()`, which turns a module
     * response into attributes, and this file never calls it.
     * `28-enrichment-probe.php` counts `attributes`, `objects` and
     * `events` either side of every query it makes.
     */

    /**
     * The most elements one run will render.
     *
     * **200.** A cap on result size, and the first one on this page
     * whose pressure comes from outside MISP entirely: the module
     * decides how much to say, and one of them says a great deal.
     * `circl_passivedns` on `8.8.8.8` returns **1,374 objects in
     * 4.9 s** — measured 2026-09-06 by `28-enrichment-probe.php` — and
     * an object rendered with its attributes is roughly a kilobyte of
     * markup, so the uncapped fragment is well over a megabyte for one
     * press of one button.
     *
     * Phase 12 §11 predicted the cost of this tab as *time* and got a
     * conservative answer right for the wrong quantity: one
     * `POST /query` under `Plugin.Enrichment_timeout`, no progress
     * inside a module. Time turned out to be fine — 98 ms to 4.9 s
     * across six real runs. Size is what bites.
     *
     * When the cap bites the panel says so, and says it against the
     * total rather than instead of it (§14.6): a cap is not a
     * permission, and a reader who cannot see 1,174 of 1,374 rows must
     * not be left thinking there were 200.
     */
    const ENRICHMENT_ELEMENT_CAP = 200;

    /**
     * How many elements of one answer are kept, for the Enrichment tab's
     * *Show all*. Everything else reads the first `ENRICHMENT_ELEMENT_CAP`
     * of them (`enrichmentView`). Measured on passive-dns objects: each
     * renders ~9.5 KB and ~83 DOM nodes, so 2,000 is ~19 MB of pane.
     */
    const ENRICHMENT_KEEP_CAP = 2000;

    /**
     * The Enrichment tab: which modules this value could be sent to,
     * and nothing that has been sent.
     *
     * **This endpoint runs no module.** Not on load, not on tab
     * switch, not on selecting a row — carried unchanged from phase 12
     * §9 and with more force now that the query is real. A run spends
     * the instance's quota and announces interest in the value to a
     * third party, so it needs a press nobody made by arriving.
     *
     * Its cost is one outbound `GET /modules` (9 ms on the dev
     * instance, under a 1 s timeout) plus one `typesFor` (2–26 ms) —
     * and, since phase 7, a **second** `GET /modules` on the one path
     * that needs it: a profile naming a module the eligible set does
     * not contain, where saying *why* is the difference between a
     * stated condition and a silent drop. A profile declaring nothing,
     * which is the shipped default, never pays it.
     *
     * **And what the store already holds, drawn.** The tab opened on
     * *Nothing has been queried* while the Overview drew five widgets
     * off the same rows, which is the page disagreeing with itself.
     * So every held answer arrives with its shapes prepared, and the
     * pane a module's row opens onto shows what it said rather than
     * only that it said something.
     *
     * **The widget and not the pane.** A held answer's rows stay
     * behind their press: `circl_passivedns` on `8.8.8.8` renders
     * 1.6 MB of object cards and three such answers would be a
     * multi-megabyte fragment on a tab nobody has asked a question of
     * yet. The widget is 84 KB of that at the same 199 objects, and
     * it is the half that reads at a glance.
     *
     * @param array $user
     * @param string $value
     * @param array $options `profile` to resolve the enrichment
     *                       declaration against one other than the
     *                       viewer's — the seam phase 8's editor needs
     * @return array
     */
    public function forEnrichment(array $user, $value,
        array $options = array()
    ) {
        $catalogue = $this->enrichmentCatalogue($user, $value, $options);
        return array(
            'value' => $value,
            'enrichment' => $catalogue,
            'held' => $this->enrichmentHeldShapes(
                $this->enrichmentStored($user, $value, $catalogue)
            ),
        );
    }

    /**
     * What each held answer draws, per module.
     *
     * **Per module, where the Overview's strip merges.** The strip has
     * one row and five slots, so three modules answering `geolocation`
     * there is one map naming three sources; the tab has a pane per
     * module and the rule it already keeps is that a module's pane
     * draws that module's answer alone — a widget there carrying
     * somebody else's data would answer a question the rail did not
     * ask. Same renderers, same `drawFor`, different question.
     *
     * **A module whose answer no renderer claims keeps its entry, with
     * no shapes in it.** It is still an answer this organisation
     * holds, and the tab's badge counts rows in the store rather than
     * drawings — so dropping it here would have the tab bar promising
     * four answers over three. What it gets instead of a widget is a
     * line saying its answer is rows, which are a press away.
     *
     * @param array $stored From `enrichmentStored`
     * @return array module => `shapes`, `ran_at`, `total`, `shown`
     */
    private function enrichmentHeldShapes(array $stored)
    {
        $out = array();
        foreach ($stored as $module => $run) {
            if ($run === null || ($run['state'] ?? null) !== 'ok') {
                continue;
            }
            $drawn = ValueRendererTool::drawFor(array($run));
            $out[$module] = array(
                'shapes' => array_values($drawn),
                'ran_at' => isset($run['ran_at'])
                    ? (int)$run['ran_at']
                    : null,
                'total' => isset($run['total']) ? (int)$run['total'] : 0,
                'shown' => isset($run['shown']) ? (int)$run['shown'] : 0,
            );
        }
        return $out;
    }

    /**
     * One module, one value, one answer — the only method on this page
     * that causes anything to leave the instance.
     *
     * `$options['module']` and `$options['type']` arrive from the
     * reader and **neither is trusted**: both are checked against the
     * catalogue this reader would have been shown, so a posted module
     * name can only ever name something `getEnabledModules` already
     * returned for a type `typesFor` already granted. That check is
     * this panel's ACL band (§14.6) and it is the reason the run is
     * built from the catalogue rather than from the request.
     *
     * @param array $user
     * @param string $value
     * @param array $options `module`, `type`
     * @return array
     */
    public function forEnrichmentRun(array $user, $value,
        array $options = array()
    ) {
        return array(
            'value' => $value,
            'run' => $this->enrichmentRun(
                $user,
                $value,
                isset($options['module']) ? $options['module'] : null,
                isset($options['type']) ? $options['type'] : null,
                isset($options['mode']) ? $options['mode'] : null,
                !empty($options['all'])
            ),
        );
    }

    /**
     * Which expansion modules each type is offered, for the Pivot
     * Explorer's *Enrich* pivot to decide eligibility without a round
     * trip per node: one `getEnabledModules` per page.
     *
     * Expansion only — a hover-only or cortex module is not offered —
     * and `ModuleRole`'s non-enrichment modules are left out. The
     * profile's `ticked` and `auto` both pre-tick, `never` hides; the
     * graph runs nothing unpressed.
     *
     * @param array $user
     * @return array `types`, `modules`, `profile`
     */
    public function forEnrichmentTypes(array $user)
    {
        $enabled = $this->model('Module')->getEnabledModules($user);
        $plan = ValueEnrichmentTool::planFor(
            ClassRegistry::init('AnalystProfile')->resolveFor($user)
        );
        $out = array('types' => array(), 'modules' => array(),
            'profile' => array('ticked' => array(), 'never' => array()));
        if (!is_array($enabled) || empty($enabled['modules'])) {
            return $out;
        }
        foreach ($enabled['modules'] as $module) {
            $kinds = isset($module['meta']['module-type'])
                ? (array)$module['meta']['module-type']
                : array();
            if (!in_array('expansion', $kinds, true)
                || !ModuleRole::isEnrichment($module['name'], $plan['roles'])
            ) {
                continue;
            }
            $out['modules'][$module['name']] = array(
                'format' => $this->enrichmentFormat($module),
                'description' => isset($module['meta']['description'])
                    ? $module['meta']['description']
                    : null,
            );
            $inputs = isset($module['mispattributes']['input'])
                ? (array)$module['mispattributes']['input']
                : array();
            foreach ($inputs as $type) {
                $out['types'][$type][] = $module['name'];
            }
        }
        foreach ($plan['auto_run'] as $type => $states) {
            foreach ($states as $name => $state) {
                if (!isset($out['modules'][$name])) {
                    continue;
                }
                $key = $state === ValueEnrichmentTool::STATE_NEVER
                    ? 'never'
                    : 'ticked';
                $out['profile'][$key][$type][] = $name;
            }
        }
        return $out;
    }

    /**
     * What this organisation already holds for each `{value, type}`,
     * per module: the store's row, read-only, and whether it is fresh.
     *
     * An item the reader holds no visible attribute for comes back
     * empty, as though never asked — the store is per organisation,
     * not per reader, and it says nothing about a value this reader
     * cannot see.
     *
     * @param array $user
     * @param array $items `[{value, type}]`
     * @return array One entry per item, `{value, type, modules}`
     */
    public function forEnrichmentStored(array $user, array $items)
    {
        $plan = ValueEnrichmentTool::planFor(
            ClassRegistry::init('AnalystProfile')->resolveFor($user)
        );
        $store = $this->model('ValueEnrichmentRun');
        $out = array();
        foreach ($items as $item) {
            $value = (string)$item['value'];
            $type = (string)$item['type'];
            $modules = array();
            if (!empty($this->enrichmentOccurrence($user, $value, $type))) {
                foreach ($store->forValue($user, $value) as $row) {
                    if ($row['type'] !== $type
                        || $row['state'] === ValueEnrichmentTool::RUN_RUNNING
                    ) {
                        continue;
                    }
                    $modules[$row['module']] = array(
                        'state' => $row['state'],
                        'ran_at' => (int)$row['last_run'],
                        'total' => (int)$row['total'],
                        'fresh' => ValueEnrichmentTool::isFresh(
                            $row,
                            $plan['max_age_hours']
                        ),
                    );
                }
            }
            $out[] = array('value' => $value, 'type' => $type,
                'modules' => (object)$modules);
        }
        return $out;
    }

    /**
     * What the modules have said about this value, small enough to sit
     * at the top of the Overview.
     *
     * **It runs nothing.** What it does is read: the catalogue, for
     * which modules this reader may be offered and what the profile
     * declared, and the store, for what any of them last said. Where
     * the declaration marks a module `auto` and the instance permits
     * it, the plan travels out with the markup and the browser fires
     * those at `viewEnrichmentBadge` — so the panel itself paints at
     * the speed of a database read whether or not a module is up,
     * which is the property that makes an enrichment surface on this
     * tab possible at all.
     *
     * **A stored answer is drawn here rather than fetched.** The tab
     * fires its `fresh` dispositions because its panes are empty until
     * a request fills them; this panel's are not, so `fresh` arrives
     * already drawn and only `fire` leaves the browser. The difference
     * matters on an instance with the gate off: `mode=auto` is refused
     * there, and a module a colleague ran by hand last week would
     * otherwise have no way to reach the page.
     *
     * **The blob comes back one row at a time**, by `one()`, because
     * `forValue()` deliberately does not select it — the catalogue
     * wants a roster and this wants an answer, and the roster is read
     * on every Enrichment tab open. One indexed lookup per module the
     * panel will draw, which is bounded by what has actually been run
     * against this value.
     *
     * @param array $user
     * @param string $value
     * @param array $options `profile`, as `forEnrichment`
     * @return array
     */
    public function forEnrichmentPanel(array $user, $value,
        array $options = array()
    ) {
        return array(
            'value' => $value,
            'panel' => $this->enrichmentPanel($user, $value, $options),
        );
    }

    /**
     * One module's answer, shaped for a chip slot.
     *
     * `forEnrichmentRun`'s twin and deliberately nothing more: the
     * same call, the same `auto` mode, the same gate and reuse window
     * decided in the same place. What differs is the element the
     * controller renders it into, which is the whole of the Overview's
     * claim on this machinery.
     *
     * @param array $user
     * @param string $value
     * @param array $options `module`, `type`, `mode`
     * @return array
     */
    public function forEnrichmentBadge(array $user, $value,
        array $options = array()
    ) {
        $out = $this->forEnrichmentRun($user, $value, $options);
        $out['chips'] = ValueEnrichmentTool::chipsFor($out['run']);
        return $out;
    }


    /**
     * What this reader could ask about this value.
     *
     * **One outbound call on the happy path, two only on failure.**
     * `getEnabledModules()` calls `getModules()` itself and throws the
     * reason away — every failure comes back as the same sentence, so
     * *the service is down* and *nothing is enabled* are one string.
     * Those are different states with different wording (phase 12 §9),
     * so when it fails this asks `getModules()` directly to find out
     * which. A working instance never pays for that.
     *
     * A reader who holds no occurrence gets a `typing` block and is
     * matched on the types it names instead; null otherwise.
     *
     * @param array $user
     * @param string $value
     * @param array $options `profile`, `roles`, `as` (a type to match on
     *     when the reader holds no occurrence)
     * @return array
     */
    private function enrichmentCatalogue(array $user, $value,
        array $options = array()
    ) {
        $moduleModel = $this->model('Module');
        $types = Value::asTypes(
            $this->model('Value')->typesFor($user, $value)
        );

        $started = microtime(true);
        $enabled = $moduleModel->getEnabledModules($user);
        $took = (int)round((microtime(true) - $started) * 1000);

        $service = array(
            'reachable' => true,
            'error' => null,
            'took' => $took,
            'timeout' => $this->enrichmentTimeout(),
        );
        if (!is_array($enabled)) {
            $probe = $moduleModel->getModules('Enrichment');
            $service['reachable'] = is_array($probe);
            $service['error'] = is_array($probe) ? null : (string)$probe;
        }
        $modules = (is_array($enabled) && !empty($enabled['modules']))
            ? $enabled['modules']
            : array();

        $profile = array_key_exists('profile', $options)
            ? $options['profile']
            : ClassRegistry::init('AnalystProfile')->resolveFor($user);
        $plan = ValueEnrichmentTool::planFor($profile);
        if (isset($options['roles'])) {
            $plan['roles'] = $options['roles'];
        }
        /*
         * Phase 11, D25. One indexed read over the store's leading
         * key columns, and the whole reason the tab gains a memory
         * rather than only `auto` gaining one: every row learns
         * whether this organisation has already asked, and that is
         * true of a module nobody declared as much as of one somebody
         * did.
         */
        $stored = $this->model('ValueEnrichmentRun')->forValue(
            $user,
            $value
        );
        $typing = null;
        if (empty($types)) {
            $typing = $this->enrichmentTyping(
                $value,
                $enabled,
                $plan,
                $stored,
                isset($options['as']) ? $options['as'] : null
            );
            $types = $typing['types'];
            unset($typing['types']);
        }
        $rows = $this->enrichmentEligible($enabled, $types, $plan);
        $rows = $this->enrichmentAttachStored($rows, $stored);

        return array(
            'service' => $service,
            'types' => $types,
            'typing' => $typing,
            'enabled' => count($modules),
            /*
             * MISP gates `hoverEnrichment` and `queryEnrichment` on
             * `perm_add`, and this page is never looser than a surface
             * MISP already ships. A reader without it still sees the
             * rail — what *could* be asked is not a secret — and the
             * run control renders visibly disabled, which is this
             * page's standing treatment for a control the reader may
             * not press.
             */
            'can_run' => !empty($user['Role']['perm_add']),
            'modules' => $rows,
            /*
             * Phase 7. The block is present whatever the profile says
             * and `in_force` is false on the shipped default, so a tab
             * whose reader has declared nothing renders exactly as it
             * did before this existed.
             */
            'profile' => $this->enrichmentDeclaration(
                $user,
                $profile,
                $plan,
                $types,
                $rows,
                $service,
                $stored,
                $typing !== null
            ),
        );
    }

    /**
     * The types to match modules on for a reader who holds no
     * occurrence: their pick, else what the value reads as, then any
     * type the organisation has already asked about it under.
     *
     * @param string $value
     * @param array|string $enabled From `getEnabledModules`
     * @param array $plan
     * @param array $stored `module|type` => row
     * @param mixed $as The reader's pick, untrusted
     * @return array `source`, `read`, `chosen`, `choices`,
     *     `workflow_blocks`, `types`
     */
    private function enrichmentTyping($value, $enabled, array $plan,
        array $stored, $as
    ) {
        $offered = $this->enrichmentOfferedTypes($enabled, $plan);
        $warninglist = $this->model('Warninglist');
        $read = ValueTypeGuessTool::read(
            $value,
            array_keys($offered),
            $warninglist->fetchTLDLists(),
            $warninglist->fetchSecurityVendorDomains()
        );
        $picked = is_string($as) && isset($offered[$as]) ? $as : null;

        $basis = array();
        foreach ($picked === null ? $read : array($picked) as $type) {
            $basis[$type] = $picked === null ? 'read' : 'picked';
        }
        $kept = array();
        foreach ($stored as $row) {
            $kept[$row['type']] = true;
            if (!isset($basis[$row['type']]) && isset($offered[$row['type']])) {
                $basis[$row['type']] = 'held';
            }
        }
        $types = array();
        foreach ($basis as $type => $how) {
            $types[] = array(
                'type' => $type,
                'count' => 0,
                'stored' => array(),
                'basis' => $how,
                'kept' => isset($kept[$type]),
            );
        }

        $choices = array();
        $ranked = ValueTypeGuessTool::rank($value, array_keys($offered));
        foreach ($ranked as $group => $names) {
            $choices[$group] = array();
            foreach ($names as $type) {
                $choices[$group][] = array(
                    'type' => $type,
                    'modules' => $offered[$type],
                );
            }
        }

        if ($picked !== null) {
            $source = 'picked';
        } else {
            $source = empty($read) ? 'none' : 'read';
        }
        return array(
            'source' => $source,
            'read' => $read,
            'chosen' => $picked !== null
                ? $picked
                : (empty($read) ? null : $read[0]),
            'choices' => $choices,
            'workflow_blocks' => $this->isTriggerCallable(
                'enrichment-before-query'
            ),
            'types' => $types,
        );
    }

    /**
     * Every attribute type an enrichment module offered to this reader
     * accepts, with the modules that accept it.
     *
     * Composite types are left out — a value is one half of a pair —
     * and so are input names MISP has no attribute type for.
     *
     * @param array|string $enabled From `getEnabledModules`
     * @param array $plan
     * @return array type => module names, sorted by type
     */
    private function enrichmentOfferedTypes($enabled, array $plan)
    {
        if (!is_array($enabled)) {
            return array();
        }
        $all = array();
        foreach (array('types', 'hover_type') as $map) {
            if (empty($enabled[$map]) || !is_array($enabled[$map])) {
                continue;
            }
            foreach (array_keys($enabled[$map]) as $type) {
                $all[$type] = array('type' => (string)$type, 'count' => 0);
            }
        }
        $attributes = $this->model('MispAttribute');
        $composite = $attributes->getCompositeTypes();
        $offered = array();
        $rows = $this->enrichmentEligible($enabled, array_values($all), $plan);
        foreach ($rows as $row) {
            foreach (array_keys($row['types']) as $type) {
                if (isset($attributes->typeDefinitions[$type])
                    && !in_array($type, $composite, true)
                ) {
                    $offered[$type][] = $row['name'];
                }
            }
        }
        ksort($offered, SORT_STRING | SORT_FLAG_CASE);
        return $offered;
    }

    /**
     * Give every catalogue row what the organisation already knows.
     *
     * **The most recent row for the module, across types.** A module
     * can hold a row per type it was asked under, and *"asked 2 h
     * ago"* is a statement about the module rather than about one
     * question put to it — the reader picking a pane wants to know
     * somebody has been here, and the pane itself names the type.
     *
     * `user_id` is deliberately not carried across (D27): the store
     * knows who asked and no surface says so.
     *
     * @param array $rows Catalogue rows
     * @param array $stored `module|type` => row
     * @return array
     */
    private function enrichmentAttachStored(array $rows, array $stored)
    {
        $latest = array();
        foreach ($stored as $row) {
            $name = $row['module'];
            if (isset($latest[$name])
                && (int)$latest[$name]['last_run'] >= (int)$row['last_run']
            ) {
                continue;
            }
            $latest[$name] = $row;
        }
        foreach ($rows as $i => $row) {
            $rows[$i]['stored'] = null;
            if (!isset($latest[$row['name']])) {
                continue;
            }
            $one = $latest[$row['name']];
            $rows[$i]['stored'] = array(
                'type' => $one['type'],
                'state' => $one['state'],
                'age' => max(0, time() - (int)$one['last_run']),
                'total' => (int)$one['total'],
                'shown' => (int)$one['shown'],
                'capped' => !empty($one['capped']),
                /*
                 * A claim carries no answer yet, and every other state
                 * was written by `record()`, which always packs one.
                 * So this needs no look at the blob the catalogue
                 * deliberately did not select.
                 */
                'held' => $one['state'] !== ValueEnrichmentTool::RUN_RUNNING,
            );
        }
        return $rows;
    }

    /**
     * The Overview panel's roster: one entry per module that has
     * something to say or is about to.
     *
     * Built from the catalogue rather than beside it, so the panel and
     * the tab cannot disagree about which modules this reader may be
     * offered, what the profile declared, or what the store holds.
     *
     * Three things put a module on it, and the order they are applied
     * is the order they take precedence:
     *
     * | | |
     * |---|---|
     * | a stored answer | drawn now, from the blob |
     * | `fire` | a slot the browser fills |
     * | `in_flight` | somebody else is asking; neither, and said so |
     *
     * `fire` beats a stored answer because a disposition of `fire`
     * means the stored one is past the reader's own reuse window —
     * drawing a stale answer under a slot that is about to replace it
     * would move the chips under the reader for no gain.
     *
     * `blocked` puts nothing on the roster. A module the gate is
     * holding must not be described by the store: *asked 2 h ago*
     * against something this instance will not run on its own is
     * answering a question nobody asked.
     *
     * @param array $user
     * @param string $value
     * @param array $options `profile`
     * @return array
     */
    private function enrichmentPanel(array $user, $value,
        array $options = array()
    ) {
        $catalogue = $this->enrichmentCatalogue($user, $value, $options);
        /*
         * MISP gates every other enrichment surface on `perm_add` and
         * this page is never looser than one MISP already ships. A
         * reader without it keeps the stored answers, which are a
         * read of this organisation's own rows, and fires nothing.
         */
        $canRun = !empty($catalogue['can_run']);

        $entries = array();
        /*
         * The same unpacked runs the chips are built from, kept so the
         * widgets can be built from them too. One read of the store
         * answers both questions — *what is the headline* and *what
         * shape is this* — and a second pass would be a second set of
         * inflates over the same blobs.
         */
        $runs = array();
        $stored = $this->enrichmentStored($user, $value, $catalogue);
        foreach ($catalogue['modules'] as $row) {
            if (!array_key_exists($row['name'], $stored)) {
                continue;
            }
            $shaped = $stored[$row['name']];
            if ($shaped !== null) {
                $runs[] = $shaped;
            }
            $entries[$row['name']] = array(
                'module' => $row['name'],
                'type' => $row['stored']['type'],
                'locality' => $row['locality'],
                'pending' => null,
                /*
                 * A row whose payload will not inflate is not an
                 * error: the row still says a module was asked and
                 * when, so the state is *asked, no longer held* —
                 * which a purge produces and the panel has to draw
                 * either way.
                 */
                'state' => $shaped === null
                    ? 'expired'
                    : $row['stored']['state'],
                'age' => $row['stored']['age'],
                'chips' => $shaped === null
                    ? ValueEnrichmentTool::chipsFor(array())
                    : ValueEnrichmentTool::chipsFor($shaped),
            );
        }

        foreach ($catalogue['profile']['auto'] as $one) {
            if ($one['disposition'] !== 'fire'
                && $one['disposition'] !== 'in_flight'
            ) {
                continue;
            }
            if ($one['disposition'] === 'fire' && !$canRun) {
                continue;
            }
            $entries[$one['module']] = array(
                'module' => $one['module'],
                'type' => $one['type'],
                'locality' => $one['locality'],
                'pending' => $one['disposition'],
                'state' => null,
                'age' => $one['age'],
                'chips' => ValueEnrichmentTool::chipsFor(array()),
            );
        }

        /*
         * Catalogue order, so the panel and the tab's rail name the
         * modules in the same sequence — a reader who has seen one is
         * reading the other against it.
         */
        $modules = array();
        foreach ($catalogue['modules'] as $row) {
            if (isset($entries[$row['name']])) {
                $modules[] = $entries[$row['name']];
                unset($entries[$row['name']]);
            }
        }
        foreach ($entries as $entry) {
            $modules[] = $entry;
        }

        $fire = array();
        foreach ($modules as $entry) {
            if ($entry['pending'] !== 'fire') {
                continue;
            }
            $fire[] = array(
                'module' => $entry['module'],
                'type' => $entry['type'],
            );
        }

        /*
         * The widgets first, because what they draw decides which
         * modules still need a row: an answer drawn on the strip is
         * not restated as chips underneath it.
         */
        $strip = $this->enrichmentStrip(
            $runs,
            $catalogue['profile'],
            $catalogue['types'],
            $value
        );
        foreach ($modules as &$entry) {
            $entry['drawn'] = in_array(
                $entry['module'],
                $strip['drawn'],
                true
            );
        }
        unset($entry);

        return array(
            /*
             * The panel's presence is itself the signal that something
             * is known. An instance that has never run a module
             * and declares no `auto` draws no header, no empty state
             * and no card — the alternative is a permanently empty
             * first row on every Overview, which is the outcome the
             * two phases that measured this tab's height would be
             * most hostile to.
             */
            'present' => !empty($modules),
            'can_run' => $canRun,
            'modules' => $modules,
            'fire' => $fire,
            'max_age_hours' => $catalogue['profile']['max_age_hours'],
            'strip' => $strip,
            /*
             * The one policy a reader of *this* panel is owed, and only
             * where it applies to them. An empty band and a forbidden
             * band look identical, and only one of them is a fact
             * about the value — so where the profile asked for
             * something to run on its own and the instance does not
             * allow that, the panel says so once rather than leaving
             * slots that look like answers nobody found.
             *
             * Taken from the resolved conditions rather than worded
             * here: the Enrichment tab already states this in a
             * sentence, and a second phrasing of one policy is two
             * places for it to drift.
             */
            'gate_note' => $this->enrichmentGateNote($catalogue),
        );
    }

    /**
     * Every answer the store holds about this value, unpacked.
     *
     * **One place where a blob is inflated**, because two surfaces
     * read the same rows for different reasons — the Overview panel
     * builds chips and widgets from them, the Enrichment tab draws
     * each one over its module's pane — and a second spelling of this
     * loop is how the two would come to disagree about what is held.
     *
     * Keyed by module and **null where the payload will not inflate**,
     * which is not an error: the row still says a module was asked and
     * when, so the caller can draw *asked, no longer held*. A module
     * absent from the array was never asked at all, and the two are
     * different things.
     *
     * The roster decides which rows are read — `stored.held` — so this
     * costs one indexed lookup per module that has actually answered,
     * and nothing at all on a value nobody has enriched.
     *
     * @param array $user
     * @param string $value
     * @param array $catalogue From `enrichmentCatalogue`
     * @return array module => shaped run carrying `ran_at`, or null
     */
    private function enrichmentStored(array $user, $value,
        array $catalogue
    ) {
        $store = $this->model('ValueEnrichmentRun');
        $out = array();
        foreach ($catalogue['modules'] as $row) {
            if (empty($row['stored']) || empty($row['stored']['held'])) {
                continue;
            }
            $held = $store->one(
                $user,
                $value,
                $row['name'],
                $row['stored']['type']
            );
            $shaped = $held === null
                ? null
                : ValueEnrichmentRun::unpack($held);
            if ($shaped !== null) {
                $shaped = $this->enrichmentView($shaped);
                /*
                 * `pack()` drops the two fields that are about *now*
                 * rather than about then, so the stamp is put back
                 * from the row that carried it — which is what lets a
                 * re-run visibly take a slot from the answer it
                 * replaced.
                 */
                $shaped['ran_at'] = (int)$held['last_run'];
            }
            $out[$row['name']] = $shaped;
        }
        return $out;
    }

    /**
     * The instance's auto-run policy, where the profile ran into it.
     *
     * Null on every instance that has not turned auto-run on **and**
     * every profile that never asked for it, which between them is
     * nearly all of them: a note stating a policy nobody has met is
     * the permanently-present sentence that makes readers stop reading
     * notes.
     *
     * @param array $catalogue
     * @return string|null
     */
    private function enrichmentGateNote(array $catalogue)
    {
        $conditions = isset($catalogue['profile']['conditions'])
            && is_array($catalogue['profile']['conditions'])
            ? $catalogue['profile']['conditions']
            : array();
        $wanted = array(
            ValueEnrichmentTool::C_STATE_AUTO_DISABLED,
            ValueEnrichmentTool::C_STATE_AUTO_SITE_ADMIN,
        );
        foreach ($conditions as $condition) {
            if (isset($condition['id'])
                && in_array($condition['id'], $wanted, true)
            ) {
                return $condition['note'];
            }
        }
        return null;
    }

    /**
     * The promoted widgets, in the order they are drawn.
     *
     * One row above the module rows, and the geometry is the whole
     * decision: five widgets at roughly 190px sit inside the same
     * ~180px this panel was already measured and accepted at, where a
     * stack of five would be 500–1000px and would make enrichment the
     * tallest thing on the Overview — which is not what an overview
     * is.
     *
     * **One widget per shape.** Where three modules all returned a
     * geolocation, the renderers merge them and the strip shows one
     * map, whose cell names all three. Five *different* visual
     * answers, never three maps.
     *
     * **And what it drew is what the rows below stop saying.** The
     * covered modules come back with the slots, because a chip
     * restating three relations under a picture of them is the same
     * answer twice — the rows are for what the strip does not show.
     *
     * Everything about which five is `ValueRendererTool`'s: the
     * profile's ranking first — answered or not — then the shipped
     * per-type order for what actually drew, and nothing that neither
     * names. This method's own job is only to carry the drawings
     * across to a template with the two facts a reader needs beside
     * each: which modules answered, and when.
     *
     * **A slot is returned for a ranked shape with no answer**, with
     * `widget` null. Closing the row up would report four answers to a
     * reader who asked for five and got four.
     *
     * @param array $runs Unpacked runs carrying `ran_at`
     * @param array $profile The resolved declaration
     * @param array $types `typesFor` output
     * @param string $value The value being enriched
     * @return array
     */
    private function enrichmentStrip(array $runs, array $profile,
        array $types, $value
    ) {
        $ranked = isset($profile['shapes']) ? $profile['shapes'] : array();
        /*
         * A value with nothing stored still has slots to draw where a
         * profile ranked something — the gap is the point — so the
         * early return is only for the case where nobody asked for
         * anything either.
         */
        if (empty($runs) && empty($ranked)) {
            return array('slots' => array(), 'drawn' => array());
        }
        $drawn = ValueRendererTool::drawFor($runs);
        $promoted = ValueRendererTool::promote($drawn, $ranked, $types);
        $slots = array();
        foreach ($promoted as $shape) {
            $slots[] = array(
                'shape' => $shape,
                'widget' => isset($drawn[$shape])
                    ? $drawn[$shape]
                    : null,
            );
        }
        return array(
            'slots' => $slots,
            /*
             * Which modules the row above answers for, so the rows
             * below can be the ones it does not.
             */
            'drawn' => ValueRendererTool::covered(
                $runs,
                $drawn,
                $promoted,
                $value
            ),
        );
    }

    /**
     * The profile's enrichment declaration, met with this instance.
     *
     * **The second `GET /modules` lives here**, and only on the path
     * that cannot answer without it: a declared module missing from
     * the eligible set is missing for one of four reasons — turned
     * off, reserved for another organisation, absent from the build,
     * or filed under a type it does not accept — and
     * `getEnabledModules()` has already discarded the difference by
     * the time this runs. `needsFacts()` decides; a declaration that
     * resolves cleanly, and the shipped default that declares nothing,
     * pay nothing.
     *
     * @param array $user
     * @param array|null $profile
     * @param array $plan From `ValueEnrichmentTool::planFor`
     * @param array $types `typesFor` output
     * @param array $rows The eligible catalogue rows
     * @param array $service The service block
     * @return array
     */
    private function enrichmentDeclaration(array $user, $profile,
        array $plan, array $types, array $rows, array $service,
        array $stored = array(), $typed = false
    ) {
        $facts = array(
            'service' => $service,
            'types' => $types,
            'eligible' => $rows,
            /*
             * Phase 11, D24. The gate is instance policy, so it
             * arrives as a fact the model read rather than as
             * something the tool goes and looks up — the same reason
             * the service block and the eligible set arrive this way,
             * and what keeps `ValueEnrichmentTool` free of `$user`, a
             * model and `Configure`.
             */
            'auto_gate' => Configure::read(
                'Plugin.ValueIntelligence_enrichment_auto_run'
            ),
            'site_admin' => !empty($user['Role']['perm_site_admin']),
        );
        $missing = ValueEnrichmentTool::needsFacts($plan, $types, $rows);
        if (!empty($missing) && !empty($service['reachable'])) {
            $facts = array_merge(
                $facts,
                $this->enrichmentModuleFacts($user, $missing)
            );
        }
        $resolved = ValueEnrichmentTool::resolve($plan, $facts);
        $resolved['name'] = is_array($profile) && isset($profile['name'])
            ? $profile['name']
            : null;
        $resolved['leaving'] = ValueEnrichmentTool::leavingCount(
            $resolved
        );
        /*
         * **The plan, and it travels with the panel that acts on it.**
         * One disposition per declared `auto` module — fire it, wait
         * for somebody else's run, serve what is stored, or say why
         * not. No second endpoint: this page renders markup rather
         * than JSON, and a plan fetched separately would be a second
         * request for something the first already knew.
         *
         * It is deliberately surface-agnostic. When the Overview grows
         * its hero badges it reads this same block rather than a view
         * of its own, so the two cannot disagree about what should
         * run.
         *
         * Advisory, not authoritative: a row can turn fresh between
         * this being computed and a request landing, which is why
         * `enrichmentRun()` decides again rather than trusting a
         * disposition it was handed.
         */
        $resolved['auto'] = ValueEnrichmentTool::autoDispositions(
            $resolved,
            $stored,
            $this->enrichmentTimeout()
        );
        if ($typed) {
            // Nothing runs unasked on a type the reader does not hold.
            foreach ($resolved['auto'] as &$one) {
                if ($one['disposition'] === 'fire') {
                    $one['disposition'] = 'blocked';
                }
            }
            unset($one);
        }
        return $resolved;
    }

    /**
     * The three settings and the one declaration that say why a module
     * this reader cannot see is not there.
     *
     * `canUse()` rather than a second reading of `_restrict`, because
     * the rule is not *"a restriction exists"* — a site admin passes
     * every restriction, and telling one that a module is reserved
     * away from them would be false.
     *
     * A second failed call returns nothing rather than a guess: the
     * conditions then land as `module.unresolved`, which says the
     * question was not answered instead of picking an answer.
     *
     * @param array $user
     * @param array $names The declared names needing an explanation
     * @return array `offered` and `modules`, or empty
     */
    private function enrichmentModuleFacts(array $user, array $names)
    {
        $moduleModel = $this->model('Module');
        $all = $moduleModel->getModules('Enrichment');
        if (!is_array($all)) {
            return array();
        }
        $offered = array();
        $byName = array();
        foreach ($all as $module) {
            if (empty($module['name'])) {
                continue;
            }
            $offered[] = $module['name'];
            $byName[$module['name']] = $module;
        }
        $facts = array();
        foreach ($names as $name) {
            if (!isset($byName[$name])) {
                $facts[$name] = array(
                    'present' => false,
                    'enabled' => false,
                    'restricted' => false,
                    'restrict_org' => null,
                    'accepts' => array(),
                );
                continue;
            }
            $module = $byName[$name];
            $restrict = Configure::read(
                'Plugin.Enrichment_' . $name . '_restrict'
            );
            $facts[$name] = array(
                'present' => true,
                'enabled' => (bool)Configure::read(
                    'Plugin.Enrichment_' . $name . '_enabled'
                ),
                'restricted' => !$moduleModel->canUse(
                    $user,
                    'Enrichment',
                    $module
                ),
                'restrict_org' => empty($restrict) ? null : $restrict,
                'accepts' => empty($module['mispattributes']['input'])
                    ? array()
                    : array_values($module['mispattributes']['input']),
            );
        }
        return array('offered' => $offered, 'modules' => $facts);
    }

    /**
     * The union over the value's types, one row per module.
     *
     * **A value is several types.** `8.8.8.8` is four — `ip-dst` 17, `ip-src`
     * 5, `text` 2, `ip-dst|port` 2 — and three enabled modules accept some of
     * them. A module eligible through three of those types is *one* rail row
     * carrying three, not three rows; and `text`, which no enabled module
     * declares, contributes nothing and is not an error.
     *
     * `types` is `getEnabledModules`' expansion map and `hover_type`
     * its hover one. A module in both is one row whose kind is a
     * property rather than a duplicate.
     *
     * The default run type is the **first** the module accepts, which
     * is the value's most common because `typesFor` orders by
     * occurrence count descending and this walks it in that order.
     *
     * Since phase 7 each row also carries whether **asking it leaves
     * the instance** (`ModuleLocality`), which is what lets the tray
     * price a selection in the only currency that has a source.
     *
     * @param array|string $enabled `getEnabledModules` output
     * @param array $types `typesFor` output
     * @param array $plan From `ValueEnrichmentTool::planFor`
     * @return array
     */
    private function enrichmentEligible($enabled, array $types,
        array $plan = array()
    ) {
        if (!is_array($enabled) || empty($enabled['modules'])) {
            return array();
        }
        $maps = array('types' => 'expansion', 'hover_type' => 'hover');
        $eligible = array();
        foreach ($types as $row) {
            $type = $row['type'];
            foreach ($maps as $map => $kind) {
                if (empty($enabled[$map][$type])) {
                    continue;
                }
                foreach ($enabled[$map][$type] as $name) {
                    if (!isset($eligible[$name])) {
                        $eligible[$name] = array(
                            'kinds' => array(),
                            'types' => array(),
                        );
                    }
                    $eligible[$name]['kinds'][$kind] = true;
                    $eligible[$name]['types'][$type] = $row['count'];
                }
            }
        }
        $roles = isset($plan['roles']) && is_array($plan['roles'])
            ? $plan['roles']
            : array();
        $rows = array();
        foreach ($eligible as $name => $meta) {
            $module = $this->enrichmentModule($enabled, $name);
            if ($module === null || !ModuleRole::isEnrichment($name, $roles)) {
                continue;
            }
            $locality = ModuleLocality::resolve($name);
            $rows[] = array(
                'name' => $name,
                'kinds' => array_keys($meta['kinds']),
                'types' => $meta['types'],
                'type' => key($meta['types']),
                'format' => $this->enrichmentFormat($module),
                'locality' => $locality['locality'],
                'locality_source' => $locality['source'],
                'description' => isset($module['meta']['description'])
                    ? $module['meta']['description']
                    : null,
                /*
                 * The keys, not a verdict on them. Nothing tells a
                 * required key from an optional override, so the row
                 * states what the module declares and the run finds
                 * out — §2.3 of the phase document, where `whois`
                 * fails for want of two and `mmdb_lookup` works
                 * without three.
                 */
                'config' => empty($module['meta']['config'])
                    ? array()
                    : array_values($module['meta']['config']),
            );
        }
        usort($rows, function ($a, $b) {
            return strcmp($a['name'], $b['name']);
        });
        return $rows;
    }

    /**
     * Run one module and shape what came back.
     *
     * @param array $user
     * @param string $value
     * @param string|null $name
     * @param string|null $type
     * @return array
     */
    private function enrichmentRun(array $user, $value, $name, $type,
        $mode = null, $all = false
    ) {
        /*
         * Two callers, and the difference between them is the whole
         * of D25's second consequence.
         *
         * A **press** always re-runs. `max_age_hours` governs
         * automatic reuse, and a human pressing a button has made a
         * decision that a cache must not overrule.
         *
         * An **auto** reuses a fresh row and asks the module only when
         * there is nothing fresh to serve. The page decides which
         * modules to send here from the dispositions its panel
         * carried, but the decision is remade below rather than
         * trusted: a row can turn fresh between the plan being
         * computed and this request landing, which is precisely the
         * Overview-then-tab race this mode exists for.
         *
         * A **stored** never asks anybody anything. It is what *Show
         * what came back* means, and that control went through `auto`
         * until it was noticed that `auto` is refused where the gate
         * is shut — which is every instance by default. A reader
         * pressing it on a stock instance was told their own
         * organisation's answer *was not run on its own*, and where
         * the gate was open but the answer had aged past the reuse
         * window they got a fresh outbound query from a button that
         * promised to show them something already held. The gate
         * governs running a module unasked; reading a row this
         * organisation already wrote is neither.
         */
        $auto = $mode === 'auto';
        $storedOnly = $mode === 'stored';
        /*
         * The catalogue is built with no profile, deliberately: it is
         * read here as an ACL band — which modules this reader would
         * have been offered — and a *selection* plays no part in that.
         * A profile can only ever narrow what the instance allows, so
         * resolving one to decide what is offered could only refuse a
         * run the instance permits on the strength of a preference.
         * Passing `null` also keeps the run path free of the
         * catalogue's own profile read and its second `GET /modules`.
         *
         * **One part of the declaration is not a preference** (D17).
         * `never` is the reader saying this module must not be asked,
         * and the run endpoint takes a module name from the request —
         * so an unticked or disabled checkbox is not a guard. That
         * check is made below, against the plan alone, which needs no
         * modules service.
         */
        $catalogue = $this->enrichmentCatalogue(
            $user,
            $value,
            array(
                'profile' => null,
                // Unlike a selection, a role can widen what is offered, so the
                // profile's roles are the one part the band must honour.
                'roles' => ValueEnrichmentTool::planFor(
                    ClassRegistry::init('AnalystProfile')->resolveFor($user)
                )['roles'],
                'as' => $type,
            )
        );
        $typed = $catalogue['typing'] !== null;
        $run = array(
            'module' => $name,
            'type' => $type,
            'format' => null,
            'kinds' => array(),
            'state' => 'ineligible',
            'message' => null,
            'took' => 0,
            'attributes' => array(),
            'objects' => array(),
            'elements' => array(),
            'total' => 0,
            'kept' => 0,
            'shown' => 0,
            'capped' => false,
            'cap' => self::ENRICHMENT_ELEMENT_CAP,
            'timeout' => $catalogue['service']['timeout'],
            /*
             * Whether this answer came out of the store rather than
             * off the wire, and how old it is. Both are about *now*
             * and neither is stored — `pack()` drops them along with
             * the timeout.
             */
            'from_store' => false,
            'age' => null,
        );
        if (!$catalogue['service']['reachable']) {
            $run['state'] = 'unreachable';
            $run['message'] = $catalogue['service']['error'];
            return $run;
        }

        /*
         * The ACL band. A run may only ever name a module this reader
         * would have been offered, for a type this reader holds an
         * occurrence of — both taken from the catalogue rather than
         * from the request. Without an occurrence the type is the
         * reader's own choice, so the module must declare it.
         */
        $row = null;
        foreach ($catalogue['modules'] as $candidate) {
            if ($candidate['name'] === $name) {
                $row = $candidate;
                break;
            }
        }
        if ($row === null) {
            return $run;
        }
        if ($typed && $type !== null && !isset($row['types'][$type])) {
            return $run;
        }
        if ($type === null || !isset($row['types'][$type])) {
            $type = $row['type'];
        }
        $run['type'] = $type;
        $run['format'] = $row['format'];
        $run['kinds'] = $row['kinds'];

        /*
         * D17's `never`, enforced where the run happens. Checked
         * against the resolved type rather than the posted one,
         * because that is the type the module would be asked about.
         */
        $plan = ValueEnrichmentTool::planFor(
            ClassRegistry::init('AnalystProfile')->resolveFor($user)
        );
        if (ValueEnrichmentTool::refuses($plan, $name, $type)) {
            $run['state'] = 'profile_refused';
            return $run;
        }

        $store = $this->model('ValueEnrichmentRun');
        if ($auto) {
            /*
             * **The gate, enforced where the run happens** — the same
             * argument D17 made for `never`. The page will not send an
             * auto request when the gate is shut, but the mode arrives
             * in the request, and a guard that only the caller
             * observes is not a guard.
             *
             * A press is untouched by this: the gate governs what runs
             * *without* one.
             */
            if (!ValueEnrichmentTool::gateAllows(
                Configure::read('Plugin.ValueIntelligence_enrichment_auto_run'),
                !empty($user['Role']['perm_site_admin'])
            )) {
                $run['state'] = 'auto_not_allowed';
                return $run;
            }
            $held = $store->one($user, $value, $name, $type);
            if ($held !== null
                && $held['state'] !== ValueEnrichmentTool::RUN_RUNNING
                && ValueEnrichmentTool::isFresh(
                    $held,
                    $plan['max_age_hours']
                )
            ) {
                return $this->enrichmentFromStore($held, $user, $value,
                    $run, $all);
            }
            if ($typed) {
                $run['state'] = 'auto_typed';
                return $run;
            }
        }

        if ($storedOnly) {
            /*
             * No gate and no reuse window. Neither is about this: the
             * gate governs asking a module unasked, the window governs
             * when an automatic reuse stops being good enough, and
             * this is a reader asking to see a row their own
             * organisation already wrote. The age travels with the
             * answer, so an old one says so rather than being hidden.
             *
             * Nothing held is *expired* — the state the pane already
             * words as *asked, and the answer is no longer kept* —
             * because that is what a reader pressing this on a purged
             * row has happen to them. It is also what a row somebody
             * else is writing right now reads as: a `running` claim
             * carries no payload, and saying *no longer kept* of it is
             * wrong only until their request lands.
             */
            $held = $store->one($user, $value, $name, $type);
            if ($held === null
                || $held['state'] === ValueEnrichmentTool::RUN_RUNNING
            ) {
                $run['state'] = 'expired';
                return $run;
            }
            return $this->enrichmentFromStore($held, $user, $value, $run,
                $all);
        }


        /*
         * The run is backed by one of the reader's own occurrences. No
         * module receives it (enrichmentPayload() sends the value
         * alone), but every format passes it as trigger data, so that
         * an instance's `enrichment-before-query` workflow can still
         * refuse the query. Passing `$skipTrigger` instead would be
         * quietly disabling a control somebody configured on purpose.
         *
         * A reader with no occurrence has no trigger data to offer, so
         * where such a workflow is listening the run is refused here
         * rather than handed to it empty.
         */
        if ($typed) {
            if ($catalogue['typing']['workflow_blocks']) {
                $run['state'] = 'needs_occurrence';
                return $run;
            }
            $occurrence = array();
        } else {
            $occurrence = $this->enrichmentOccurrence($user, $value, $type);
            if (empty($occurrence['Attribute'])) {
                $run['state'] = 'ineligible';
                return $run;
            }
        }

        /*
         * Claim the row here and not earlier: everything above this
         * can decline without asking anybody anything, and a claim
         * left behind by a decline would have the tab reporting a
         * module as *being asked now* when nothing was ever asked.
         *
         * From this line on the module is going to be queried, so the
         * claim is true the moment it is written — which is what makes
         * it safe for a second reader arriving mid-flight (§7.3) to
         * treat as *somebody is asking, wait*.
         */
        $store->claim($user, $value, $name, $type);

        $moduleModel = $this->model('Module');
        $started = microtime(true);

        /*
         * **`$throwException` is on so a timeout can keep its name.**
         * `queryModuleServer` otherwise swallows every exception into
         * one `false`, which would collapse two states the tab draws
         * differently: *gave up at 30 s*, where the module was asked
         * and did not finish, and *no service*, where nothing was
         * asked at all. Phase 12 §9 lists them as separate rows for
         * that reason, and a reader acts on them differently — one is
         * worth pressing again, the other is worth telling an admin.
         *
         * The cost of asking for the exception is that this has to do
         * the logging the model would have done.
         */
        try {
            $result = $moduleModel->queryModuleServer(
                $this->enrichmentPayload($row, $type, $value),
                false,
                'Enrichment',
                true,
                $occurrence
            );
        } catch (Exception $e) {
            $this->logException('Failed to query enrichment module', $e);
            $run['took'] = (int)round((microtime(true) - $started) * 1000);
            $failed = $this->enrichmentFailure($run, $e);
            /*
             * A failure is an outcome and is remembered like any
             * other. It matters most for `auto`: a module that timed
             * out is not re-asked on every page open for the next
             * `max_age_hours`, while a press still re-runs it
             * immediately.
             */
            $store->record($user, $value, $failed);
            return $failed;
        }
        $run['took'] = (int)round((microtime(true) - $started) * 1000);

        /*
         * Shape, store, then mark up — and that order is §8.1.
         * `enrichmentKnown()` answers *"already in MISP and you can
         * see it"* about the database as it stands and about this
         * reader's ACL, so storing its answer would freeze somebody
         * else's view of a moment that has passed. The store holds the
         * module's answer; the chips are recomputed for whoever is
         * looking.
         */
        $shaped = $this->enrichmentShape(
            $run,
            $result,
            $user,
            $value,
            false
        );
        $store->record($user, $value, $shaped);

        return $this->enrichmentKnown(
            $this->enrichmentView($shaped, $all),
            $user,
            $value
        );
    }

    /**
     * Serve a stored answer instead of asking the module again.
     *
     * The row holds the shaped run as it was, minus the chips; this
     * puts back the two things that are about *now* rather than about
     * then — how old the answer is, and what MISP currently holds that
     * this reader can see.
     *
     * A payload that will not inflate is not an error: the row still
     * says a module was asked and when, so the answer is *"asked, no
     * longer held"*, which is a state the tab has to draw anyway once
     * a purge has been through.
     *
     * @param array $held The stored row
     * @param array $user
     * @param string $value
     * @param array $run The shell built by the caller
     * @return array
     */
    private function enrichmentFromStore(array $held, array $user, $value,
        array $run, $all = false
    ) {
        $stored = ValueEnrichmentRun::unpack($held);
        $age = max(0, time() - (int)$held['last_run']);
        if ($stored === null) {
            $run['state'] = 'expired';
            $run['from_store'] = true;
            $run['age'] = $age;
            return $run;
        }
        $stored['timeout'] = $run['timeout'];
        $stored['from_store'] = true;
        $stored['age'] = $age;
        return $this->enrichmentKnown(
            $this->enrichmentView($stored, $all),
            $user,
            $value
        );
    }

    /**
     * An answer as one surface reads it: its first
     * `ENRICHMENT_ELEMENT_CAP` elements, or all of them for the
     * Enrichment tab's *Show all*.
     *
     * @param array $run A shaped or unpacked run
     * @param bool $all
     * @return array
     */
    private function enrichmentView(array $run, $all = false)
    {
        return ValueEnrichmentTool::view(
            $run,
            $all,
            self::ENRICHMENT_ELEMENT_CAP
        );
    }

    /**
     * Which of the two transport failures this was.
     *
     * `CurlClient` raises `SocketException("curl error 28 …")` when it
     * gives up, 28 being `CURLE_OPERATION_TIMEDOUT`. That number is
     * the only thing separating *the module was asked and ran out of
     * time* from *nothing answered at the address*, and the two get
     * different wording, a different dot and different advice.
     *
     * @param array $run
     * @param Exception $e
     * @return array
     */
    private function enrichmentFailure(array $run, Exception $e)
    {
        $message = $e->getMessage();
        $timedOut = strpos($message, 'curl error 28') !== false
            || stripos($message, 'timed out') !== false
            || stripos($message, 'timeout') !== false;
        $run['state'] = $timedOut ? 'timeout' : 'unreachable';
        $run['message'] = $message;
        return $run;
    }

    /**
     * The reader's first visible occurrence of this value under this
     * type, as `fetchAttributesSimple` shapes it.
     *
     * Through `Value` and never through conditions written here:
     * §14.2 makes that file the only one that knows how a value
     * resolves to rows, and §14.3 is the promise that when the value
     * table lands, one file changes.
     *
     * @param array $user
     * @param string $value
     * @param string $type
     * @return array
     */
    private function enrichmentOccurrence(array $user, $value, $type)
    {
        $valueModel = $this->model('Value');
        $rows = $valueModel->occurrencesFor($user, $value, array(
            'types' => $valueModel->storedTypesOf($type),
            'limit' => 1,
            'order' => array('Attribute.id ASC'),
        ));
        return empty($rows) ? array() : $rows[0];
    }

    /**
     * What goes on the wire.
     *
     * The two formats differ in what they are asked about: a
     * `misp_standard` module wants an attribute, a `simplified` one
     * wants `{type: value}`. Config is read per declared key and
     * sent as given — **never judged**, because nothing distinguishes
     * a required key from an optional override and guessing gets it
     * wrong in both directions (§2.3 of the phase document).
     *
     * @param array $row A catalogue row
     * @param string $type
     * @param string $value
     * @return array
     */
    private function enrichmentPayload(array $row, $type, $value)
    {
        $postData = array('module' => $row['name']);
        if (!empty($row['config'])) {
            $config = array();
            foreach ($row['config'] as $key) {
                $config[$key] = Configure::read(
                    'Plugin.Enrichment_' . $row['name'] . '_' . $key
                );
            }
            $postData['config'] = $config;
        }
        if ($row['format'] === 'misp_standard') {
            /*
             * The value alone, never the row it was found in: the store
             * keeps one answer per value and reuses it for every
             * attribute carrying it, so an answer echoing one row's
             * comment would reach another row's readers. It also keeps
             * comments and event ids from leaving the instance. The
             * occurrence still backs the run as the workflow's trigger
             * data, which is evaluated here and never sent.
             */
            $types = $this->model('MispAttribute')->typeDefinitions;
            $postData['attribute'] = array(
                'uuid' => Value::uuidFor($value),
                'type' => $type,
                'category' => $types[$type]['default_category'] ?? 'Other',
                'value' => $value,
                'value1' => $value,
                'value2' => '',
                'to_ids' => false,
            );
        } else {
            $postData[$type] = $value;
        }
        return $postData;
    }

    /**
     * Normalise a module response into the shape the pane reads, and
     * cap it.
     *
     * Five outcomes, and they are deliberately not interchangeable.
     * `false` is the transport failing — unreachable, or an exception
     * the model logged. A **string** is MISP's own refusal, and the
     * one that matters is the workflow trigger declining the query. An
     * `error` key is the module answering that it cannot do the job,
     * which is what a missing required config key looks like and comes
     * back in 7 ms. **Silent** is a module that answered with nothing,
     * which is a finding rather than a failure. Anything else is an
     * answer.
     *
     * @param array $run
     * @param array|string|false $result
     * @return array
     */
    private function enrichmentShape(array $run, $result, array $user,
        $subject, $withKnown = true
    ) {
        if ($result === false) {
            $run['state'] = 'unreachable';
            $run['message'] = __(
                'The enrichment service did not answer.'
            );
            return $run;
        }
        if (!is_array($result)) {
            $run['state'] = 'refused';
            $run['message'] = (string)$result;
            return $run;
        }
        if (!empty($result['error'])) {
            $run['state'] = 'error';
            $run['message'] = is_string($result['error'])
                ? $result['error']
                : JsonTool::encode($result['error']);
            return $run;
        }
        if (empty($result['results'])) {
            $run['state'] = 'silent';
            return $run;
        }

        $results = $result['results'];
        $run['state'] = 'ok';
        $budget = self::ENRICHMENT_KEEP_CAP;

        if (isset($results['Attribute']) || isset($results['Object'])) {
            $attributes = isset($results['Attribute'])
                ? $results['Attribute'] : array();
            $objects = isset($results['Object'])
                ? $results['Object'] : array();
            $run['total'] = count($attributes) + count($objects);
            foreach ($attributes as $attribute) {
                if ($budget < 1) {
                    break;
                }
                $budget--;
                $run['attributes'][] = $this->enrichmentAttribute(
                    $attribute
                );
            }
            foreach ($objects as $object) {
                if ($budget < 1) {
                    break;
                }
                $budget--;
                $run['objects'][] = ValueRendererTool::shapeObject($object);
            }
        } else {
            foreach ($results as $entry) {
                if (!isset($entry['values'])) {
                    continue;
                }
                $values = is_array($entry['values'])
                    ? $entry['values']
                    : array($entry['values']);
                foreach ($values as $one) {
                    $run['total']++;
                    if ($budget < 1) {
                        continue;
                    }
                    $budget--;
                    $run['elements'][] = array(
                        'types' => isset($entry['types'])
                            ? (array)$entry['types']
                            : array(),
                        'value' => is_array($one)
                            ? JsonTool::encode($one)
                            : (string)$one,
                        'known' => false,
                    );
                }
            }
        }

        $run['kept'] = count($run['attributes'])
            + count($run['objects'])
            + count($run['elements']);
        $run['shown'] = min($run['kept'], self::ENRICHMENT_ELEMENT_CAP);
        $run['capped'] = $run['total'] > $run['shown'];
        if ($run['total'] === 0) {
            $run['state'] = 'silent';
        }
        /*
         * `$withKnown = false` is the store's boundary (§8.1): the
         * caller wants the module's answer to keep, and the chips
         * belong to whoever is reading rather than to the answer.
         */
        return $withKnown
            ? $this->enrichmentKnown($run, $user, $subject)
            : $run;
    }

    /**
     * Mark the returned values MISP already holds.
     *
     * **The one piece of phase 12's provenance that survives having no
     * store**, and the one that does the most work: §8.3 calls
     * *Already in MISP* "what stops an analyst adding a duplicate".
     * `New since <date>` is a delta against a previous run and is
     * gone; this is a question about the database right now, so it
     * needs no memory at all.
     *
     * `Value::prevalenceFor` is the right instrument and was built for
     * a different panel: it probes many values at once as separate
     * indexed equality lookups, caps each one, and applies the
     * reader's ACL — so the chip means *already in MISP **and** you
     * can see it*, which is the only version of the claim this page
     * may make.
     *
     * **Only values MISP would correlate on are asked about**, per
     * `ValueRendererTool::correlates()`. A row the probe is not asked about is
     * `known => false` and wears no chip, which is the honest state:
     * the page did not look, because there was nothing worth looking
     * for. This is what stops `count: 1` and `rrtype: A` from wearing
     * a duplicate warning.
     *
     * **Type-scoping the probe is not the fix, and was measured
     * before being rejected.** `28b-known-probe.php` compared an
     * untyped probe against one statement per distinct type over all
     * three modules: not one of the objectionable chips went away,
     * because MISP genuinely holds a `counter` with value 1 and a
     * `text` equal to `A`. The claim was true and useless, so the cure
     * is asking about fewer values rather than asking more precisely
     * — and it costs one statement fewer rather than six more.
     *
     * That filtering is also what keeps this under
     * `PREVALENCE_PROBE_CAP`. 200 rendered `passive-dns` objects carry
     * 1,400 attribute values against a 1,500 cap; dropping the three
     * relations of seven that MISP does not correlate on leaves ~800,
     * where the old code ran up against the cap and silently probed a
     * prefix.
     *
     * **One query for the whole result**, whatever the module
     * returned, and the value the page is about is excluded: every
     * module echoes the subject back, and telling a reader that
     * `8.8.8.8` is already in MISP on the page for `8.8.8.8` is noise.
     *
     * @param array $run
     * @param array $user
     * @param string $subject The value the page is about
     * @return array
     */
    /**
     * The values of kept module answers that MISP holds where this reader
     * can see them: what a fresh run marks "already in MISP", asked again
     * for whoever reads the graph keeping them. The same filter applies,
     * so only values MISP would correlate on are asked about.
     *
     * @param array $user
     * @param array $contents Answer contents, as a graph document stores them
     * @return string[]
     */
    public function knownAnswerValues(array $user, array $contents)
    {
        $wanted = array();
        foreach ($contents as $content) {
            switch ($content['kind'] ?? null) {
                case 'attribute':
                    if (ValueRendererTool::correlates(array('type' => $content['type']))) {
                        $wanted[] = (string)$content['value'];
                    }
                    break;
                case 'element':
                    if ($this->enrichmentElementCorrelates(array('types' => $content['types']))) {
                        $wanted[] = (string)$content['value'];
                    }
                    break;
                case 'object':
                    foreach ($content['attributes'] as $attribute) {
                        if (ValueRendererTool::correlates(array('type' => $attribute['type']))) {
                            $wanted[] = (string)$attribute['value'];
                        }
                    }
                    break;
            }
        }
        $wanted = array_values(array_unique(array_filter($wanted, 'strlen')));
        if (empty($wanted)) {
            return array();
        }
        $prevalence = $this->model('Value')->prevalenceFor($user, $wanted);
        return array_values(array_filter($wanted, function ($value) use ($prevalence) {
            return isset($prevalence['counts'][$value]) || isset($prevalence['capped'][$value]);
        }));
    }

    private function enrichmentKnown(array $run, array $user, $subject)
    {
        // Each element's values worth asking about, in the order shown.
        $asks = array();
        foreach ($run['attributes'] as $i => $attribute) {
            $asks[] = array('attributes', $i,
                $attribute['value'] !== null && $attribute['correlates']
                    ? array((string)$attribute['value']) : array());
        }
        foreach ($run['objects'] as $i => $object) {
            $values = array();
            foreach ($object['attributes'] as $attribute) {
                if ($attribute['value'] !== null
                    && $attribute['correlates']
                ) {
                    $values[] = (string)$attribute['value'];
                }
            }
            $asks[] = array('objects', $i, $values);
        }
        foreach ($run['elements'] as $i => $element) {
            $asks[] = array('elements', $i,
                $this->enrichmentElementCorrelates($element)
                    ? array((string)$element['value']) : array());
        }

        $budget = ValueEnrichmentTool::knownBudget(
            array_column($asks, 2),
            $subject,
            Value::PREVALENCE_PROBE_CAP
        );
        $run['known_checked'] = $budget['checked'];
        $counts = array();
        $capped = array();
        if (!empty($budget['values'])) {
            $prevalence = $this->model('Value')
                ->prevalenceFor($user, $budget['values']);
            $counts = $prevalence['counts'];
            $capped = $prevalence['capped'];
        }
        $known = function ($value) use ($counts, $capped) {
            $value = (string)$value;
            return isset($counts[$value]) || isset($capped[$value]);
        };

        foreach ($asks as $n => $ask) {
            list($list, $i) = $ask;
            $asked = $n < $budget['checked'];
            if ($list === 'objects') {
                $rows = $run['objects'][$i]['attributes'];
                foreach ($rows as $j => $attribute) {
                    $run['objects'][$i]['attributes'][$j]['known'] = $asked
                        && $attribute['correlates']
                        && $known($attribute['value']);
                }
            } elseif ($list === 'attributes') {
                $attribute = $run['attributes'][$i];
                $run['attributes'][$i]['known'] = $asked
                    && $attribute['correlates']
                    && $known($attribute['value']);
            } else {
                $element = $run['elements'][$i];
                $run['elements'][$i]['known'] = $asked
                    && $this->enrichmentElementCorrelates($element)
                    && $known($element['value']);
            }
        }
        return $run;
    }

    /**
     * The same question for a `simplified` module's bare element.
     *
     * There is no attribute row here and so no `disable_correlation` —
     * only the types the module says the value could be taken as. If
     * none of them is one MISP correlates on, neither is the value.
     *
     * @param array $element
     * @return bool
     */
    private function enrichmentElementCorrelates(array $element)
    {
        if (empty($element['types'])) {
            return true;
        }
        foreach ($element['types'] as $type) {
            if (!in_array(
                $type,
                MispAttribute::NON_CORRELATING_TYPES,
                true
            )) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array $attribute
     * @return array
     */
    private function enrichmentAttribute(array $attribute)
    {
        return array(
            'type' => isset($attribute['type'])
                ? $attribute['type'] : null,
            'value' => isset($attribute['value'])
                ? $attribute['value'] : null,
            'category' => isset($attribute['category'])
                ? $attribute['category'] : null,
            'comment' => isset($attribute['comment'])
                ? $attribute['comment'] : null,
            'to_ids' => !empty($attribute['to_ids']),
            'correlates' => ValueRendererTool::correlates($attribute),
            // Filled by enrichmentKnown; false where it never asked.
            'known' => false,
        );
    }

    /**
     * @param array|string $enabled
     * @param string $name
     * @return array|null
     */
    private function enrichmentModule($enabled, $name)
    {
        foreach ($enabled['modules'] as $module) {
            if ($module['name'] === $name) {
                return $module;
            }
        }
        return null;
    }

    /**
     * @param array $module
     * @return string
     */
    private function enrichmentFormat(array $module)
    {
        return isset($module['mispattributes']['format'])
            ? $module['mispattributes']['format']
            : 'simplified';
    }

    /**
     * @return int Seconds a module is given to answer
     */
    private function enrichmentTimeout()
    {
        $timeout = Configure::read('Plugin.Enrichment_timeout');
        return empty($timeout) ? 10 : (int)$timeout;
    }

    /*
     * ------------------------------------------------------------------
     * The assessment's context.
     *
     * One build, every signal. `03-signals.md` §2.2 makes the aggregate
     * shared rather than per signal, and the reason is arithmetic: the
     * eleven shipped signals between them read the occurrence tally,
     * the per-org stance, the publication split, the monthly activity,
     * the sighting rows, the tag and galaxy sets, the warninglist
     * result and the feed caches — twelve reads if each asked for its
     * own, seven queries if they share one context.
     *
     * It lives here rather than in the tool because §14.5 is explicit
     * that a `Value*` tool computes over data handed to it: the queries
     * and the ACL are the model's, the arithmetic is the tool's.
     * `forVerdict()` below wraps it for the page; phase 10 swaps in a
     * batch builder behind the same seam.
     * ------------------------------------------------------------------
     */

    /**
     * The assessment behind the Verdict tab, its rail, and the
     * Overview's verdict card.
     *
     * **One context build per request, and nothing shared between
     * them.** The three endpoints are three lazy requests in three PHP
     * processes, so there is no build for them to share — an earlier
     * draft of `10-wiring.md` promised *"one build, seven readers"* and
     * §7.4 there records why that was never available. What is shared
     * is inside a request: the rail renders five sub-elements off this
     * one array.
     *
     * What makes the card and the tab agree is therefore not sharing
     * but determinism — `assess()` returns the same array for the same
     * context and profile, which is also what lets the profile
     * simulator and phase 10's worker agree with the page. Any cache
     * added later sits behind that seam or the guarantee is gone.
     *
     * @param array $user
     * @param string $value
     * @param array $options `profile` scores against one other than the
     *                       viewer's — the simulator's seam; the rest
     *                       as `verdictContextFor`
     * @return array `value` and `verdict`, the envelope every
     *               `value_verdict*.ctp` reads
     */
    public function forVerdict(array $user, $value,
        array $options = array()
    ) {
        /*
         * The profile and the context are resolved **here** rather than
         * inside the engine, which would do both if asked, because the
         * display keys below are built from the same two and a second
         * resolution is a second chance to disagree. `verdictFor()`
         * takes either as an option precisely so a caller that needs
         * them can own them; `resolveFor()` memoises per request, so
         * holding it costs nothing.
         */
        /*
         * Whether the profile is the instance's own choice. A reader on
         * any other profile scores this value differently from a
         * colleague who kept the default, and the page says so; a
         * profile handed in by the caller is not the reader's, so the
         * question has no answer there.
         */
        $isInstanceDefault = null;
        if (array_key_exists('profile', $options)) {
            $profile = $options['profile'];
        } else {
            $resolution = ClassRegistry::init('AnalystProfile')
                ->resolutionFor($user);
            $profile = $resolution['profile'];
            if ($profile !== null) {
                $isInstanceDefault = isset($profile['uuid'])
                    && strtolower($profile['uuid']) === strtolower(
                        (string)$resolution['selections']['instance']
                    );
            }
        }
        $context = isset($options['context'])
            ? $options['context']
            : $this->verdictContextFor($user, $value, $profile, $options);
        $engine = new ValueVerdictTool($this);
        $verdict = $engine->verdictFor($user, $value, array_merge(
            $options,
            array('profile' => $profile, 'context' => $context)
        ));
        /*
         * The analyst union, and only where a panel draws it. It is the
         * Collaboration tab's own read — 7 to 28 queries, §14.12 — so
         * the two endpoints that show an opinion ask for it and
         * `viewVerdictCard`, which shows none, does not.
         *
         * **The same union, never a cheaper one.** A histogram built
         * from opinions on the attributes alone would count a subset of
         * what the Collaboration tab counts and the two panels would
         * disagree about how many opinions a value has — which is the
         * bug §14.3 had just finished fixing on the relevance axis. The
         * price of not having it twice is paying for it twice.
         */
        $standing = empty($options['with_opinions'])
            ? null
            : $this->analystContext($user, $value)['standing'];
        return array(
            'value' => $value,
            /*
             * Three layers, and the order is the contract. The skeleton
             * (`VERDICT_UNPRODUCED`) promises every key exists; the
             * engine's array wins every key it emits; the display keys
             * win last, because they are derived *from* the first two
             * and from the context, and a key they answer is a key the
             * skeleton was only holding open.
             */
            'verdict' => array_merge(
                self::VERDICT_UNPRODUCED,
                $verdict,
                $this->verdictPanels($verdict, $context, $profile,
                    $standing),
                array('profile_is_instance_default' => $isInstanceDefault)
            ),
        );
    }

    /**
     * The hover card: one assessment, read down to what fits in 400px.
     *
     * **The context is built here and handed to both readers**, which
     * is the whole of this method. `forVerdict()` accepts a `context`
     * option precisely so a caller that needs the context for itself
     * can own it, and this is that caller: the card's four tiles, its
     * spark, its dates and its warninglist row are all folded from the
     * same array the engine scored, so the hover and the page cannot
     * disagree and the hover costs nothing the assessment did not
     * already cost.
     *
     * The alternative was `forFrame()` beside `forVerdict()` — seven
     * queries plus nine to twenty-seven — on every hover of every row
     * of a table with fifty values in it. A reader sweeping a column
     * would have paid for fifty pages they did not open.
     *
     * `with_opinions` is deliberately not passed: the analyst union is
     * 7 to 28 queries and the card shows no opinion.
     *
     * @param array $user
     * @param string $value
     * @param array $options As `verdictContextFor`
     * @return array `value` and `card`, the envelope
     *               `value_hover_card.ctp` reads
     */
    public function forHoverCard(array $user, $value,
        array $options = array()
    ) {
        $profile = array_key_exists('profile', $options)
            ? $options['profile']
            : ClassRegistry::init('AnalystProfile')->resolveFor($user);
        $now = isset($options['now']) ? (int)$options['now'] : time();
        $context = $this->verdictContextFor(
            $user,
            $value,
            $profile,
            array_merge($options, array('now' => $now))
        );
        $envelope = $this->forVerdict($user, $value, array_merge(
            $options,
            array('profile' => $profile, 'context' => $context)
        ));
        $card = ValueHoverTool::cardFor(
            $envelope['verdict'],
            $context,
            $now,
            ValueLabelPriority::planFor($profile)
        );
        if (!empty($card['galaxy']['type'])) {
            $galaxy = ClassRegistry::init('Galaxy')->find('first', array(
                'conditions' => array('Galaxy.type' => $card['galaxy']['type']),
                'fields' => array('Galaxy.name'),
                'recursive' => -1,
            ));
            $card['galaxy']['galaxy'] = empty($galaxy['Galaxy']['name'])
                ? $card['galaxy']['type']
                : $galaxy['Galaxy']['name'];
        }
        return array(
            'value' => $value,
            'card' => $card,
        );
    }

    /**
     * The display keys the templates read and the engine does not emit.
     *
     * **Derived, never invented.** `10-wiring.md` §2.2 counts thirteen
     * keys the seventeen verdict templates read with no producer
     * behind them; eleven are answerable from facts the engine and
     * phases 5 and 6 already compute, and this is where those eleven
     * are answered. `changer_actions` and `resolutions` stay on the
     * skeleton's defaults and their cards stay dark, which is the
     * honest reading of *nothing computes this yet* — and
     * `resolutions` stays there for good until the page can write.
     *
     * It takes no `$user`: everything here is folded from a context
     * that was already scoped to the viewer, which is §14.5's rule
     * held at the one seam where it would be easy to break.
     *
     * @param array $verdict What the engine returned
     * @param array $context The context it scored
     * @param array|null $profile The profile in force
     * @param array|null $standing The Collaboration tab's own analyst
     *                             standing, where a caller asked for it
     * @return array The keys this method can answer, and only those
     */
    private function verdictPanels(array $verdict, array $context,
        $profile, $standing = null
    ) {
        /*
         * One derivation, two placements: the ledger's *Contradictions*
         * block on the agreeing layout and the card under the two cases
         * on the contested one show the same facts, so they are folded
         * once and handed out twice rather than computed apart.
         */
        $unresolved = ValueContestedTool::unresolvedFor($context);
        $panels = array(
            'summary' => ValueSummaryTool::summaryFor($verdict),
            'cases' => ValueContestedTool::casesFor($verdict),
            'conflicts' => $unresolved,
            'ambiguities' => $unresolved,
            /*
             * `aggregate` is null when nobody has opined, and the
             * histogram's own guard reads that as *no card* rather than
             * as an empty chart. Its shape is `analystAggregate()`'s
             * unchanged — `n`, `mean_label`, `buckets`, `note` — which
             * is what the two panels sharing one producer buys.
             */
            'opinions' => $standing === null
                ? null
                : $standing['aggregate'],
            'orgs' => $this->verdictOrgTable($context, $standing),
            'warninglist' => $this->verdictWarninglistBand($context),
            'composition_note' => $this->verdictCompositionNote($verdict,
                $profile),
        );
        return array_merge($panels, $this->verdictCurves($verdict));
    }

    /**
     * Under the arithmetic: whose weights these are.
     *
     * `10-wiring.md` §3 retires the shipped sentence *"An instance
     * admin can edit the profile; the tab always names the one in
     * force"*. Its second half was true and is said one card away, by
     * `value_verdict_meta`; its first half is wrong under D3, because
     * the profile most readers are weighted by is their own or their
     * organisation's and no instance admin can touch it.
     *
     * What replaces it is the thing the meta line cannot say: which
     * scope owns the profile in force. It states the scope and stops;
     * what an edit or a fork would move is the editor's to explain.
     *
     * Drawn only where something was weighted. A value with no ledger
     * has a profile in force and nothing was computed under it, and
     * §3.1's conditional exists so the page does not claim otherwise.
     *
     * @param array $verdict What the engine returned
     * @param array|null $profile The profile in force
     * @return string|null
     */
    private function verdictCompositionNote(array $verdict, $profile)
    {
        if (empty($profile) || empty($verdict['composition'])) {
            return null;
        }
        $name = isset($profile['name']) ? $profile['name'] : '';
        switch (ClassRegistry::init('AnalystProfile')->scopeOf($profile)) {
            case 'user':
                return sprintf(
                    __(
                        'Weights come from %s, your own profile.'
                    ),
                    $name
                );
            case 'org':
                return sprintf(
                    __(
                        'Weights come from %s, your organisation\'s'
                        . ' profile.'
                    ),
                    $name
                );
            case 'shared':
                return sprintf(
                    __('Weights come from %s, a shared profile.'),
                    $name
                );
            default:
                return sprintf(
                    __(
                        'Weights come from %s, the instance default.'
                    ),
                    $name
                );
        }
    }

    /**
     * *Who says what* — the same argument counted by organisation.
     *
     * Every column but one is folded from facts the context already
     * carries, and folding rather than querying is the point: the table
     * and the ledger have to be counting the same rows or the card
     * beside the argument contradicts it. `reporting.independent_orgs`
     * counts these organisations; `sightings.false_positive` counts
     * these filers.
     *
     * **`opinion` is the one column with no source**, and it renders as
     * *none stated* rather than as a zero — zero is an opinion, and the
     * strongest possible disagreement at that. MISP does hold analyst
     * opinions and this page already reads them for Collaboration and
     * for the Timeline, but per organisation and per value is an
     * aggregate nothing computes yet.
     *
     * What an organisation *reads the value as* is not a column here:
     * it is a lean-side reading that belongs with the conflicted
     * layout's cases.
     *
     * @param array $context
     * @param array|null $standing The Collaboration tab's standing,
     *                             where the caller paid for it
     * @return array One row per organisation, widest reporter first
     */
    private function verdictOrgTable(array $context, $standing = null)
    {
        /*
         * An organisation's strongest opinion, keyed by its id.
         * `analystStanding()` orders each organisation's opinions
         * strongest first and lists them all, so the first row per id
         * is the one this column wants — and it is the same row the
         * Collaboration tab puts at the top of that organisation's
         * lane.
         */
        $opinions = array();
        if ($standing !== null) {
            foreach ($standing['orgs'] as $row) {
                if (empty($row['org_id'])
                    || isset($opinions[(int)$row['org_id']])
                ) {
                    continue;
                }
                $opinions[(int)$row['org_id']] = $row;
            }
        }
        $orgs = isset($context['orgs']) ? $context['orgs'] : array();
        if (empty($orgs)) {
            return array();
        }
        $byOrg = isset($context['sightings']['by_org'])
            ? $context['sightings']['by_org']
            : array();
        $byOrgFp = isset($context['sightings']['by_org_fp'])
            ? $context['sightings']['by_org_fp']
            : array();
        $uuids = $this->model('Organisation')->find('list', array(
            'recursive' => -1,
            'fields' => array('Organisation.id', 'Organisation.uuid'),
            'conditions' => array(
                'Organisation.id' => array_column($orgs, 'id'),
            ),
        ));

        $rows = array();
        foreach ($orgs as $org) {
            $id = (int)$org['id'];
            $rows[] = array(
                'org' => $org['name'],
                'org_id' => $id,
                'org_uuid' => isset($uuids[$id]) ? $uuids[$id] : null,
                'occurrences' => (int)$org['occurrences'],
                'sightings' => isset($byOrg[$id]) ? (int)$byOrg[$id] : 0,
                'fp' => isset($byOrgFp[$id]) ? (int)$byOrgFp[$id] : 0,
                /*
                 * Still `null` where nobody from this organisation has
                 * opined, which the template draws as *none stated*.
                 * Zero is an opinion — the strongest available
                 * disagreement — so a value nobody has opined on must
                 * not read as one eight organisations thought
                 * worthless (§9.2).
                 */
                'opinion' => isset($opinions[$id])
                    ? (int)$opinions[$id]['score']
                    : null,
                'to_ids' => $this->verdictStanceWord($org),
                /*
                 * The grade the engine weighted this organisation
                 * with, which for an ungraded one is `unrated` — the
                 * same fallback `ValueTrustTool::factor()` takes, so
                 * the column cannot say one thing while the ledger
                 * counted another. `gradeFor()` answers null there and
                 * null is not a grade; the map's own word for *no
                 * opinion recorded* is.
                 *
                 * **The whole context, not the trust block.**
                 * `blockFrom()` reads `$context['trust']` itself, so
                 * handing it the block makes it look for
                 * `trust.trust`, miss, and grade every organisation
                 * null — which looks exactly like an empty map.
                 */
                'reliability' => ValueTrustTool::gradeFor($context, $id)
                    ?: ValueTrustTool::UNRATED,
            );
        }
        /*
         * Widest reporter first, which is the order the ledger's own
         * evidence line names them in.
         */
        usort($rows, function ($a, $b) {
            if ($a['occurrences'] !== $b['occurrences']) {
                return $b['occurrences'] - $a['occurrences'];
            }
            return strcasecmp($a['org'], $b['org']);
        });
        return $rows;
    }

    /**
     * One organisation's `to_ids` stance in a word.
     *
     * `mixed` is a real answer rather than a rounding: an organisation
     * with the value twice, actionable once, has not made one decision
     * about it, and the lean counts stances per organisation for the
     * same reason (`04-dispositions.md` §2).
     *
     * @param array $org A context org row
     * @return string
     */
    private function verdictStanceWord(array $org)
    {
        $yes = (int)$org['to_ids_yes'];
        $no = (int)$org['to_ids_no'];
        if ($yes > 0 && $no > 0) {
            return __('mixed');
        }
        if ($yes > 0) {
            return __('yes');
        }
        if ($no > 0) {
            return __('no');
        }
        return __('none');
    }

    /**
     * The warninglist band: the hit that decided the category.
     *
     * One band and not a list, because the band is a *side talking* and
     * the side is the category — so the hit shown is one that resolved
     * to the category the context settled on, and `false_positive`
     * outranks `known` there for the reason `verdictWarninglist()`
     * gives. A value matching three `known` lists is not three
     * arguments.
     *
     * The note is `WarninglistCategory`'s, not this method's: what a
     * category claims is knowledge about the category.
     *
     * @param array $context
     * @return array|null
     */
    private function verdictWarninglistBand(array $context)
    {
        $block = isset($context['warninglist'])
            ? $context['warninglist']
            : array();
        $category = isset($block['category']) ? $block['category'] : null;
        if ($category === null || empty($block['hits'])) {
            return null;
        }
        foreach ($block['hits'] as $hit) {
            if ($hit['category'] !== $category) {
                continue;
            }
            return array(
                'name' => $hit['name'],
                'version' => $hit['version'],
                'category' => $category,
                'matched' => $hit['matched'],
                'type' => $hit['type'],
                'note' => WarninglistCategory::note($category),
            );
        }
        return null;
    }

    /**
     * The stored enrichment answers this reader's organisation holds,
     * with the profile's grade for each module beside them.
     *
     * **One indexed read of one table, and the payloads it needs.**
     * The runs are already stored shaped, so nothing is parsed and
     * nothing is asked of a module — the signal that scores these is
     * forbidden from querying, and the reason is that a score which
     * moved because a vendor was slow is not reproducible.
     *
     * **A module the profile has not graded is still read.** Its
     * answer appears in the ledger marked as not counted, which is
     * what makes grading it a single visible act rather than a setting
     * whose effect nobody can see. Skipping ungraded modules here
     * would make the shipped default look like an instance where
     * nothing had ever been asked.
     *
     * @param array $user
     * @param string $value
     * @param array|null $profile
     * @param array $options `scored_enrichment => false` builds none
     * @return array `runs` and `trust`
     */
    private function verdictEnrichment(array $user, $value, $profile,
        array $options = array()
    ) {
        $empty = array('runs' => array(), 'trust' => array(
            'grades' => array(),
            'factors' => array(),
            'in_force' => false,
        ));
        if (array_key_exists('scored_enrichment', $options)
            && empty($options['scored_enrichment'])
        ) {
            return $empty;
        }
        if (empty($user['org_id'])) {
            return $empty;
        }
        $plan = ValueTrustTool::modulePlanFor($profile);
        $store = $this->model('ValueEnrichmentRun');
        $held = $store->forValue($user, $value);
        if (empty($held)) {
            return $empty;
        }
        $runs = array();
        $factors = array();
        foreach ($held as $row) {
            if ($row['state'] !== 'ok') {
                continue;
            }
            $shaped = ValueEnrichmentRun::unpack(
                $store->one($user, $value, $row['module'], $row['type'])
                    ?: array()
            );
            if ($shaped === null) {
                continue;
            }
            $shaped = $this->enrichmentView($shaped);
            $shaped['ran_at'] = (int)$row['last_run'];
            $runs[] = $shaped;
            $factors[$row['module']] = ValueTrustTool::moduleFactor(
                $plan,
                $row['module']
            );
        }
        return array(
            'runs' => $runs,
            'trust' => array(
                'grades' => $plan['grades'],
                'factors' => $factors,
                'in_force' => !empty($plan['in_force']),
            ),
        );
    }

    /**
     * The rail's chart: shelf life over the last 90 days.
     *
     * **There is no verdict history to plot.** This page computes at render and
     * stores nothing, so there is no yesterday to draw. Phase 10's
     * materialisation is the first thing that could make one, and it stores a
     * current row rather than a series.
     *
     * So the card draws the one quantity on this tab that genuinely has
     * ninety days behind it: the relevance runway, which is
     * `06-staleness.md` §4.2's *remaining shelf life* — computed from
     * dates rather than from stored scores, which is why it can be
     * reconstructed for any past day and the signal strength cannot. It is also
     * the only place the Verdict tab says anything at all about the
     * second of D11's three axes.
     *
     * @param array $verdict Carrying the `relevance` block
     * @return array `curves`, `curves_span`, `curves_note`
     */
    private function verdictCurves(array $verdict)
    {
        $relevance = isset($verdict['relevance'])
            ? $verdict['relevance']
            : array();
        if (empty($relevance) || empty($relevance['state'])) {
            return array();
        }
        $grid = $this->verdictDayGrid(self::VERDICT_CURVE_DAYS);
        $points = ValueRelevanceTool::runwaySeries($relevance, $grid);
        $drawn = false;
        foreach ($points as $i => $point) {
            if ($point === null) {
                continue;
            }
            $drawn = true;
            $points[$i] = (int)round($point * 100);
        }
        if (!$drawn) {
            return array();
        }
        /*
         * The Sightings overlay plots this same series as its Lifetime
         * line, so it is drawn in that line's ink rather than in one of
         * its own: two cards showing one series in two colours is the
         * drift `value-palette.css` exists to stop. It is also the only
         * shelf life ink with a dark theme behind it — `--sighting`,
         * which this asked for until 2026-09-22, is #890096 at 1.84:1
         * on `#212529`.
         */
        return array(
            'curves' => array(array(
                'label' => __('Shelf life left'),
                'colour' => 'var(--vp-sight-curve-1)',
                'data' => $points,
            )),
            'curves_span' => __('90 days'),
            'curves_note' => __(
                'Shelf life left on this value\'s TTL, day by day.'
                . ' Independent corroboration pushes it up; time alone'
                . ' brings it down. Reaching zero means the assessment'
                . ' has expired, not that the value is benign.'
            ),
        );
    }

    /**
     * One unix stamp per day for the last `$days`, oldest first.
     *
     * `dayGrid()`'s sibling for a fixed window rather than a measured
     * span. The chart's labels are computed from the point count on the
     * assumption that the series spans 90 days
     * (`value_verdict_curves.ctp`), so the window is the constant and
     * the grid follows it.
     *
     * @param int $days
     * @return array
     */
    private function verdictDayGrid($days)
    {
        $now = time();
        $grid = array();
        for ($back = $days - 1; $back >= 0; $back--) {
            $grid[] = $now - ($back * 86400);
        }
        return $grid;
    }

    /**
     * Every fact the signal-strength ledger reads, for one value and one
     * viewer.
     *
     * The contract — every key, and which evidence class it belongs to
     * — is documented on `ValueSignalBase`, because that is the file a
     * signal author reads.
     *
     * **Two evidence classes, and the budget only bounds one**
     * (`03-signals.md` §2.3). Index aggregates — the tally, the org
     * count, the monthly buckets, the warninglist result — are
     * computed whole-history, always: a window would blind the
     * freshness clock and undercount a long-history value's reporting
     * breadth. Row evidence is the sighting rows and the per-occurrence
     * tag detail, and that is what the window cuts, because rows were
     * the cost.
     *
     * **Deterministic by design.** No row caps and no stopwatch: the
     * page, the profile simulator and phase 10's worker all compute
     * this and they have to agree, so what the context contains is
     * decided by the profile's own policy rather than by server load.
     *
     * @param array $user
     * @param string $value
     * @param array|null $profile The profile in force; its
     *                            `exclusions` set the budget and its
     *                            `reference` map resolves warninglist
     *                            categories
     * @param array $options `now` fixes the clock for a test; the rest
     *                       as conditionsFor
     * @return array
     */
    public function verdictContextFor(array $user, $value,
        $profile = null, array $options = array()
    ) {
        /*
         * **A string, whatever the caller had.** PHP turns a numeric
         * array key into an integer, so a caller iterating a map of
         * values hands `1` over as `int 1` — and an integer compared
         * against a `varchar` column makes MariaDB convert the column
         * rather than use its index. Measured on this instance's
         * largest value: 31 ms as a string, 9.4 seconds as an integer,
         * same rows either way. `Value::prevalenceFor` records the same
         * trap from the other direction, and the phase 2 probe walked
         * straight into it.
         */
        $value = (string)$value;
        $this->forget($value);
        $now = isset($options['now']) ? (int)$options['now'] : time();
        $valueModel = $this->model('Value');
        /*
         * The exclusions, resolved before anything is read. The
         * condition-class ones ride in `$options` from here on, so
         * every aggregate below is computed over the same set — which
         * is the property that stops reporting breadth and the
         * occurrence tally disagreeing about whose rows count.
         */
        $exclusions = new ValueExclusionTool();
        $plan = $exclusions->planFor($profile, $user);
        $options = array_merge(
            $options,
            $exclusions->conditionOptions($plan)
        );
        $record = $valueModel->recordSummaryFor($user, $value, $options);
        $types = $valueModel->typesFor($user, $value, $options);
        $budget = $this->verdictBudget($value, $record, $profile);

        $context = array(
            'value' => $value,
            'now' => $now,
            'as_of' => date('Y-m-d', $now),
            // Per-organisation like enrichment, so dropped with it.
            'viewer' => array('org_id' => array_key_exists(
                'scored_enrichment',
                $options
            ) && empty($options['scored_enrichment'])
                ? 0
                : (int)($user['org_id'] ?? 0)),
            'types' => $types,
            'occurrences' => array(
                'total' => $record['occurrences'],
                'events' => $record['events'],
                'orgs' => $record['orgs'],
                'oldest' => $record['oldest'],
                'newest' => $record['newest'],
            ),
            'publication' => array(
                'events' => $record['events'],
                'published' => $record['published'],
                'unpublished' => max(
                    0,
                    $record['events'] - $record['published']
                ),
            ),
            'temporal' => array(
                'occurrences' => $record['occurrences'],
                'with_first_seen' => $record['dated'],
            ),
            'orgs' => $this->verdictOrgs($user, $value, $options),
            /*
             * What the analyst believes about their sources (phase 6).
             * Resolved before any signal runs, because three of them
             * weight against it and a context that carried the grades
             * per signal would let the ledger's own rows disagree about
             * who counts (`07-reference.md` §2.4).
             */
            'trust' => $this->verdictTrust($profile),
            'activity' => $this->verdictActivity(
                $valueModel->activityMonthsFor($user, $value, $options)
            ),
            'warninglist' => $this->verdictWarninglist(
                $value,
                $types,
                $profile
            ),
            'sightings' => array('total' => 0, 'fp' => 0,
                'seen' => ValueStatsTool::seenFacts(array(), $now,
                    self::VERDICT_RECENT_DAYS)),
            /*
             * The relevance clock's sighting half. Empty here and
             * filled by the row read below, so a value whose rows were
             * not fetched has a clock that says which half it is
             * missing rather than one that quietly runs off the
             * occurrences alone.
             */
            'corroboration' => ValueRelevanceTool::corroborationFrom(
                array(),
                array()
            ),
            'galaxies' => array(
                'clusters' => array(),
                'techniques' => array(),
                'types' => array(),
                'attribution' => ValueLabelPriority::attribution($profile),
                'on_events' => array(),
                'on_flagged_events' => array(),
                'event_types' => array(),
            ),
            'statements' => array('events' => array()),
            'budget' => $budget,
            /*
             * What outside sources have said, and how far this profile
             * believes each of them.
             *
             * **Scoped to the viewer's organisation**, because the run
             * store is: an answer this organisation paid for is not
             * evidence anybody else on the instance holds. The honest
             * consequence, stated rather than hidden, is that two
             * organisations on one instance can legitimately read
             * different signal strength numbers for the same value — because
             * they know different things about it. Each ledger says
             * why, on the row.
             *
             * **And it is the seam the export gate needs.** The gate
             * materialises one assessment per value under the instance
             * default profile so that `restSearch` can filter on it,
             * and a per-organisation number cannot be that: the
             * filtering decision would depend on which org happened to
             * run which module, which is irreproducible for everyone
             * else. A caller building the assessment passes
             * `scored_enrichment => false` and gets a context with no
             * enrichment in it at all, so the exclusion is structural
             * rather than a rule somebody has to remember.
             */
            'enrichment' => $this->verdictEnrichment(
                $user,
                $value,
                $profile,
                $options
            ),
            'excluded' => array(),
            'missing' => array(),
        );

        $feeds = $this->verdictFeeds($user, $value, $exclusions, $plan,
            array_column($context['orgs'], 'id'));
        $context['feeds'] = $feeds['facts'];
        if ($feeds['missing'] !== null) {
            $context['missing']['feeds'] = $feeds['missing'];
        }
        $feedsExcluded = $feeds['excluded']
            + count($feeds['reporter_feeds']);
        if ($feedsExcluded > 0) {
            $context['excluded']['feeds'] = $feedsExcluded;
        }
        $tallies = array('sources' => $feeds['excluded'],
            'reporter_feeds' => $feeds['reporter_feeds']);

        /*
         * The row evidence, and the tier that skips it. A value MISP
         * flagged as over-correlating is one a window cannot bound —
         * a live campaign puts everything inside 90 days — so the
         * rows are not fetched at all and the engine puts the signals
         * that read them in `not_counted`.
         */
        if (empty($budget['hot'])) {
            $sightings = $this->verdictSightings(
                $user,
                $value,
                $options,
                $now,
                $budget,
                $exclusions,
                $plan
            );
            $context['sightings'] = $sightings['facts'];
            $context['corroboration'] = $sightings['corroboration'];
            $tallies['sightings'] = $sightings['excluded'];
            $tallies['sightings_undecidable'] =
                $sightings['undecidable'];
            if ($sightings['excluded'] > 0) {
                /*
                 * Absent because excluded is not absent: without this
                 * the sightings signals' absence keys would fire on a
                 * value whose every sighting the profile removed,
                 * which is the profile's own decision being scored as
                 * evidence about the value.
                 */
                $context['excluded']['sightings'] =
                    ($context['excluded']['sightings'] ?? 0)
                    + $sightings['excluded'];
            }
            if ($sightings['windowed'] > 0) {
                /*
                 * §4.2: absent because windowed is not absent. Without
                 * this the absence key would fire on a value with a
                 * decade of sightings and none in the last 90 days,
                 * which is not a value nobody has sighted.
                 */
                $context['excluded']['sightings'] =
                    ($context['excluded']['sightings'] ?? 0)
                    + $sightings['windowed'];
            }
            $events = $this->verdictEvents($user, $value, $options,
                $budget, $now);
            $context['galaxies'] = $this->verdictGalaxies(
                $user,
                $value,
                $options,
                $budget,
                $now,
                $profile,
                $events
            );
            $context['statements'] = $this->verdictStatements($user,
                $value, $options, $events);
        }

        /*
         * What the profile left out, in the shape the ledger's own
         * `not_counted` entries use. It travels on the context rather
         * than being fetched by the accumulator, because the counts are
         * only knowable where the filtering happened.
         */
        $context['exclusions'] = $exclusions->notes($plan, $tallies);

        return $context;
    }

    /**
     * The evidence budget in force for this value.
     *
     * Three tiers, expressed in evidence time rather than in rows:
     * normal values are scored from everything and say nothing; past
     * `min_occurrences` the row evidence is cut to the window and the
     * cut is stated as the profile policy it is; a value in
     * `over_correlating_values` — MISP's own *too hot* mechanism — has
     * its row-hungry signals bow out.
     *
     * The window comes from the `evidence.window` exclusion, so it is
     * the analyst's policy and not a constant in this file.
     *
     * @param string $value
     * @param array $record From `Value::recordSummaryFor`
     * @param array|null $profile
     * @return array
     */
    private function verdictBudget($value, array $record, $profile)
    {
        $window = null;
        $threshold = null;
        foreach ($this->verdictSection($profile, 'exclusions') as $rule) {
            if (($rule['id'] ?? null) !== 'evidence.window') {
                continue;
            }
            /*
             * **An entry with no `enabled` key is on**, which is how the
             * shipped default expresses itself, and one with `enabled`
             * false is off. Every other exclusion has honoured that
             * since phase 4 — `ValueExclusionTool::entries()` drops a
             * disabled rule — and this one did not, because it reads the
             * raw section rather than going through the plan. So the
             * window applied whatever the profile said, and phase 8's
             * editor was about to draw a toggle with nothing behind it.
             * Found by reading the two paths side by side while building
             * the exclusions form (09-editor.md §7a).
             */
            if (array_key_exists('enabled', $rule) && empty($rule['enabled'])) {
                continue;
            }
            $window = isset($rule['days']) ? (int)$rule['days'] : null;
            $threshold = isset($rule['min_occurrences'])
                ? (int)$rule['min_occurrences']
                : null;
        }
        $occurrences = (int)$record['occurrences'];
        $inForce = ($window !== null && $threshold !== null
            && $occurrences >= $threshold);
        return array(
            'window_days' => $inForce ? $window : null,
            'hot' => $this->overCorrelating($value),
            'occurrences' => $occurrences,
            'threshold' => $threshold,
        );
    }

    /**
     * Each organisation's stake in the value, with a name on it.
     *
     * The stance columns ride along unread by this phase: the lean
     * derivation (phase 3) counts them per organisation, and it will
     * find them here rather than issuing the query again.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    private function verdictOrgs(array $user, $value, array $options)
    {
        $rows = $this->model('Value')
            ->orgStanceFor($user, $value, $options);
        $names = $this->organisationIdentities($rows);
        $orgs = array();
        foreach ($rows as $row) {
            $id = (int)$row['Event']['orgc_id'];
            $orgs[] = array(
                'id' => $id,
                /*
                 * The stable key a shared profile grades by, carried
                 * beside the local id for the reason `ValueTrustTool`
                 * gives: an id is local, a uuid is the organisation
                 * (`07-reference.md` §2.2). Nothing on the page prints
                 * it; the lean and the trust join both need it.
                 */
                'uuid' => isset($names[$id]['uuid'])
                    ? $names[$id]['uuid']
                    : null,
                'name' => isset($names[$id]['name'])
                    ? $names[$id]['name']
                    : __('Unknown organisation'),
                'occurrences' => (int)$row[0]['occurrences'],
                'to_ids_yes' => (int)$row[0]['to_ids_yes'],
                'to_ids_no' => (int)$row[0]['to_ids_no'],
                'newest' => (int)$row[0]['newest'],
                'newest_flagged' => empty($row[0]['newest_flagged'])
                    ? null
                    : (int)$row[0]['newest_flagged'],
                // When this organisation joined — the relevance clock's
                // occurrence half (`06-staleness.md` §3.3).
                'oldest' => (int)$row[0]['oldest'],
            );
        }
        return $orgs;
    }

    /**
     * The organisations behind a set of stance rows, name **and** uuid.
     *
     * `organisationNames()`'s two-column sibling rather than a second
     * column on it: that method answers a `find('list')` and eleven
     * callers read it as `id => name`, so widening it would be a
     * refactor of the whole file to serve one phase.
     *
     * @param array $rows Rows carrying `Event.orgc_id`
     * @return array id => `name` and `uuid`
     */
    private function organisationIdentities(array $rows)
    {
        $ids = array();
        foreach ($rows as $row) {
            if (!empty($row['Event']['orgc_id'])) {
                $ids[(int)$row['Event']['orgc_id']] = true;
            }
        }
        if (empty($ids)) {
            return array();
        }
        $found = $this->model('Organisation')->find('all', array(
            'recursive' => -1,
            'fields' => array('Organisation.id', 'Organisation.name',
                'Organisation.uuid'),
            'conditions' => array(
                'Organisation.id' => array_keys($ids),
            ),
        ));
        $out = array();
        foreach ($found as $org) {
            $out[(int)$org['Organisation']['id']] = array(
                'name' => $org['Organisation']['name'],
                'uuid' => strtolower(
                    (string)$org['Organisation']['uuid']
                ),
            );
        }
        return $out;
    }

    /**
     * `id` and `name` pairs, in the order the ids arrived.
     *
     * @param array $ids
     * @param array $names id => name
     * @return array
     */
    private function orgPairs(array $ids, array $names)
    {
        $pairs = array();
        foreach ($ids as $id) {
            $pairs[] = array(
                'id' => (int)$id,
                'name' => isset($names[$id]) ? $names[$id] : null,
            );
        }
        return $pairs;
    }

    /**
     * The profile's source-trust grades, joined to this instance.
     *
     * The uuid→id resolution `ValueTrustTool` cannot do: the profile
     * grades `organisations.uuid` because that is the organisation, and
     * every row downstream — the stance rows, the sighting rows —
     * carries the local id. Resolved **once**, here, so the two
     * sightings signals and the reporting signal all weight against the
     * same join rather than three.
     *
     * **One query, and only when the map has something in it.** An
     * empty map takes the mechanism out of the path entirely
     * (`ValueTrustTool::planFor`), so the default profile costs nothing
     * — which is the property that lets §5 item 1 be *the same ledger
     * to the unit* rather than *the same ledger and one more query*.
     *
     * The lookup is over the graded uuids and not over the value's own
     * organisations, because §4's first row needs the difference: a
     * grade whose uuid is on this instance but not on this value is
     * silent and uninteresting, while a grade whose uuid is on no
     * organisation at all is *kept, ignored and reported*. Only a
     * lookup keyed by the map can tell those apart.
     *
     * @param array|null $profile
     * @return array The context's `trust` block
     */
    private function verdictTrust($profile)
    {
        $plan = ValueTrustTool::planFor($profile);
        if (empty($plan['in_force'])) {
            return ValueTrustTool::contextFrom($plan, array());
        }
        $uuids = array_keys($plan['grades']);
        $found = $this->model('Organisation')->find('all', array(
            'recursive' => -1,
            'fields' => array('Organisation.id', 'Organisation.name',
                'Organisation.uuid'),
            'conditions' => array('Organisation.uuid' => $uuids),
        ));
        $present = array();
        foreach ($found as $org) {
            $key = strtolower((string)$org['Organisation']['uuid']);
            $present[$key] = array(
                'id' => (int)$org['Organisation']['id'],
                'name' => $org['Organisation']['name'],
            );
        }
        return ValueTrustTool::contextFrom($plan, $present);
    }

    /**
     * The monthly activity, read for continuity.
     *
     * `longest_run` is the longest unbroken sequence of calendar
     * months with at least one occurrence — the number
     * `lifecycle.continuity` states — against `active_months`, which
     * counts them however they are scattered, and `span_months`, the
     * distance from the first to the last.
     *
     * @param array $months `YYYY-MM` => occurrences, oldest first
     * @return array
     */
    private function verdictActivity(array $months)
    {
        $keys = array_keys($months);
        $run = 0;
        $longest = 0;
        $previous = null;
        foreach ($keys as $key) {
            $index = $this->monthIndex($key);
            if ($index === null) {
                continue;
            }
            $run = ($previous !== null && $index === $previous + 1)
                ? $run + 1
                : 1;
            $longest = max($longest, $run);
            $previous = $index;
        }
        $first = empty($keys) ? null : $this->monthIndex($keys[0]);
        $last = empty($keys)
            ? null
            : $this->monthIndex($keys[count($keys) - 1]);
        return array(
            'months' => $months,
            'active_months' => count($months),
            'span_months' => ($first === null || $last === null)
                ? 0
                : ($last - $first + 1),
            'longest_run' => $longest,
        );
    }

    /**
     * A `YYYY-MM` key as a month counter, so consecutive months are
     * consecutive integers across a year boundary.
     *
     * @param string $key
     * @return int|null
     */
    private function monthIndex($key)
    {
        if (!preg_match('/^(\d{4})-(\d{2})$/', (string)$key, $parts)) {
            return null;
        }
        return (int)$parts[1] * 12 + ((int)$parts[2] - 1);
    }

    /**
     * The warninglist result, and the category it resolves to.
     *
     * `ValueWarninglistTool` is the page's one warninglist read — the
     * event view's own Redis-backed check — and it is asked about every
     * type the value is stored under, because a `sha1` seen once as an
     * `md5` would otherwise escape the list it is on.
     *
     * **The category is resolved, not read.** `07-reference.md` §3.1
     * verified that no shipped list sets one and that
     * `Warninglist::__updateList()` drops the field on import, so the
     * order is: the profile's override map by exact list name, then
     * the shipped name map, then the database column, then
     * `false_positive` — the column's own default and what MISP's
     * warning banner has always meant by a hit. `WarninglistCategory`
     * owns the whole order, including why the shipped map sits *above*
     * the column, and every hit carries the `source` that answered it
     * so the panel can name it (§3.2, §5 item 12).
     *
     * **A refuting hit outranks a contextualising one.** Where a value
     * hits both a `false_positive` list and a `known` one, the
     * resolution is `false_positive`: the first says *this is not an
     * indicator*, the second only says *this cannot be attributed to
     * one tenant*, and the clash between the second and wide reporting
     * is what phase 3's escalation names.
     *
     * @param string $value
     * @param array $types From `Value::typesFor`
     * @param array|null $profile
     * @return array
     */
    private function verdictWarninglist($value, array $types, $profile)
    {
        $warninglist = $this->model('Warninglist');
        $pairs = array();
        foreach ($types as $type) {
            $pairs[] = array('type' => $type['type'], 'value' => $value);
        }
        $hits = ValueWarninglistTool::hitsFor($warninglist, $pairs, false);
        $lists = isset($hits[$value]) ? $hits[$value] : array();
        $overrides = $this->verdictSection($profile, 'reference');
        $map = isset($overrides['warninglist_category'])
            && is_array($overrides['warninglist_category'])
            ? $overrides['warninglist_category']
            : array();
        $resolved = array();
        $rows = array();
        $sources = array();
        foreach ($lists as $hit) {
            $name = $hit['name'];
            $answer = WarninglistCategory::resolve(
                $name,
                isset($hit['category']) ? $hit['category'] : null,
                $map
            );
            $resolved[$answer['category']] = true;
            $sources[$answer['source']] = true;
            $rows[] = array(
                'name' => $name,
                'category' => $answer['category'],
                /*
                 * Which of the four steps answered, per hit. The
                 * standing requirement §3.2 puts against name-keying:
                 * an override that stopped matching because a list was
                 * renamed upstream is then visible on the page rather
                 * than silent.
                 */
                'category_source' => $answer['source'],
                'matched' => $hit['matched'] ?? null,
                // The band's two remaining fields (phase 9). No signal
                // reads either; they are what the hit looks like on the
                // page rather than what it is worth.
                'version' => $hit['version'] ?? null,
                'type' => $hit['type'] ?? null,
            );
        }
        $category = null;
        if (isset($resolved[WarninglistCategory::FALSE_POSITIVE])) {
            $category = WarninglistCategory::FALSE_POSITIVE;
        } elseif (!empty($resolved)) {
            $category = array_keys($resolved)[0];
        }
        return array(
            'hits' => $rows,
            'lists_checked' => ValueWarninglistTool::enabledCount(
                $warninglist
            ),
            'category' => $category,
            /*
             * Every source that answered anything, so a reader of the
             * aggregate can tell *the instance decided this* from
             * *I decided this* without walking the hits.
             */
            'category_sources' => array_keys($sources),
        );
    }

    /**
     * External corroboration: the cached feeds and MISP servers
     * carrying this value.
     *
     * `externalPresence` is the External tab's own read, reused rather
     * than a second regime — and it already applies the two ACL rules
     * that matter here: a feed the viewer may not see is not counted,
     * and server hits are site-admin only.
     *
     * **Nothing cached is a gap, not an answer.** An instance that has
     * never populated a feed cache would otherwise have every value
     * score *"no enabled feed carries it"*, which is the engine reading
     * its own blindness as evidence. It goes to `missing`, and the
     * signal lands in `not_counted` (§4.3).
     *
     * @param array $user
     * @param string $value
     * @param ValueExclusionTool|null $exclusions
     * @param array $plan
     * @param array $reporters The value's reporting organisation ids,
     *                         for `feeds.reporters`
     * @return array `facts`, `missing`, `excluded` (mirrors folded)
     *               and `reporter_feeds` (names of feeds folded into
     *               their publisher)
     */
    private function verdictFeeds(array $user, $value,
        $exclusions = null, array $plan = array(),
        array $reporters = array()
    ) {
        $presence = $this->externalPresence($user, $value);
        $cached = isset($presence['cached'])
            ? $presence['cached']
            : array();
        $anyCache = !empty($cached['feeds']) || !empty($cached['servers']);
        $sources = $presence['sources'];
        $excluded = 0;
        $reporterFeeds = array();
        if ($exclusions !== null) {
            if (isset($plan['rules'][ValueExclusionTool::FEEDS_REPORTERS])
                && !empty($reporters)
            ) {
                $own = $exclusions->applyToReporters(
                    $this->feedPublishers($sources),
                    $reporters,
                    $plan
                );
                $sources = $own['sources'];
                $reporterFeeds = $own['names'];
            }
            $folded = $exclusions->applyToSources($sources, $plan);
            $sources = $folded['sources'];
            $excluded = $folded['excluded'];
        }
        $names = array();
        foreach ($sources as $source) {
            $names[] = $source['name'];
        }
        return array(
            'excluded' => $excluded,
            'reporter_feeds' => $reporterFeeds,
            'facts' => array(
                'count' => count($sources),
                'names' => $names,
                'checked' => (int)($cached['feeds'] ?? 0)
                    + (int)($cached['servers'] ?? 0),
            ),
            'missing' => $anyCache
                ? null
                : __('No feed or server cache has been populated on'
                    . ' this instance, so external presence could not'
                    . ' be checked.'),
        );
    }

    /**
     * The organisations each cached feed hit publishes as, for
     * `feeds.reporters`.
     *
     * Three routes, because MISP records a feed's publisher three ways:
     * a freetext or CSV feed's `orgc_id`, the creator of its fixed
     * event, and — for a MISP feed, whose events keep their own
     * creator when fetched — the creator of the local copies of the
     * events the cache hit names. A freetext feed with neither an
     * `orgc_id` nor a fixed event creates its events as whoever pulled
     * it, which the row does not record, so it resolves to nobody.
     *
     * @param array $sources From `externalPresence`
     * @return array The same sources, each feed carrying `publishers`
     */
    private function feedPublishers(array $sources)
    {
        $feedIds = array();
        foreach ($sources as $source) {
            if (($source['scope'] ?? 'feed') === 'feed') {
                $feedIds[] = (int)$source['id'];
            }
        }
        if (empty($feedIds)) {
            return $sources;
        }
        $feeds = $this->model('Feed')->find('all', array(
            'recursive' => -1,
            'fields' => array('Feed.id', 'Feed.orgc_id',
                'Feed.fixed_event', 'Feed.event_id'),
            'conditions' => array('Feed.id' => $feedIds),
        ));
        $byFeed = array();
        $fixed = array();
        foreach ($feeds as $feed) {
            $id = (int)$feed['Feed']['id'];
            $byFeed[$id] = array();
            if (!empty($feed['Feed']['orgc_id'])) {
                $byFeed[$id][] = (int)$feed['Feed']['orgc_id'];
            }
            if (!empty($feed['Feed']['fixed_event'])
                && !empty($feed['Feed']['event_id'])
            ) {
                $fixed[(int)$feed['Feed']['event_id']][] = $id;
            }
        }
        $event = $this->model('Event');
        if (!empty($fixed)) {
            $rows = $event->find('list', array(
                'recursive' => -1,
                'fields' => array('Event.id', 'Event.orgc_id'),
                'conditions' => array('Event.id' => array_keys($fixed)),
            ));
            foreach ($rows as $eventId => $orgId) {
                foreach ($fixed[(int)$eventId] as $id) {
                    $byFeed[$id][] = (int)$orgId;
                }
            }
        }
        $uuids = array();
        foreach ($sources as $source) {
            foreach (array_slice($source['event_uuids'] ?? array(), 0,
                self::FEED_PUBLISHER_UUID_CAP) as $uuid
            ) {
                $uuids[(string)$uuid][] = (int)$source['id'];
            }
        }
        if (!empty($uuids)) {
            $rows = $event->find('list', array(
                'recursive' => -1,
                'fields' => array('Event.uuid', 'Event.orgc_id'),
                'conditions' => array(
                    'Event.uuid' => array_map('strval', array_keys($uuids)),
                ),
            ));
            foreach ($rows as $uuid => $orgId) {
                foreach ($uuids[(string)$uuid] ?? array() as $id) {
                    $byFeed[$id][] = (int)$orgId;
                }
            }
        }
        foreach ($sources as $i => $source) {
            if (($source['scope'] ?? 'feed') === 'feed') {
                $sources[$i]['publishers'] = array_values(array_unique(
                    $byFeed[(int)$source['id']] ?? array()
                ));
            }
        }
        return $sources;
    }

    /**
     * The sighting facts, windowed where the budget says so.
     *
     * The rows come from `Sighting::listSightings` through the same
     * path the Sightings tab uses, so the instance's sighting policy
     * and anonymisation are applied before anything is counted — which
     * is what makes §14.6's *every count is the viewer's* true of the
     * ledger too.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @param int $now
     * @param array $budget
     * @return array `facts` and `windowed`, the rows the window cut
     */
    private function verdictSightings(array $user, $value,
        array $options, $now, array $budget, $exclusions = null,
        array $plan = array()
    ) {
        $context = $this->sightingContext($user, $value, $options);
        $rows = $context['sightings'];
        /*
         * The self-sighting filter runs on the rows, before anything is
         * tallied, for the same reason the window below does: two
         * signals reading the sightings have to read the same set or
         * the ledger's own rows disagree about how many there are.
         */
        $selfExcluded = 0;
        $undecidable = 0;
        if ($exclusions !== null) {
            $filtered = $exclusions->applyToSightings(
                $rows,
                $context['sighted'],
                $plan
            );
            $rows = $filtered['rows'];
            $selfExcluded = $filtered['excluded'];
            $undecidable = $filtered['undecidable'];
        }
        /*
         * The relevance clock, folded here and not below, because it is
         * a whole-history aggregate by declaration and the window is
         * the one exclusion it does not see (`06-staleness.md` §3.3).
         * A windowed clock could not tell stale-since-91-days from
         * stale-since-three-years while `ttl_days` reaches 730 — and
         * this line's position in the method is the whole of that
         * property, so it sits between the two filters on purpose:
         * after `sightings.self`, before `evidence.window`.
         */
        $corroboration = ValueRelevanceTool::corroborationFrom(
            $rows,
            $context['sighted']
        );
        $windowed = 0;
        if (!empty($budget['window_days'])) {
            $cut = $now - (int)$budget['window_days'] * 86400;
            $kept = array();
            foreach ($rows as $row) {
                if ((int)$row['Sighting']['date_sighting'] >= $cut) {
                    $kept[] = $row;
                } else {
                    $windowed++;
                }
            }
            $rows = $kept;
        }
        $totals = ValueStatsTool::sightingTotals($rows);
        $signals = ValueStatsTool::sightingSignals(
            $rows,
            $now,
            self::VERDICT_RECENT_DAYS
        );
        /*
         * The same rows a third time, tallied by organisation id, which
         * is the only key a trust grade can land on (`07-reference.md`
         * §2.4). Folded off the rows already in hand rather than
         * queried: it is the same set the two tallies above read, so a
         * weighted count and an unweighted one cannot disagree about
         * how many sightings there are.
         */
        $attributed = ValueStatsTool::sightingsByOrg($rows);
        return array(
            'facts' => array(
                'total' => $totals['total'],
                'fp' => $totals['fp'],
                'expiration' => $totals['expiration'],
                'last_stamp' => $totals['last_stamp'],
                'fp_last_stamp' => $totals['last_fp_stamp'],
                'orgs' => $signals['orgs'],
                'fp_orgs' => $signals['fp_orgs'],
                'fp_org_names' => $signals['fp_org_names'],
                /*
                 * `id` and `name` together, so a signal weighting the
                 * filers can name the ones it weighted without pairing
                 * `fp_org_names` against an id list by position.
                 */
                'fp_org_list' => $this->orgPairs(
                    array_keys($attributed['by_org_fp']),
                    $attributed['names']
                ),
                'by_org' => $attributed['by_org'],
                'by_org_fp' => $attributed['by_org_fp'],
                'by_org_fp_last' => $attributed['by_org_fp_last'],
                'anonymous' => $attributed['anonymous'],
                'anonymous_fp' => $attributed['anonymous_fp'],
                'anonymous_fp_last' => $attributed['anonymous_fp_last'],
                'seen' => ValueStatsTool::seenFacts(
                    $rows,
                    $now,
                    self::VERDICT_RECENT_DAYS
                ),
                'recent' => $signals['recent'],
                'recent_days' => $signals['recent_days'],
                'first_stamp' => $signals['first_stamp'],
                /*
                 * The 90-day signed spark, folded off the rows the
                 * tallies above already read rather than fetched for
                 * the one caller that draws it. The hover card is that
                 * caller; the Overview's Sightings card builds the same
                 * array from its own rows through the same tool, so the
                 * two surfaces cannot draw one value two shapes.
                 *
                 * These are the windowed rows, deliberately: a spark
                 * wider than the evidence the assessment beside it
                 * scored would be a chart disagreeing with the number
                 * it sits under.
                 */
                'spark' => ValueStatsTool::sightingSpark(
                    $rows,
                    date('Y-m-d', $now)
                ),
            ),
            'corroboration' => $corroboration,
            'windowed' => $windowed,
            'excluded' => $selfExcluded,
            'undecidable' => $undecidable,
        );
    }

    /**
     * What the value's own occurrences are attributed to.
     *
     * `ownTagsFor` is the tightest reading MISP holds — not *an event
     * mentioning APT28 contained this address* but *this address, in
     * this event, is marked APT28* — and it answers with one grouped
     * query however many occurrences there are.
     *
     * Techniques are split from clusters by `GalaxyCategory`, which
     * already knows which galaxies are ATT&CK-shaped, and the
     * technique id is lifted out of the cluster name where it carries
     * one: a ledger row reading `T1071.001` is one an analyst can look
     * up, where the full cluster title is a sentence.
     *
     * **`clusters` is everything that is not ATT&CK-shaped**, which
     * is a wider set than the name suggests and the reason the profile
     * has a say here at all: a value tagged `sector:banking`,
     * `country:lu` and a `preventive-measure` puts three clusters in
     * it, and `attribution.galaxy` pays for all three under a signal
     * whose own absence row reads *"Nobody has attributed this value
     * to an actor, family or campaign"*. So the galaxies each cluster
     * came from are carried beside the counts, and the profile's
     * `galaxies.attribution` list — which is a scoring judgement and
     * not the card's display priority (D43) — says which of them name
     * a threat. A profile declaring none leaves `attribution` null and
     * the signal counts what it counts today.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @param array $budget
     * @param int $now
     * @param array|null $profile The profile in force, for the
     *                            eligibility list alone
     * @param array|null $events From verdictEvents(), when the caller
     *                           already has them
     * @return array
     */
    private function verdictGalaxies(array $user, $value,
        array $options, array $budget, $now, $profile = null,
        $events = null
    ) {
        $eligible = ValueLabelPriority::attribution($profile);
        if ($events === null) {
            $events = $this->verdictEvents($user, $value, $options,
                $budget, $now);
        }
        $clusters = array();
        $techniques = array();
        $types = array();
        if (empty($events)) {
            return array(
                'clusters' => $clusters,
                'techniques' => $techniques,
                'types' => $types,
                'attribution' => $eligible,
                'on_events' => array(),
                'on_flagged_events' => array(),
                'event_types' => array(),
            );
        }
        $tags = $this->model('Value')->ownTagsFor(
            $user,
            $value,
            array_keys($events),
            $options
        );
        foreach ($tags as $name => $tag) {
            if (empty($tag['tag']['is_galaxy'])) {
                continue;
            }
            $parsed = $this->galaxyTagParts($name);
            if ($parsed === null) {
                continue;
            }
            $occurrences = 0;
            foreach ($tag['events'] as $event) {
                $occurrences += (int)$event['occurrences'];
            }
            if (GalaxyCategory::isAttackPattern($parsed['type'])) {
                $key = $parsed['technique'] === null
                    ? $parsed['cluster']
                    : $parsed['technique'];
                $techniques[$key] = ($techniques[$key] ?? 0)
                    + $occurrences;
            } else {
                $key = $parsed['cluster'];
                $clusters[$key] = ($clusters[$key] ?? 0) + $occurrences;
                /*
                 * The galaxy a cluster came from, which the count
                 * above throws away: two galaxies naming the same
                 * cluster fold into one entry here, so the galaxies
                 * are carried as a set rather than as one answer.
                 * `attribution.galaxy` needs them to know what it may
                 * count, and the hover card needs them to know which
                 * of twenty-six clusters this reader asked for first.
                 */
                $types[$key][$parsed['type']] = true;
            }
        }
        foreach ($types as $key => $set) {
            $types[$key] = array_keys($set);
        }
        /*
         * Read when the occurrences carry nothing, for the absence
         * wording, or when the reporter flagged the value in any of
         * its events, for the event's discounted attribution. One `IN`
         * against `event_tags`' own index over the ids resolved above.
         */
        $flagged = array();
        foreach ($events as $id => $event) {
            if (!empty($event['flagged'])) {
                $flagged[] = (int)$id;
            }
        }
        $onEvents = array('clusters' => array(), 'types' => array(),
            'flagged' => array());
        if (empty($clusters) || !empty($flagged)) {
            $onEvents = $this->verdictEventGalaxies($user, $events,
                $flagged);
        }
        return array(
            'clusters' => $clusters,
            'techniques' => $techniques,
            'types' => $types,
            'attribution' => $eligible,
            'on_events' => $onEvents['clusters'],
            'on_flagged_events' => $onEvents['flagged'],
            'event_types' => $onEvents['types'],
        );
    }

    /**
     * The events this value occurs in, cut to the evidence window.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @param array $budget
     * @param int $now
     * @return array As Value::occurrenceEventsFor
     */
    private function verdictEvents(array $user, $value, array $options,
        array $budget, $now
    ) {
        $events = $this->model('Value')
            ->occurrenceEventsFor($user, $value, $options);
        if (!empty($budget['window_days'])) {
            $cut = $now - (int)$budget['window_days'] * 86400;
            foreach ($events as $id => $event) {
                if ((int)$event['last'] < $cut) {
                    unset($events[$id]);
                }
            }
        }
        return $events;
    }

    /**
     * What each reporter stated about its own claim: the confidence and
     * false-positive tags on the value's occurrences and on the events
     * carrying them, read by `ValueStatementTool`.
     *
     * The statement belongs to the event's creator, which is who put a
     * global tag on it. Local tags are left out at both levels — they
     * are this instance's notes on somebody else's report.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @param array $events From verdictEvents()
     * @return array `events`: event id => `org`, `last`, `flagged`,
     *               `attribute` and `event` (each `name`, `number`)
     */
    private function verdictStatements(array $user, $value,
        array $options, array $events
    ) {
        $empty = array('events' => array());
        if (empty($events)) {
            return $empty;
        }
        $tags = $this->statementTags();
        if (empty($tags)) {
            return $empty;
        }
        $eventIds = array_keys($events);
        $onOccurrences = $this->model('Value')->statementTagsFor($user,
            $value, $eventIds, array_keys($tags), $options);
        $onEvents = array();
        $rows = ClassRegistry::init('EventTag')->find('all', array(
            'fields' => array('EventTag.event_id', 'EventTag.tag_id'),
            'conditions' => array(
                'EventTag.event_id' => $eventIds,
                'EventTag.tag_id' => array_keys($tags),
                'EventTag.local' => 0,
            ),
            'recursive' => -1,
        ));
        foreach ($rows as $row) {
            $onEvents[(int)$row['EventTag']['event_id']][] =
                (int)$row['EventTag']['tag_id'];
        }
        $stated = array_values(array_unique(array_merge(
            array_keys($onOccurrences),
            array_keys($onEvents)
        )));
        if (empty($stated)) {
            return $empty;
        }
        $creators = ClassRegistry::init('Event')->find('list', array(
            'recursive' => -1,
            'fields' => array('Event.id', 'Event.orgc_id'),
            'conditions' => array('Event.id' => $stated),
        ));
        $resolve = function (array $ids) use ($tags) {
            $out = array();
            foreach (array_unique($ids) as $id) {
                if (isset($tags[$id])) {
                    $out[] = $tags[$id];
                }
            }
            return $out;
        };
        $out = array();
        foreach ($stated as $id) {
            $out[(int)$id] = array(
                'org' => (int)($creators[$id] ?? 0),
                'last' => (int)$events[$id]['last'],
                'flagged' => !empty($events[$id]['flagged']),
                'attribute' => $resolve($onOccurrences[$id] ?? array()),
                'event' => $resolve($onEvents[$id] ?? array()),
            );
        }
        return array('events' => $out);
    }

    /**
     * The statement tags this instance holds, with their numbers.
     *
     * The tag's own `numerical_value` where it overrides its taxonomy,
     * as MISP lets it, and the taxonomy entry's otherwise — the tag
     * rows' copy is not kept filled.
     *
     * @return array tag id => `name`, `number`
     */
    private function statementTags()
    {
        $or = array();
        foreach (ValueStatementTool::predicates() as $predicate) {
            $or[] = array('Tag.name LIKE' => $predicate . '=%');
        }
        $rows = ClassRegistry::init('Tag')->find('all', array(
            'recursive' => -1,
            'fields' => array('Tag.id', 'Tag.name', 'Tag.numerical_value'),
            'conditions' => array('OR' => $or),
        ));
        if (empty($rows)) {
            return array();
        }
        $numbers = $this->taxonomyNumbers();
        $tags = array();
        foreach ($rows as $row) {
            $name = $row['Tag']['name'];
            $parsed = ValueStatementTool::parse($name);
            $number = $row['Tag']['numerical_value'];
            if ($number === null && $parsed !== null) {
                $number = $numbers[$parsed['tag']] ?? null;
            }
            $tags[(int)$row['Tag']['id']] = array(
                'name' => $name,
                'number' => $number === null ? null : (int)$number,
            );
        }
        return $tags;
    }

    /**
     * The statement taxonomies' entry numbers, keyed the way
     * `ValueStatementTool::parse()` writes a tag.
     *
     * @return array
     */
    private function taxonomyNumbers()
    {
        $namespaces = array();
        foreach (ValueStatementTool::predicates() as $predicate) {
            $namespaces[] = explode(':', $predicate, 2)[0];
        }
        $rows = ClassRegistry::init('TaxonomyEntry')->find('all', array(
            'recursive' => -1,
            'fields' => array(
                'Taxonomy.namespace',
                'TaxonomyPredicate.value',
                'TaxonomyEntry.value',
                'TaxonomyEntry.numerical_value',
            ),
            'joins' => array(
                array(
                    'table' => 'taxonomy_predicates',
                    'alias' => 'TaxonomyPredicate',
                    'type' => 'INNER',
                    'conditions' => array('TaxonomyPredicate.id'
                        . ' = TaxonomyEntry.taxonomy_predicate_id'),
                ),
                array(
                    'table' => 'taxonomies',
                    'alias' => 'Taxonomy',
                    'type' => 'INNER',
                    'conditions' => array(
                        'Taxonomy.id = TaxonomyPredicate.taxonomy_id',
                    ),
                ),
            ),
            'conditions' => array(
                'Taxonomy.namespace' => array_values(
                    array_unique($namespaces)
                ),
                'TaxonomyEntry.numerical_value IS NOT NULL',
            ),
        ));
        $numbers = array();
        foreach ($rows as $row) {
            $key = $row['Taxonomy']['namespace'] . ':'
                . $row['TaxonomyPredicate']['value'] . '="'
                . $row['TaxonomyEntry']['value'] . '"';
            $numbers[$key] =
                (int)$row['TaxonomyEntry']['numerical_value'];
        }
        return $numbers;
    }

    /**
     * The clusters named by the events this value occurs in, which are
     * **not** an attribution of the value.
     *
     * A reader who has just seen *APT29* on the Overview's context card
     * and reads *"no galaxy on any occurrence"* two panels away is
     * being told two true things that sound like a contradiction. They
     * are not: the event tag says *this report is about APT29*, the
     * occurrence tag would say *this indicator is APT29's*, and only
     * the second is an attribution. `Value::ownTagsFor`'s docblock
     * draws the same line, with the same example.
     *
     * The distinction is worth keeping rather than softening. A report
     * on an actor cites sandbox artefacts, public infrastructure the
     * malware touched and services it abused — `8.8.8.8` reaches an
     * APT29 event because something resolved a name, not because APT29
     * runs it. Counting event tags as attribution would pay every
     * indicator in that report for one analyst's judgement about the
     * report, which is how a verdict engine ends up calling Google's
     * resolver an actor's asset.
     *
     * So the event tag alone pays nothing; it lets the ledger *say* the
     * events are labelled. **The one exception is the event's
     * attribution**: an event in which the reporter flagged this
     * value `to_ids = 1` — this value,
     * in this report, is an indicator of the report's threat — and
     * `flagged` counts those events per cluster for
     * `attribution.galaxy` to pay at its own discount. `8.8.8.8` in an
     * APT29 report is context and is not flagged.
     *
     * **The cluster ACL still applies.** A galaxy tag names a cluster
     * the reader may not be allowed to know exists, so the names go
     * through `galaxyClusters()` exactly as the context card's do, and
     * a tag with no row behind it is dropped rather than counted. The
     * events themselves need no test: they came from
     * `occurrenceEventsFor`, so each one holds an occurrence this
     * reader may already see — `taggableEventIdsFor` makes the same
     * argument for the context card.
     *
     * ATT&CK-shaped clusters are dropped on `verdictGalaxies`' own
     * rule: a technique on the carrying event is not a near-miss
     * attribution, and counting one would put *T1071.001* behind a
     * sentence about actors, families and campaigns.
     *
     * @param array $user
     * @param array $events The windowed event set, keyed by id
     * @param array $flaggedIds The ids among them in which the value
     *                          has a `to_ids = 1` occurrence
     * @return array `clusters` (name => events), `flagged` (name =>
     *               flagged events) and `types` (name => galaxy types),
     *               the shape `AttributionGalaxy::eligible()` reads
     */
    private function verdictEventGalaxies(array $user, array $events,
        array $flaggedIds = array()
    ) {
        $empty = array('clusters' => array(), 'types' => array(),
            'flagged' => array());
        if (empty($events)) {
            return $empty;
        }
        $flaggedIds = array_map('intval', $flaggedIds);
        $flaggedCount = empty($flaggedIds)
            ? 'SUM(0) AS flagged'
            : 'COUNT(DISTINCT CASE WHEN EventTag.event_id IN ('
                . implode(',', $flaggedIds)
                . ') THEN EventTag.event_id END) AS flagged';
        $rows = ClassRegistry::init('EventTag')->find('all', array(
            'fields' => array(
                'Tag.name',
                'COUNT(DISTINCT EventTag.event_id) AS events',
                $flaggedCount,
            ),
            'conditions' => array(
                'EventTag.event_id' => array_keys($events),
                'Tag.is_galaxy' => 1,
            ),
            'recursive' => -1,
            'joins' => array(
                array(
                    'table' => 'tags',
                    'alias' => 'Tag',
                    'type' => 'INNER',
                    'conditions' => array('Tag.id = EventTag.tag_id'),
                ),
            ),
            'group' => array('Tag.name'),
        ));
        if (empty($rows)) {
            return $empty;
        }
        $tags = array();
        foreach ($rows as $row) {
            $tags[$row['Tag']['name']] = array(
                'tag' => array('is_galaxy' => true),
                'count' => (int)$row[0]['events'],
                'flagged' => (int)$row[0]['flagged'],
            );
        }
        $permitted = $this->galaxyClusters($user, $tags);
        $clusters = array();
        $flagged = array();
        $types = array();
        foreach ($tags as $name => $tag) {
            if (!isset($permitted[$name])) {
                continue;
            }
            $parsed = $this->galaxyTagParts($name);
            if ($parsed === null
                || GalaxyCategory::isAttackPattern($parsed['type'])
            ) {
                continue;
            }
            $key = $parsed['cluster'];
            $clusters[$key] = ($clusters[$key] ?? 0) + $tag['count'];
            if ($tag['flagged'] > 0) {
                $flagged[$key] = ($flagged[$key] ?? 0) + $tag['flagged'];
            }
            $types[$key][$parsed['type']] = true;
        }
        foreach ($types as $key => $set) {
            $types[$key] = array_keys($set);
        }
        return array('clusters' => $clusters, 'types' => $types,
            'flagged' => $flagged);
    }

    /**
     * A galaxy tag pulled apart: `misp-galaxy:threat-actor="Sofacy"`
     * into its galaxy type and its cluster, plus the ATT&CK id where
     * the cluster name carries one.
     *
     * @param string $name
     * @return array|null Null when the tag is not galaxy-shaped
     */
    private function galaxyTagParts($name)
    {
        if (!preg_match(
            '/^misp-galaxy:([^=]+)="?(.*?)"?$/',
            (string)$name,
            $parts
        )) {
            return null;
        }
        $cluster = $parts[2];
        $technique = null;
        if (preg_match('/\bT\d{4}(?:\.\d{3})?\b/', $cluster, $id)) {
            $technique = $id[0];
        }
        return array(
            'type' => $parts[1],
            'cluster' => $cluster,
            'technique' => $technique,
        );
    }

    /**
     * One `parameters` section of the profile in force, whichever
     * shape it arrived in — the model decodes `parameters` on find,
     * and a caller may hand over the parameters alone.
     *
     * @param array|null $profile
     * @param string $name
     * @return array
     */
    private function verdictSection($profile, $name)
    {
        if (!is_array($profile)) {
            return array();
        }
        if (isset($profile['parameters'][$name])
            && is_array($profile['parameters'][$name])
        ) {
            return $profile['parameters'][$name];
        }
        if (isset($profile[$name]) && is_array($profile[$name])) {
            return $profile[$name];
        }
        return array();
    }
}
