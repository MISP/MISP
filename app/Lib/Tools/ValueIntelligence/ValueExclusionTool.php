<?php

/**
 * Evidence the analyst has decided not to count.
 *
 * The `exclusions` section of a profile: filters that run over a value's
 * evidence **before any signal sees it**, so that two signals reading
 * the same fact read the same filtered set. A ledger whose sightings
 * row says 47 next to a false-positive row computed from 44 is a ledger
 * a reader summing it by hand would be right to complain about.
 *
 * ## Three mechanisms, because the evidence has two classes
 *
 * *"Applied to `$context`, once"* reads as one mechanism and is three
 * different things — because half a value's evidence is computed in
 * SQL and never exists as rows at all.
 *
 * - **A condition** (`orgs.own`). The occurrence tally, the reporting
 *   breadth, the publication split and the monthly activity are
 *   `COUNT DISTINCT` aggregates over the attribute table. Excluding an
 *   organisation from them means excluding it *in the query*, or the
 *   ledger contradicts itself: reporting breadth would drop an
 *   organisation while the occurrence count still included its rows.
 *   So this class of exclusion contributes to `Value::conditionsFor()`,
 *   which is the single place every value-scoped aggregate builds its
 *   predicate, and it therefore reaches all of them at once.
 * - **A row filter** (`sightings.self`). Sighting rows do exist, and
 *   are filtered where they exist — before they are tallied, exactly
 *   as the evidence window already filters them.
 * - **A list fold** (`feeds.reporters`, `feeds.mirrored`). One
 *   already-fetched list, deduplicated.
 *
 * What the three share is the property that matters: every signal
 * sees the same evidence, because the filtering happens once, during
 * the build, and nothing downstream can opt out.
 *
 * ## `evidence.window` is not here
 *
 * It is an exclusion, it is in the section, and it is applied by the
 * context builder's budget instead — because it decides what is
 * *fetched*, and the others filter what arrived. It also filters row
 * evidence only, where these filter whatever they are pointed at. Its
 * `not_counted` entry comes from the accumulator's budget notes, in the
 * same shape as the ones this file produces.
 *
 * ## No class per id, and no drop-in directory
 *
 * Signals and conflict rules resolve to discovered classes because an
 * instance admin may want ones nobody shipped. An exclusion is
 * configuration the engine applies directly: the five shipped ids
 * operate at three different layers and could not honestly share an
 * interface — one contributes SQL, one filters rows, one folds a list.
 * A custom exclusion would need the expression language the design
 * rejected, so the set is closed and the methods below are it.
 */
class ValueExclusionTool
{
    /** The five ids a v1 profile may carry. */
    const SIGHTINGS_SELF = 'sightings.self';
    const FEEDS_MIRRORED = 'feeds.mirrored';
    const FEEDS_REPORTERS = 'feeds.reporters';
    const ORGS_OWN = 'orgs.own';
    const EVIDENCE_WINDOW = 'evidence.window';

    /** Hours after an occurrence's own timestamp that a sighting from
     *  its author counts as self-confirmation rather than as news. */
    const DEFAULT_WITHIN_HOURS = 1;

    /**
     * What each layer means to somebody reading the pane.
     *
     * The layer is a real distinction and the editor has to show it —
     * `orgs.own` moving every aggregate at once is exactly the thing an
     * analyst is surprised by — but `row_filter` is the name the code
     * calls it, not an answer to *what does this touch*. Declared here
     * beside the layer each rule is assigned, for the same reason the
     * schemas are: a vocabulary kept in the view drifts from the code
     * that uses it the first time a rule moves layer.
     *
     * @return array layer => label and the sentence behind it
     */
    public static function layers()
    {
        return array(
            'condition' => array(
                'label' => __('every count'),
                'title' => __(
                    'Excluded in the query itself, so every aggregate'
                    . ' on the value moves at once rather than one'
                    . ' list being filtered afterwards.'
                ),
            ),
            'row_filter' => array(
                'label' => __('rows'),
                'title' => __(
                    'Rows are left out where they exist, before'
                    . ' anything tallies them.'
                ),
            ),
            'list_fold' => array(
                'label' => __('one list'),
                'title' => __(
                    'One already-fetched list, deduplicated. Nothing'
                    . ' else on the value changes.'
                ),
            ),
            'budget' => array(
                'label' => __('what is fetched'),
                'title' => __(
                    'Decides what is read at all, rather than'
                    . ' filtering what arrived. Whole-history'
                    . ' aggregates are never windowed.'
                ),
            ),
        );
    }

    /**
     * The five ids described, so the editor can render a form for a
     * section that has no directory to read.
     *
     * Signals and conflict rules declare their own schemas on their own
     * classes; an exclusion has no class, because the five operate at
     * three different layers and could not honestly share an interface
     * (see the class docblock). That leaves the editor with a choice
     * between a hardcoded list of its own and a declaration here, and
     * the declaration belongs beside the code that applies it — the
     * same argument that put `points_schema` on the signal rather than
     * in the form. A list in the view would drift from `entries()` the
     * first time a parameter changed, silently, because a form that
     * offers the wrong key writes a key nothing reads.
     *
     * `layer` is not decoration: it is why `orgs.own` changes the
     * numbers a signal sees rather than filtering its output, and the
     * simulator needs to know that two profiles differing here are two
     * different contexts rather than two scorings.
     *
     * `help` feeds the editor's "How it works" popover, in the shape of
     * `ValueSignalBase::$help` minus `name`, which is the `title`.
     *
     * @return array id => declaration
     */
    public static function catalogue()
    {
        return array(
            self::SIGHTINGS_SELF => array(
                'id' => self::SIGHTINGS_SELF,
                'title' => __('Self-sightings'),
                'layer' => 'row_filter',
                'description' => __(
                    'Leaves out the sightings an organisation files on its'
                    . ' own report soon after it, so agreeing with itself'
                    . ' does not count as corroboration.'
                ),
                'schema' => array(
                    'within_hours' => array(
                        'type' => 'float',
                        'default' => self::DEFAULT_WITHIN_HOURS,
                        'min' => 0,
                        'label' => __('Hours after the occurrence'),
                    ),
                ),
                'help' => array(
                    'what' => __(
                        'Sightings filed by the organisation whose event'
                        . ' holds the occurrence. Right after its report,'
                        . ' that is the organisation agreeing with itself;'
                        . ' weeks later, "we still see this" is news, and'
                        . ' is kept.'
                    ),
                    'how' => __(
                        'A sighting from the reporting organisation within'
                        . ' {within_hours} hours of the occurrence is left'
                        . ' out before any signal counts sightings.'
                    ),
                    'note' => __(
                        'The occurrence\'s time is its last change, as MISP'
                        . ' keeps no creation time on an attribute, so an'
                        . ' edited one can let a self-sighting through. A'
                        . ' sighting whose organisation is hidden from you'
                        . ' cannot be checked, and is kept.'
                    ),
                    'settings' => array(
                        'within_hours' => __(
                            'How long after the occurrence its reporter\'s'
                            . ' own sightings are left out. 168 is a week.'
                        ),
                    ),
                    'recipes' => array(
                        array(
                            'want' => __('Count an organisation\'s'
                                . ' sightings of its own report like any'
                                . ' other'),
                            'do' => __('Untick Self-sightings.'),
                        ),
                        array(
                            'want' => __('Leave them out for the whole'
                                . ' first week'),
                            'do' => __('Set within_hours to 168.'),
                        ),
                    ),
                ),
            ),
            self::FEEDS_MIRRORED => array(
                'id' => self::FEEDS_MIRRORED,
                'title' => __('Mirrored feeds'),
                'layer' => 'list_fold',
                'description' => __(
                    'Counts feeds that share a provider once, so one'
                    . ' source mirrored several times is not counted as'
                    . ' several.'
                ),
                'schema' => array(
                    'dedupe_by' => array(
                        'type' => 'string',
                        'default' => 'provider',
                        'label' => __('Fold feeds sharing this'),
                        'options' => array('provider', 'url'),
                    ),
                ),
                'help' => array(
                    'what' => __(
                        'The feeds that carry the value, which'
                        . ' lifecycle.feeds counts. Several feeds often'
                        . ' mirror one upstream source; counted'
                        . ' separately, one source looks like independent'
                        . ' corroboration.'
                    ),
                    'how' => __(
                        'Feeds sharing the same {dedupe_by} are counted'
                        . ' once. A feed without one stands alone, and'
                        . ' other MISP servers are never folded.'
                    ),
                    'note' => __(
                        'MISP does not record what a feed mirrors, so this'
                        . ' folds by a field instead: by provider it is'
                        . ' wrong where one provider runs unrelated feeds.'
                    ),
                    'settings' => array(
                        'dedupe_by' => __(
                            'provider folds every feed from one provider;'
                            . ' url folds only feeds fetched from the same'
                            . ' address.'
                        ),
                    ),
                    'recipes' => array(
                        array(
                            'want' => __('Count every feed separately'),
                            'do' => __('Untick Mirrored feeds.'),
                        ),
                        array(
                            'want' => __('Fold only exact duplicates, not'
                                . ' every feed of one provider'),
                            'do' => __('Set dedupe_by to url.'),
                        ),
                    ),
                ),
            ),
            self::FEEDS_REPORTERS => array(
                'id' => self::FEEDS_REPORTERS,
                'title' => __('Feeds from a reporter'),
                'layer' => 'list_fold',
                'description' => __(
                    'Leaves out a feed published by an organisation that'
                    . ' already reports the value, so that organisation is'
                    . ' not counted twice.'
                ),
                'schema' => array(),
                'help' => array(
                    'what' => __(
                        'A feed whose publisher also reports the value in'
                        . ' an event here. The feed is that organisation\'s'
                        . ' report again: counted, it would add to'
                        . ' lifecycle.feeds as well as to the reporting'
                        . ' organisations.'
                    ),
                    'how' => __(
                        'A feed is matched to its publisher by its creator'
                        . ' organisation, its fixed event, or the local'
                        . ' copies of the events it carries. A matched feed'
                        . ' leaves the feed count; the organisation still'
                        . ' counts as a reporter.'
                    ),
                    'note' => __(
                        'A feed whose publisher cannot be told is kept: a'
                        . ' fold that guesses would remove evidence.'
                    ),
                    'recipes' => array(
                        array(
                            'want' => __('Count a reporter\'s own feed as'
                                . ' outside corroboration too'),
                            'do' => __('Untick Feeds from a reporter.'),
                        ),
                    ),
                ),
            ),
            self::ORGS_OWN => array(
                'id' => self::ORGS_OWN,
                'title' => __('Your own organisation'),
                'layer' => 'condition',
                'description' => __(
                    'Leaves your own organisation out of every count, so'
                    . ' the assessment says what everyone else reports.'
                ),
                'schema' => array(),
                'help' => array(
                    'what' => __(
                        'What your organisation contributed: the'
                        . ' occurrences in events it created, and the'
                        . ' sightings filed against them. Useful when you'
                        . ' mostly report what you already detect, and want'
                        . ' to know what the others add.'
                    ),
                    'how' => __(
                        'Left out in the query itself, so every count on'
                        . ' the value moves at once: occurrences, reporting'
                        . ' organisations, the published share, activity'
                        . ' over time.'
                    ),
                    'note' => __(
                        '"Your organisation" is the reader\'s: a shared'
                        . ' profile leaves out a different one for each'
                        . ' person. A value only your organisation reports'
                        . ' has nothing left, and reads as having no'
                        . ' record.'
                    ),
                    'recipes' => array(
                        array(
                            'want' => __('See what everyone else says'
                                . ' about a value you report'),
                            'do' => __('Tick Your own organisation, and'
                                . ' put the value on the bench.'),
                        ),
                    ),
                ),
            ),
            self::EVIDENCE_WINDOW => array(
                'id' => self::EVIDENCE_WINDOW,
                'title' => __('Evidence window'),
                'layer' => 'budget',
                'description' => __(
                    'On a very large value, reads row by row evidence from'
                    . ' the last days only, to keep the page fast. Counts'
                    . ' over the whole history are never cut.'
                ),
                'help' => array(
                    'what' => __(
                        'Values seen tens of thousands of times, such as'
                        . ' popular domains and resolvers, would have every'
                        . ' sighting and every event holding them read.'
                        . ' This bounds that work. It is a'
                        . ' performance budget, not a judgement about old'
                        . ' evidence.'
                    ),
                    'how' => __(
                        'On a value with at least {min_occurrences}'
                        . ' occurrences, only the sightings and events of'
                        . ' the last {days} days are read, so the sighting,'
                        . ' tag and galaxy signals see that window.'
                    ),
                    'note' => __(
                        'Occurrences, reporting organisations, feeds and'
                        . ' how recent the value is are counted over its'
                        . ' whole history, window or not.'
                    ),
                    'settings' => array(
                        'days' => __(
                            'How far back row evidence is read on a large'
                            . ' value.'
                        ),
                        'min_occurrences' => __(
                            'How many occurrences make a value large. 0'
                            . ' windows every value.'
                        ),
                    ),
                    'recipes' => array(
                        array(
                            'want' => __('Read the last year on large'
                                . ' values'),
                            'do' => __('Set days to 365.'),
                        ),
                        array(
                            'want' => __('Window only the very largest'
                                . ' values'),
                            'do' => __('Raise min_occurrences, e.g. to'
                                . ' 50000.'),
                        ),
                        array(
                            'want' => __('Always read the whole history'),
                            'do' => __('Untick Evidence window. On a large'
                                . ' instance the value page can then be'
                                . ' slow.'),
                        ),
                    ),
                ),
                'schema' => array(
                    'days' => array(
                        'type' => 'int',
                        'default' => 90,
                        'min' => 1,
                        'label' => __('Days of row evidence'),
                    ),
                    'min_occurrences' => array(
                        'type' => 'int',
                        'default' => 10000,
                        'min' => 0,
                        'label' => __('Occurrences before it applies'),
                    ),
                ),
            ),
        );
    }

    /**
     * What the profile in force asks to be left out, resolved against
     * this viewer.
     *
     * Built once and handed around, so that the decision *whether* a
     * rule applies is made in one place and the three application
     * points only ever ask what it decided.
     *
     * @param array|null $profile An `AnalystProfile` row, unwrapped
     * @param array $user The viewer, for `orgs.own`
     * @return array
     */
    public function planFor($profile, array $user)
    {
        $rules = array();
        foreach ($this->entries($profile) as $entry) {
            $rules[$entry['id']] = $entry;
        }
        $excludeOrgs = array();
        if (isset($rules[self::ORGS_OWN]) && !empty($user['org_id'])) {
            $excludeOrgs[] = (int)$user['org_id'];
        }
        return array(
            'rules' => $rules,
            'exclude_orgs' => $excludeOrgs,
            'org_name' => isset($user['Organisation']['name'])
                ? $user['Organisation']['name']
                : null,
        );
    }

    /**
     * The `$options` additions that carry a plan into the query layer.
     *
     * Merged into whatever options an aggregate was going to be called
     * with, so `orgs.own` needs no caller to know it exists.
     *
     * @param array $plan
     * @return array
     */
    public function conditionOptions(array $plan)
    {
        if (empty($plan['exclude_orgs'])) {
            return array();
        }
        return array('exclude_orgs' => $plan['exclude_orgs']);
    }

    /**
     * `sightings.self` — an organisation confirming its own fresh
     * report is not corroboration.
     *
     * **The window is the whole rule.** A self-sighting a year after
     * the report is real information — *we still see this* — so a
     * blanket "never count the author's sightings" would throw away the
     * one thing an author is best placed to say. Inside
     * `within_hours` of the occurrence's own timestamp it is the author
     * agreeing with themselves.
     *
     * Two imprecisions, both stated rather than papered over:
     *
     * - **The occurrence's timestamp is its last change, not its
     *   creation.** MISP keeps no created column on an attribute, so an
     *   attribute edited later has a timestamp later than the report
     *   it describes, and a self-sighting filed in between stops
     *   looking self-adjacent. The error is in the safe direction — it
     *   counts a sighting that might not deserve it, rather than
     *   discarding one that does.
     * - **An anonymised sighting cannot be tested.** Under a
     *   restrictive sighting policy the org is stripped from the row,
     *   and a rule that treated a missing org as *not the author*
     *   would silently apply to a subset. Those rows are kept and
     *   counted, so the note can say how many the rule could not
     *   decide about.
     *
     * @param array $rows From `Sighting::listSightings`
     * @param array $occurrences Attribute id => occurrence, from
     *                           `Value::sightedOccurrenceIdsFor`
     * @param array $plan
     * @return array `rows`, `excluded`, `undecidable`
     */
    public function applyToSightings(array $rows, array $occurrences,
        array $plan
    ) {
        if (!isset($plan['rules'][self::SIGHTINGS_SELF])) {
            return array('rows' => $rows, 'excluded' => 0,
                'undecidable' => 0);
        }
        $entry = $plan['rules'][self::SIGHTINGS_SELF];
        $window = (isset($entry['within_hours'])
            && is_numeric($entry['within_hours'])
            ? (float)$entry['within_hours']
            : self::DEFAULT_WITHIN_HOURS) * 3600;
        $kept = array();
        $excluded = 0;
        $undecidable = 0;
        foreach ($rows as $row) {
            $orgId = (int)($row['Sighting']['org_id'] ?? 0);
            if ($orgId === 0) {
                $undecidable++;
                $kept[] = $row;
                continue;
            }
            $author = $this->authorOf($row, $occurrences);
            if ($author === null) {
                $undecidable++;
                $kept[] = $row;
                continue;
            }
            $age = (int)($row['Sighting']['date_sighting'] ?? 0)
                - $author['at'];
            if ($orgId === $author['org_id'] && $age >= 0
                && $age <= $window
            ) {
                $excluded++;
                continue;
            }
            $kept[] = $row;
        }
        return array('rows' => $kept, 'excluded' => $excluded,
            'undecidable' => $undecidable);
    }

    /**
     * Who filed the occurrence a sighting is attached to, and when.
     *
     * The occurrence map is **flat** — `Value::sightedOccurrenceIdsFor`
     * folds each row into `id => array('timestamp', 'orgc_id', …)`
     * rather than handing back CakePHP's nested result. Reading it as
     * though it were nested finds nothing, and finding nothing here is
     * indistinguishable from a value with no self-sightings: the rule
     * declares every row undecidable and excludes none of them, which
     * looks exactly like the rule correctly having nothing to do.
     *
     * @param array $row
     * @param array $occurrences
     * @return array|null `org_id` and `at`, or null when unknowable
     */
    private function authorOf(array $row, array $occurrences)
    {
        $id = (int)($row['Sighting']['attribute_id'] ?? 0);
        if ($id === 0 || !isset($occurrences[$id])) {
            return null;
        }
        $occurrence = $occurrences[$id];
        $orgId = (int)($occurrence['orgc_id'] ?? 0);
        $at = (int)($occurrence['timestamp'] ?? 0);
        if ($orgId === 0 || $at === 0) {
            return null;
        }
        return array('org_id' => $orgId, 'at' => $at);
    }

    /**
     * `feeds.reporters` — a feed is not a second voice for its own
     * publisher.
     *
     * A feed both cached and fetched into local events would count
     * once as a reporting organisation, through the events' creator,
     * and again in `lifecycle.feeds`. `publishers` is resolved by the
     * caller; a feed whose publisher it could not resolve is kept,
     * since a fold that guesses removes evidence.
     *
     * @param array $sources From `externalPresence`, each feed carrying
     *                       `publishers` (organisation ids)
     * @param array $reporters The value's reporting organisation ids
     * @param array $plan
     * @return array `sources`, `excluded` and `names`
     */
    public function applyToReporters(array $sources, array $reporters,
        array $plan
    ) {
        if (!isset($plan['rules'][self::FEEDS_REPORTERS])
            || empty($reporters)
        ) {
            return array('sources' => $sources, 'excluded' => 0,
                'names' => array());
        }
        $reporters = array_flip(array_map('intval', $reporters));
        $kept = array();
        $names = array();
        foreach ($sources as $source) {
            $own = false;
            if (($source['scope'] ?? 'feed') === 'feed') {
                foreach ($source['publishers'] ?? array() as $orgId) {
                    if (isset($reporters[(int)$orgId])) {
                        $own = true;
                        break;
                    }
                }
            }
            if ($own) {
                $names[] = $source['name'] ?? '';
            } else {
                $kept[] = $source;
            }
        }
        return array('sources' => $kept, 'excluded' => count($names),
            'names' => $names);
    }

    /**
     * `feeds.mirrored` — feeds carrying the same upstream content
     * counted once.
     *
     * Three feeds mirroring one OSINT source are one piece of external
     * corroboration, not three, and counting them separately is the
     * cheapest way for a value's signal strength to look better than its
     * evidence.
     *
     * **MISP does not record what a feed mirrors.** The `feeds` table
     * has `provider`, `url` and `source_format` and nothing that says
     * *this derives from ORG-A's OSINT feed*, so the dedupe key is the
     * provider: cheap, and wrong in the specific case of one provider
     * running genuinely unrelated feeds. A feed naming no provider
     * folds under its own name, so it is never merged with anything.
     * The note says which key was used, because implying an exactness
     * that is not there is worse than the imprecision.
     *
     * @param array $sources From `externalPresence`
     * @param array $plan
     * @return array `sources` and `excluded`
     */
    public function applyToSources(array $sources, array $plan)
    {
        if (!isset($plan['rules'][self::FEEDS_MIRRORED])) {
            return array('sources' => $sources, 'excluded' => 0);
        }
        $entry = $plan['rules'][self::FEEDS_MIRRORED];
        $by = !empty($entry['dedupe_by']) && is_string($entry['dedupe_by'])
            ? $entry['dedupe_by']
            : 'provider';
        $seen = array();
        $kept = array();
        $excluded = 0;
        foreach ($sources as $source) {
            /*
             * A MISP server is not a feed and does not mirror one; it
             * is another instance's own holding of the value, and
             * folding two servers together because they share a
             * provider string would discard a genuine second opinion.
             */
            if (($source['scope'] ?? 'feed') !== 'feed') {
                $kept[] = $source;
                continue;
            }
            $key = !empty($source[$by])
                ? $by . ':' . $source[$by]
                : 'name:' . ($source['name'] ?? count($kept));
            if (isset($seen[$key])) {
                $excluded++;
                continue;
            }
            $seen[$key] = true;
            $kept[] = $source;
        }
        return array('sources' => $kept, 'excluded' => $excluded);
    }

    /**
     * The `not_counted` entries for what the profile left out.
     *
     * One per rule that actually removed something. A rule that is
     * enabled and excluded nothing says nothing — the block answers
     * *"why doesn't this count?"*, and a list of rules that did not
     * apply is noise in front of the ones that did.
     *
     * @param array $plan
     * @param array $tallies `sightings`, `sightings_undecidable`,
     *                       `sources`, `reporter_feeds` (names), from
     *                       the application above
     * @return array
     */
    public function notes(array $plan, array $tallies)
    {
        $notes = array();
        $excluded = (int)($tallies['sightings'] ?? 0);
        $undecidable = (int)($tallies['sightings_undecidable'] ?? 0);
        if ($excluded > 0) {
            $entry = $plan['rules'][self::SIGHTINGS_SELF];
            $hours = isset($entry['within_hours'])
                ? (float)$entry['within_hours']
                : self::DEFAULT_WITHIN_HOURS;
            $note = sprintf(
                __('%1$d %2$s from the organisation that reported the'
                    . ' occurrence, within %3$s of it. An organisation'
                    . ' confirming its own fresh report is not'
                    . ' corroboration.'),
                $excluded,
                $excluded === 1
                    ? __('sighting')
                    : __('sightings'),
                $this->hoursPhrase($hours)
            );
            if ($undecidable > 0) {
                $note .= ' ' . sprintf(
                    __('%d more could not be checked, because this'
                        . ' instance does not name the organisation'
                        . ' that filed them.'),
                    $undecidable
                );
            }
            $notes[] = $this->note(
                self::SIGHTINGS_SELF,
                __('Self-sightings'),
                $note
            );
        }
        $own = isset($tallies['reporter_feeds'])
            && is_array($tallies['reporter_feeds'])
            ? array_values(array_filter($tallies['reporter_feeds']))
            : array();
        if (!empty($own)) {
            $notes[] = $this->note(
                self::FEEDS_REPORTERS,
                __('Feeds from a reporter'),
                sprintf(
                    __('%1$s %2$s published by an organisation that'
                        . ' already reports this value, so %3$s'
                        . ' counted with its report rather than again'
                        . ' as a feed.'),
                    implode(', ', array_slice($own, 0, 4)),
                    count($own) === 1 ? __('is') : __('are'),
                    count($own) === 1 ? __('it is') : __('they are')
                )
            );
        }
        $sources = (int)($tallies['sources'] ?? 0);
        if ($sources > 0) {
            $entry = $plan['rules'][self::FEEDS_MIRRORED];
            $notes[] = $this->note(
                self::FEEDS_MIRRORED,
                __('Mirrored feeds'),
                sprintf(
                    __('%1$d %2$s sharing another\'s %3$s counted once'
                        . ' rather than separately. MISP does not'
                        . ' record what a feed mirrors, so this folds'
                        . ' by %3$s — which is wrong where one'
                        . ' %3$s runs unrelated feeds.'),
                    $sources,
                    $sources === 1 ? __('feed') : __('feeds'),
                    !empty($entry['dedupe_by'])
                        ? $entry['dedupe_by']
                        : 'provider'
                )
            );
        }
        if (!empty($plan['exclude_orgs'])) {
            $notes[] = $this->note(
                self::ORGS_OWN,
                __('Your own organisation'),
                sprintf(
                    __('Occurrences and sightings from %s are left out'
                        . ' of every count, so the assessment says'
                        . ' what everyone else reports.'),
                    empty($plan['org_name'])
                        ? __('your organisation')
                        : $plan['org_name']
                )
            );
        }
        return $notes;
    }

    /**
     * One entry, in the shape the accumulator's own `not_counted`
     * entries use.
     *
     * `reason` is the render-level grouping and `policy` is what makes
     * a row actionable: it is the analyst's decision, so it is the one
     * kind of entry that can carry a link to the profile that made it.
     *
     * @param string $id
     * @param string $title
     * @param string $note
     * @return array
     */
    private function note($id, $title, $note)
    {
        return array(
            'title' => $title,
            'note' => $note,
            'reason' => 'policy',
            'kind' => 'policy',
            'source' => 'exclusion',
            'id' => $id,
        );
    }

    /**
     * A window as a sentence, so the note states the rule rather than
     * a number of hours nobody set.
     *
     * @param float $hours
     * @return string
     */
    private function hoursPhrase($hours)
    {
        if ($hours < 1) {
            return sprintf(
                __('%d minutes'),
                (int)round($hours * 60)
            );
        }
        if ($hours == 1) {
            return __('an hour');
        }
        if ($hours < 48) {
            return sprintf(__('%d hours'), (int)round($hours));
        }
        return sprintf(__('%d days'), (int)round($hours / 24));
    }

    /**
     * The profile's enabled `exclusions` entries.
     *
     * An entry with no `enabled` key is on, which is how the shipped
     * default expresses itself and how the context builder's budget
     * reads the window. `evidence.window` is dropped here: it is applied by
     * the context builder, and a plan carrying it would invite a second
     * application.
     *
     * @param array|null $profile
     * @return array
     */
    private function entries($profile)
    {
        $section = $this->section($profile, 'exclusions');
        $entries = array();
        foreach ($section as $entry) {
            if (!is_array($entry) || empty($entry['id'])) {
                continue;
            }
            if (array_key_exists('enabled', $entry)
                && empty($entry['enabled'])
            ) {
                continue;
            }
            if ($entry['id'] === self::EVIDENCE_WINDOW) {
                continue;
            }
            $entries[] = $entry;
        }
        return $entries;
    }

    /**
     * @param array|null $profile
     * @param string $name
     * @return array
     */
    private function section($profile, $name)
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
