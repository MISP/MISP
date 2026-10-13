<?php
App::uses('AppModel', 'Model');
App::uses('ValueFieldKind', 'Tools/ValueIntelligence');
App::uses('ValueFacetTool', 'Tools');
App::uses('ValueConditionRewriter', 'Tools');

/**
 * The value-identity seam for the Value Intelligence page.
 *
 * The subject of that page is a value string — an IP address, a hash,
 * a domain — which is not a row of any table. It is a set of attribute
 * rows that happen to carry the same string, so this model has no table
 * of its own and resolves the value against `attributes` instead.
 *
 * `useTable = false` is established practice here: `Community`, `Module`
 * and `EventLock` all do it.
 *
 * **This is the only file in the Value Intelligence feature that names
 * `value1` or `value2`** (prd/value-intelligence-live/00-contract.md §14.3).
 * A feature is coming that moves `attributes.value` into a table of its
 * own — possibly several, split by type. This page does not build it,
 * does not wait for it and does not assume its shape; what it does is
 * arrange that when it lands, one file changes. Verification is a grep:
 * those two column names must not appear in ValueIntelligence.php, in
 * app/Lib/Tools/Value*.php, in ValuesController.php or under
 * app/View/Themed/Overmind/Elements/Values/.
 *
 * Identity is the value, not the pair `(type, value)`. A composite
 * attribute therefore contributes two identities, which is the reading
 * `Sighting::saveSightings` already takes when it matches value1 OR
 * value2 to write a sighting by value.
 */
class Value extends AppModel
{
    public $useTable = false;

    /**
     * Namespace of the UUIDv5 that names a value. Fixed forever: two
     * instances agree on a value's UUID only while this does.
     */
    const UUID_NAMESPACE = '6f3c2a8e-1d4b-5e7f-9a0c-3b8d2e4f6a1c';

    /**
     * The UUID a value is known by wherever it is stored as a record of
     * its own, such as a collection element.
     *
     * The value is taken as given apart from surrounding whitespace, the
     * reading the value page takes.
     *
     * @param string $value
     * @return string RFC 4122 version 5 UUID
     */
    public static function uuidFor($value)
    {
        $namespace = hex2bin(str_replace('-', '', self::UUID_NAMESPACE));
        $hash = sha1($namespace . trim((string)$value));
        return sprintf(
            '%s-%s-%04x-%04x-%s',
            substr($hash, 0, 8),
            substr($hash, 8, 4),
            (hexdec(substr($hash, 12, 4)) & 0x0fff) | 0x5000,
            (hexdec(substr($hash, 16, 4)) & 0x3fff) | 0x8000,
            substr($hash, 20, 12)
        );
    }

    /**
     * The event and object columns every row on the Relationships tab
     * is read through — the reporter, the audience and the object
     * template — stated once so the three fetchers cannot drift.
     *
     * They are also the columns `MispAttribute::buildConditions`
     * itself names, which is why a bare `contain` looks like it works:
     * the join is there and the ACL is enforced either way. What is
     * missing without this is the data, not the permission.
     */
    /**
     * How many values one prevalence lookup asks about per round trip.
     *
     * The candidate set is a whole co-occurrence fold — 10,040 values
     * on `8.8.8.8` — and each one is now its own bounded probe, so this
     * is how many of those probes share a statement rather than how
     * long an `IN` list may get. Measured flat from 200 to 400.
     */
    const PREVALENCE_CHUNK = 250;

    /**
     * How many occurrences a single value's probe may read.
     *
     * **The number that stops this lookup scaling with the instance.**
     * Prevalence used to be one `IN` pass per column that grouped every
     * matching row, so its cost tracked the rows the candidates matched
     * rather than the candidates themselves. `8.8.8.8`'s 34 sibling
     * values matched **277,987** rows — they are object-template enum
     * values like `flood` (65,717), `not-applicable` (32,945) and
     * `client-to-server` (32,869) — which grouped to 239,076 triples,
     * every one of them hydrated into PHP to be counted. That was
     * **3,631 ms** for 34 numbers, and linear: 7.3 µs per matched row,
     * measured from 55 rows to 267,474.
     *
     * A value that has already been seen this many times is not going
     * to be told apart from one seen twice as often by a denominator,
     * so the probe stops here and the caller is told it stopped. The
     * bound has to be on **rows read**, not on grouped output: a
     * `GROUP BY … LIMIT` has to group before it can limit, so it still
     * reads every matching row — measured at ~60 ms for one hot value
     * whether the limit was 50 or 1,000, against 23 ms for the same
     * value once the grouping came out.
     */
    const PREVALENCE_ROW_CAP = 500;

    /**
     * How many values get a prevalence probe at all.
     *
     * Each probe is bounded, so this bounds the lookup: at ~0.3 ms for
     * a value nothing much holds, 1,500 of them is ~420 ms whatever the
     * instance holds. Above it the tail goes unprobed and those rows
     * carry no spread, which is a state the fold and both tables
     * already render — `ValueRelationTool::emptyGroup` has why an
     * unknown spread is not a spread of zero.
     *
     * The tail is the right thing to drop because the caller hands the
     * values over in local-frequency order, so what goes unprobed is
     * what the fewest of the panel's own rows rest on. A value with
     * more than 1,500 distinct neighbours is not a value anyone reads
     * to a conclusion; it is `8.8.8.8`, and it still answers.
     */
    const PREVALENCE_PROBE_CAP = 1500;

    /**
     * Rows `spellingsFor` reads to answer how a value is spelled.
     *
     * Four, because the question is *which spellings are there*, and
     * the answer is almost always one: MISP lowercases the types where
     * case could vary at all. Reading a handful covers the types it
     * does not touch — `filename`, `text`, `url` — and stops the read
     * being a function of the value's popularity.
     */
    const SPELLING_ROW_CAP = 4;

    /** Values a search answers per page. */
    const MATCH_PAGE = 50;

    /** The shortest text a search runs on; one character matches too much to read. */
    const MATCH_MIN_LENGTH = 2;

    /**
     * Candidates whose visibility one statement checks. Under 1000: MariaDB
     * turns a longer IN list into a join (visibleValueIds).
     */
    const MATCH_CHUNK = 500;

    /**
     * MISP's attribute type for a date an object template records in a
     * field of its own — `time_first`, `first-seen`, `send-date`.
     *
     * The same string `ValueRelationTool::DATE_TYPE` folds the
     * Relationships tab's dated relations on; stated again here rather
     * than reached across because this file is the seam and a tool is
     * not, and a value table landing later has to answer *which rows
     * are dates* from whichever table holds them.
     */
    /**
     * *When was this occurrence observed*, in seconds, as SQL.
     *
     * The one definition every *when* aggregate on this model reads, so
     * that the clock, the recency signal and the continuity months
     * cannot disagree about what a date means — and so that
     * `Attribute.created_at` lands in two strings rather than in eight
     * queries once MISP has one.
     *
     * `Attribute.timestamp` is **last-modified**: an edit, a tag, a
     * sync update or a delete bumps it, and it is what sync compares to
     * decide which copy is newer. It stays as the last resort because
     * every row has one, and it is the last resort because a row write
     * is not an observation. `first_seen` and `last_seen` are `bigint`
     * **microseconds**, hence the divisor.
     *
     * **`_AT` is the recency end, `_FROM` the earliest.** The same
     * declared window answers two questions — *how recently was this
     * observed* wants `last_seen`, *when did this organisation first
     * report it* wants `first_seen` — so the two orders are the same
     * chain read from opposite ends.
     *
     * **When `Attribute.created_at` lands** it goes immediately before
     * `Attribute.timestamp` in both: a real creation date beats a row
     * write, and a declared observation still beats a creation date.
     * Nothing else in this file needs to change.
     *
     * Measured on 2.92M live attributes: `last_seen` is set on 16.2%
     * against `first_seen`'s 6.2%, and 295,924 `last_seen` values carry
     * no `first_seen` at all — which is why it leads `_AT`. 99.88% of
     * them precede the row write, by 4 days on average and 226 at most,
     * and none is in the future, so reading the observation moves every
     * date **earlier**: values read staler, never fresher.
     */
    const OBSERVED_AT = 'COALESCE('
        . 'FLOOR(Attribute.last_seen / 1000000),'
        . ' FLOOR(Attribute.first_seen / 1000000),'
        . ' Attribute.timestamp)';

    /** The same chain from the other end — see `OBSERVED_AT`. */
    const OBSERVED_FROM = 'COALESCE('
        . 'FLOOR(Attribute.first_seen / 1000000),'
        . ' FLOOR(Attribute.last_seen / 1000000),'
        . ' Attribute.timestamp)';

    const DATE_TYPE = 'datetime';

    const CONTEXT_FIELDS = array(
        'Event' => array('fields' => array(
            'Event.id',
            'Event.info',
            'Event.date',
            'Event.orgc_id',
            'Event.org_id',
            'Event.distribution',
            'Event.sharing_group_id',
            'Event.published',
        )),
        'Object' => array('fields' => array(
            'Object.id',
            'Object.name',
            'Object.distribution',
            'Object.sharing_group_id',
        )),
    );

    /**
     * MISP's attribute model, whose `$alias` is `Attribute` — so the
     * rows this class returns are keyed the way the templates and every
     * other MISP index already read them.
     *
     * @var MispAttribute
     */
    private $attributeModel = null;

    /**
     * @return MispAttribute
     */
    private function attributes()
    {
        if ($this->attributeModel === null) {
            $this->attributeModel = ClassRegistry::init('MispAttribute');
        }
        return $this->attributeModel;
    }

    /**
     * MISP's proposal model. Its `$alias` is `ShadowAttribute`, which
     * is the alias `conditionsFor` is asked for by name.
     *
     * @var ShadowAttribute
     */
    private $proposalModel = null;

    /**
     * @return ShadowAttribute
     */
    private function proposals()
    {
        if ($this->proposalModel === null) {
            $this->proposalModel = ClassRegistry::init('ShadowAttribute');
        }
        return $this->proposalModel;
    }

    /**
     * The condition fragment that selects a value's occurrences.
     *
     * Composes with `MispAttribute::buildConditions($user)` untouched,
     * so every existing ACL fetcher keeps working exactly as it does
     * today. Tomorrow this becomes a subquery or a join against the
     * value table(s) and nothing above it changes.
     *
     * `$options['types']` exists for that split: a caller that knows
     * which types it wants passes them and a per-type table can be
     * selected; a caller that does not gets the union. It costs a
     * parameter nobody has to use now and saves revisiting every call
     * site later.
     *
     * **`$options['alias']` is the same bargain, for a second table.**
     * `shadow_attributes` carries its own `value1`/`value2` pair with
     * the same semantics, so the Timeline's proposals lane needs this
     * predicate spelled `ShadowAttribute.value1` — and §14.3's rule is
     * that no file but this one may spell it at all. Defaulting to
     * `Attribute` keeps every existing caller byte-identical; none of
     * the fourteen passes the key.
     *
     * The parameter was named by `value-intelligence-coverage.md` §2.4 as
     * the one item in that survey with a cost per live phase deferred,
     * because a value table landing later has to answer the proposals
     * question too and `shadow_attributes.value1` is a column that
     * migration must either move or leave behind.
     *
     * **`exclude_orgs` is here rather than in each caller**, and that is
     * the point of it. An assessment that leaves out an organisation
     * has to leave it out of *every* count or the ledger contradicts
     * itself — reporting breadth dropping an organisation while the
     * occurrence tally still holds its rows is two numbers on one page
     * that cannot both be right. Every value-scoped aggregate in this
     * class builds its predicate here, so one key reaches all of them.
     * No caller passes it unless a profile asked for it, so nothing
     * outside the assessment changes. It names an `Event` column, which
     * every caller in this class already contains for the ACL's sake —
     * a future one that does not must not pass the key.
     *
     * @param string $value
     * @param array $options `types` narrows to a set of MISP types;
     *                       `alias` names the model the columns are on;
     *                       `exclude_orgs` drops those creating orgs
     * @return array
     */
    public function conditionsFor($value, array $options = array())
    {
        $alias = empty($options['alias']) ? 'Attribute' : $options['alias'];
        if ($alias === 'Attribute') {
            $matches = array(
                'Attribute.value1' => $value,
                'Attribute.value2' => $value,
            );
        } elseif ($alias === 'ShadowAttribute') {
            $matches = array(
                'ShadowAttribute.value1' => $value,
                'ShadowAttribute.value2' => $value,
            );
        } else {
            throw new InvalidArgumentException('No value hook on ' . $alias);
        }
        $conditions = array('OR' => $matches);
        $parts = array($conditions);
        if (!empty($options['types'])) {
            $parts[] = array($alias . '.type' => $options['types']);
        }
        if (!empty($options['exclude_orgs'])) {
            $parts[] = array(
                'Event.orgc_id NOT IN' => array_map(
                    'intval',
                    (array)$options['exclude_orgs']
                ),
            );
        }
        return count($parts) === 1 ? $conditions : $parts;
    }

    /**
     * How many occurrences of this value the viewer may see.
     *
     * Every count on the Value Intelligence page is the viewer's (§14.6):
     * the URL takes any value the reader types, so a count that
     * included invisible occurrences would turn the page into a
     * membership oracle for any indicator on the instance.
     *
     * An aggregate rather than a row fetch because the answer is one
     * number, and because its whole job is to be the total that a
     * capped row set is not — it cannot be derived from the rows.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return int
     */
    public function occurrenceCountFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.deleted' => 0);
        return (int)$attributes->find('count', array(
            'conditions' => $conditions,
            'recursive' => -1,
            // buildConditions() references Event.* and Object.* directly
            // rather than through subqueries, so both have to be joined
            // for the ACL to be expressible at all.
            'contain' => array('Event', 'Object'),
        ));
    }

    /**
     * How many objects this value sits in, for this viewer.
     *
     * The uncapped count of exactly what `occurrenceObjectIdsFor`
     * returns — the same three conditions, in the same order — so the
     * Relationships tab badge and the sibling panel's own census cannot
     * state different numbers for one value. That is the property
     * `ValueIntelligence::forTabCounts` exists to protect, and here it is
     * held by the conditions rather than by one shared call: the census
     * gets its total free from the rows it already fetched whenever the
     * value sits under `SIBLING_OBJECT_CAP` objects, and paying for
     * this aggregate there would be a query for a number already in
     * hand.
     *
     * One indexed aggregate over the `value1` prefix index: 0.3 ms on
     * `8.8.8.8` (15 objects) and 84 ms on `0.0.0.0`, the instance's
     * 32,922-object outlier. `ValueIntelligence::forTabCounts` has why the
     * badge is worth that where the co-occurrence total is not.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return int
     */
    public function objectCountFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.object_id >' => 0);
        $row = $attributes->find('first', array(
            'fields' => array(
                'COUNT(DISTINCT Attribute.object_id) AS objects',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            // As occurrenceCountFor: buildConditions() names Event.* and
            // Object.* directly, so both have to be joined.
            'contain' => array('Event', 'Object'),
        ));
        return empty($row[0]['objects']) ? 0 : (int)$row[0]['objects'];
    }

    /**
     * Four numbers about the whole occurrence set, in one aggregate.
     *
     * Tier 2 (§14.4), and the written reason is a measurement. The
     * Sightings tab needs the value's occurrence, event and organisation
     * counts for the write card's fan-out sentence and its oldest
     * occurrence date for the chart's span, and it needs them over
     * *every* occurrence rather than over a page. Materialising rows to
     * count them cost 617 ms on `443` — 48,255 occurrences behind three
     * sightings — and 280 ms on `0.0.0.0`. This is 4 ms on both.
     *
     * `orgs` counts creator organisations, matching the fan-out
     * sentence's wording and the Occurrences rail's organisation facet.
     *
     * **`dated_from` and `dated_at` say whether the two dates were
     * declared or inferred**, and they are here rather than in a second
     * aggregate because a date without them cannot be read honestly.
     * `OBSERVED_FROM`/`OBSERVED_AT` end in `Attribute.timestamp`, which
     * every row has and none of which is an observation, so `oldest`
     * and `newest` are never null and a caller printing them bare
     * states a row write as a sighting. Each counts the occurrences
     * declaring the column that *leads* its own chain — `first_seen`
     * for `_FROM`, `last_seen` for `_AT` — so a zero means precisely
     * *this date is a row write*. They differ from
     * `recordSummaryFor`'s single `dated`, which counts `first_seen`
     * only because the signal-strength ledger asks a different question.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor, plus `with_deleted` to
     *     count soft-deleted occurrences, which only a table that can
     *     show them needs
     * `published` counts the events among `events` that are published,
     * so the two are over one row set and the pair reads coherently.
     * `recordSummaryFor` carries a `published` of its own over a
     * narrower set, for the same reason its `dated` differs.
     *
     * @return array `occurrences`, `events`, `orgs`, `oldest`, `newest`,
     *     `dated_from`, `dated_at`, `published`
     */
    public function occurrenceSummaryFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        if (empty($options['with_deleted'])) {
            $conditions['AND'][] = array('Attribute.deleted' => 0);
        }
        $row = $attributes->find('first', array(
            'fields' => array(
                'COUNT(DISTINCT Attribute.id) AS occurrences',
                'COUNT(DISTINCT Event.id) AS events',
                'COUNT(DISTINCT Event.orgc_id) AS orgs',
                'MIN(' . self::OBSERVED_FROM . ') AS oldest',
                'MAX(' . self::OBSERVED_AT . ') AS newest',
                'SUM(CASE WHEN Attribute.first_seen IS NOT NULL'
                    . ' THEN 1 ELSE 0 END) AS dated_from',
                'SUM(CASE WHEN Attribute.last_seen IS NOT NULL'
                    . ' THEN 1 ELSE 0 END) AS dated_at',
                'COUNT(DISTINCT CASE WHEN Event.published = 1'
                    . ' THEN Event.id END) AS published',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
        ));
        $found = empty($row[0]) ? array() : $row[0];
        return array(
            'occurrences' => (int)($found['occurrences'] ?? 0),
            'events' => (int)($found['events'] ?? 0),
            'orgs' => (int)($found['orgs'] ?? 0),
            'oldest' => empty($found['oldest'])
                ? null
                : (int)$found['oldest'],
            'newest' => empty($found['newest'])
                ? null
                : (int)$found['newest'],
            'dated_from' => (int)($found['dated_from'] ?? 0),
            'dated_at' => (int)($found['dated_at'] ?? 0),
            'published' => (int)($found['published'] ?? 0),
        );
    }

    /**
     * The labels on this value's own occurrences, most-carried first
     * and bounded.
     *
     * `ownTagsFor`'s summary counterpart, and the difference is the
     * event dimension. That method groups by tag **and event** because
     * the neighbourhood table prints a label's reach per event; this
     * groups by tag alone, which is what a card listing labels needs
     * and is what lets the answer be capped at all — a `LIMIT` over
     * `(tag, event)` pairs would cut a tag's own rows in half and
     * report a count that is short by however many pairs fell off the
     * end.
     *
     * **The bound is why this exists.** `443` carries **3,860 distinct
     * tags** across 1,844 events on the verification instance, which
     * `ownTagsFor` returns as 42,039 grouped rows and the Overview's
     * card rendered in full: a 2.9 MB fragment for a panel whose job
     * is a summary. `8.8.8.8`, for contrast, has 7 tags in 20 events.
     * The caller asks for one more row than it means to draw, so
     * *there are more* is answered by the fetch rather than by a second
     * `COUNT`.
     *
     * `local` is `MIN` for the reason `ownTagsFor` gives: a tag is
     * local only where every occurrence carrying it is.
     *
     * **Each kind is capped on its own.** A cap over both kinds at
     * once makes the smaller one a hostage to the larger: `443`
     * carries 3,858 plain tags and **two** galaxy tags, so which
     * clusters survive the most-carried 60 depends on how crowded the
     * plain list is — and two readers seeing different halves of the
     * record got different numbers of *clusters* out of it, which is
     * not a fact about the value at all. The grouping is read once,
     * uncapped, and split here: it is one row per distinct tag, and a
     * read per kind scanned the same tag rows twice.
     *
     * @param array $user
     * @param string $value
     * @param int $limit Plain tags kept
     * @param int $galaxyLimit Galaxy tags kept
     * @param array $options As conditionsFor
     * @return array `tags` and `galaxy`, each name => `tag` (id, name,
     *     colour, is_galaxy, local) and `count`
     */
    public function topTagsFor(array $user, $value, $limit, $galaxyLimit,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.deleted' => 0);
        $rows = $attributes->find('all', array(
            'fields' => array(
                'Tag.id',
                'Tag.name',
                'Tag.colour',
                'Tag.is_galaxy',
                'COUNT(DISTINCT Attribute.id) AS occurrences',
                'MIN(AttributeTag.local) AS local',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            // Both, as everywhere else here: the ACL is not expressible
            // without them.
            'contain' => array('Event', 'Object'),
            'joins' => array(
                array(
                    'table' => 'attribute_tags',
                    'alias' => 'AttributeTag',
                    'type' => 'INNER',
                    'conditions' => array(
                        'AttributeTag.attribute_id = Attribute.id',
                    ),
                ),
                array(
                    'table' => 'tags',
                    'alias' => 'Tag',
                    'type' => 'INNER',
                    'conditions' => array('Tag.id = AttributeTag.tag_id'),
                ),
            ),
            'group' => array(
                'Tag.id',
                'Tag.name',
                'Tag.colour',
                'Tag.is_galaxy',
            ),
            'order' => array('occurrences DESC', 'Tag.name ASC'),
        ));
        $found = array('tags' => array(), 'galaxy' => array());
        $limits = array('tags' => (int)$limit, 'galaxy' => (int)$galaxyLimit);
        foreach ($rows as $row) {
            $kind = empty($row['Tag']['is_galaxy']) ? 'tags' : 'galaxy';
            if (count($found[$kind]) >= $limits[$kind]) {
                continue;
            }
            $found[$kind][$row['Tag']['name']] = array(
                'tag' => array(
                    'id' => (int)$row['Tag']['id'],
                    'name' => $row['Tag']['name'],
                    'colour' => $row['Tag']['colour'],
                    'is_galaxy' => $kind === 'galaxy',
                    'local' => !empty($row[0]['local']),
                ),
                'count' => (int)$row[0]['occurrences'],
            );
        }
        return $found;
    }

    /**
     * The labels on the **events** this value occurs in, most-carried
     * first and bounded.
     *
     * `topTagsFor`'s event-scope twin, and the page was blind to it
     * until 2026-09-14. Every tag surface on this profile — the
     * occurrence tables' Tags column, the Overview's context card, the
     * neighbourhood's label list — joined `attribute_tags` and nothing
     * else, which on this instance means the page was showing a
     * minority of what anybody had said about the value: `8.8.8.8`
     * carries **7 distinct attribute tags** and its twenty events carry
     * **48 distinct event tags** between them, the second set holding
     * every `tlp:`, the `type:OSINT` marking, and the MITRE ATT&CK
     * clusters the context card was reporting as *0 galaxy clusters*.
     *
     * **The count is events, and the caller must not add it to
     * `topTagsFor`'s.** That one counts occurrences carrying a tag;
     * this counts events carrying it. Two units, and the moment a
     * surface sums them or prints them in one column under one heading
     * it has invented a third that means neither — which is the defect
     * the sightings card was carrying a day before this was written.
     *
     * **The ACL is `topTagsFor`'s, deliberately unchanged.** The scope
     * is built exactly as that method builds it — `buildConditions`
     * over the attributes matching the value, `Attribute.deleted = 0`,
     * `Event` and `Object` contained because the rule is not
     * expressible without them — and the event-tag join hangs off the
     * attribute's own `event_id`. So an event reaches this result only
     * by holding an occurrence the reader may already see, and no new
     * visibility reasoning is introduced to get its labels.
     *
     * **A local event tag is not withheld.** `EventTag.local` is an
     * export rule rather than an access one: `excludeLocalTags` is set
     * by `Server::push` and the sync paths, defaults to false in
     * `EventsController::view`, and is a caller-supplied parameter on
     * the API. A reader who can open the event sees its local tags
     * there, so hiding them here would differ from MISP without
     * protecting anything. `local` rides along so the chip can carry
     * the same marker the attribute tags' chips do.
     *
     * **Two statements, and the second is the reason.** The obvious
     * shape is one query — join `attributes` to `event_tags` on
     * `event_id` and group — and it is the shape this was first written
     * with. It costs what it costs because the join happens *before*
     * the grouping: `443` has 48,255 occurrences across 1,844 events,
     * so every one of an event's tags is multiplied by every occurrence
     * the value has in it. The pair of calls `forContext` makes
     * measured **≈650 ms** on that value.
     *
     * Asked as *which events*, then *which tags on those events*, the
     * multiplication never happens: the first is the same indexed
     * aggregate every other count on this page runs, the second an `IN`
     * against `event_tags`' own index. The pair measures **129 ms** —
     * 122 for the first call and **8** for the second, which is the
     * memo on `taggableEventIdsFor` doing its work.
     *
     * For scale, the `topTagsFor` pair beside it on the same value
     * costs **916 ms**, and did before any of this. This scope is not
     * where that card's time goes.
     *
     * **The `IN` list is bounded by the value's events, not its
     * occurrences**, which is the distinction that makes it safe: the
     * widest value on the instance reaches 1,844 ids, where its
     * occurrence set is twenty-six times that.
     *
     * **Cheap, and cheaper than its attribute twin.** `443`'s 1,844
     * events carry 3,999 event-tag rows and **246 distinct tags** — an
     * order below the 3,860 distinct attribute tags that made
     * `CONTEXT_TAG_CAP` necessary in the first place. The bound is
     * still taken, on `topTagsFor`'s reasoning rather than on a
     * measurement of this one.
     *
     * @param array $user
     * @param string $value
     * @param int $limit
     * @param array $options As conditionsFor, plus `galaxy`: true for
     *     galaxy tags only, false for everything else, absent for both
     * @return array name => `tag` (id, name, colour, is_galaxy, local)
     *     and `count`, the latter counting **events**
     */
    public function eventTagsFor(array $user, $value, $limit,
        array $options = array()
    ) {
        $eventIds = $this->taggableEventIdsFor($user, $value, $options);
        if (empty($eventIds)) {
            return array();
        }
        $conditions = array('EventTag.event_id' => $eventIds);
        if (array_key_exists('galaxy', $options)) {
            $conditions['Tag.is_galaxy'] =
                empty($options['galaxy']) ? 0 : 1;
        }
        $eventTags = ClassRegistry::init('EventTag');
        $rows = $eventTags->find('all', array(
            'fields' => array(
                'Tag.id',
                'Tag.name',
                'Tag.colour',
                'Tag.is_galaxy',
                'COUNT(DISTINCT EventTag.event_id) AS events',
                // A tag is local only where every event carrying it has
                // it local — `topTagsFor`'s rule, for its reason.
                'MIN(EventTag.local) AS local',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'joins' => array(
                array(
                    'table' => 'tags',
                    'alias' => 'Tag',
                    'type' => 'INNER',
                    'conditions' => array('Tag.id = EventTag.tag_id'),
                ),
            ),
            'group' => array(
                'Tag.id',
                'Tag.name',
                'Tag.colour',
                'Tag.is_galaxy',
            ),
            'order' => array('events DESC', 'Tag.name ASC'),
            'limit' => (int)$limit,
        ));
        $found = array();
        foreach ($rows as $row) {
            $found[$row['Tag']['name']] = array(
                'tag' => array(
                    'id' => (int)$row['Tag']['id'],
                    'name' => $row['Tag']['name'],
                    'colour' => $row['Tag']['colour'],
                    'is_galaxy' => !empty($row['Tag']['is_galaxy']),
                    'local' => !empty($row[0]['local']),
                ),
                'count' => (int)$row[0]['events'],
            );
        }
        return $found;
    }

    /**
     * The last `taggableEventIdsFor` answer, and what it was asked.
     *
     * `forContext` calls `eventTagsFor` **twice** — once for plain tags
     * and once for galaxies, for the reason that method's caller gives
     * — and each call needs the same event-id scope. Unmemoised that is
     * the same aggregate over the same 33,110 occurrences twice:
     * `0.0.0.0` measured 213 ms and 175 ms for two reads whose tag
     * halves are a few milliseconds each.
     *
     * Keyed on the reader as well as the value, because the scope is
     * `buildConditions`' and two readers do not have the same one. One
     * entry is enough: a panel request asks about one value.
     *
     * @var array|null
     */
    private $taggableEventIds = null;
    private $taggableEventIdsKey = null;

    /**
     * The events whose labels may be read as this value's context.
     *
     * `topTagsFor`'s scope expressed as event ids: `buildConditions`
     * over the attributes matching the value, soft-deleted occurrences
     * excluded, `Event` and `Object` contained because the ACL is not
     * expressible without them. An event reaches this list only by
     * holding an occurrence the reader may already see, which is what
     * lets `eventTagsFor` read `event_tags` with no visibility test of
     * its own.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array Event ids
     */
    private function taggableEventIdsFor(array $user, $value,
        array $options = array()
    ) {
        /*
         * `galaxy` narrows the *tags*, never the events, so the two
         * calls share one scope — and it is dropped from the key so
         * they share one answer.
         */
        $scope = $options;
        unset($scope['galaxy']);
        $key = json_encode(array(
            isset($user['id']) ? $user['id'] : null,
            $value,
            $scope,
        ));
        if ($this->taggableEventIds !== null
            && $this->taggableEventIdsKey === $key
        ) {
            return $this->taggableEventIds;
        }
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.deleted' => 0);
        $rows = $attributes->find('all', array(
            'fields' => array('DISTINCT Attribute.event_id AS event_id'),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
        ));
        $ids = array();
        foreach ($rows as $row) {
            if (!empty($row[0]['event_id'])) {
                $ids[] = (int)$row[0]['event_id'];
            } elseif (!empty($row['Attribute']['event_id'])) {
                $ids[] = (int)$row['Attribute']['event_id'];
            }
        }
        $this->taggableEventIds = $ids;
        $this->taggableEventIdsKey = $key;
        return $ids;
    }

    /**
     * How many sightings this viewer may see on this value, and how
     * many of them are false positives.
     *
     * **The count the fact strip and the tab badge both wanted and
     * neither could have.** `ValueIntelligence::forTabCounts` dropped the
     * sightings badge rather than print a number that is not the
     * reader's, and said what it would take to bring it back: *"`Sighting`
     * growing a counting method that applies the policy in SQL instead
     * of in PHP over fetched rows"*. This is that method's value-scoped
     * half.
     *
     * Two visibility rules meet here and both are somebody else's:
     *
     * - **the attribute half** is `buildConditions($user)` with
     *   `conditionsFor`, exactly as every other aggregate in this class
     *   scopes itself, so a sighting on an occurrence the reader cannot
     *   see is not counted;
     * - **the sighting half** is `Sighting::visibilityConditions`,
     *   which is `Plugin.Sightings_policy` as a predicate over the
     *   joined rows rather than over an id set — and an id set is the
     *   reason this did not exist, since `443` would have had to
     *   materialise 48,255 attribute ids before its three sightings
     *   could be counted.
     *
     * One aggregate, one join, and nothing that grows with the value:
     * `COUNT` over the `sightings` index on `attribute_id`, against the
     * occurrence predicate the rest of the page already uses.
     *
     * **Soft-deleted occurrences are excluded, and that is the one
     * place this deliberately differs from the occurrence count beside
     * it.** `listSightings` puts `Attribute.deleted = 0` in its own
     * conditions, so the Sightings tab does not show a report filed
     * against a withdrawn occurrence — and a strip cell that counted
     * reports the tab will not list is a cell that sends the reader to
     * look for rows that are not there. Agreeing with the panel this
     * number links to matters more than agreeing with the number beside
     * it, which counts a different thing.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array `total` and `fp`
     */
    public function sightingCountsFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.deleted' => 0);
        $policy = ClassRegistry::init('Sighting')
            ->visibilityConditions($user);
        if (!empty($policy)) {
            $conditions['AND'][] = $policy;
        }
        $row = $attributes->find('first', array(
            'fields' => array(
                'COUNT(Sighting.id) AS total',
                'SUM(CASE WHEN Sighting.type = 1 THEN 1 ELSE 0 END) AS fp',
                'SUM(CASE WHEN Sighting.type = 2 THEN 1 ELSE 0 END)'
                    . ' AS expiration',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
            'joins' => array(
                array(
                    'table' => 'sightings',
                    'alias' => 'Sighting',
                    'type' => 'INNER',
                    'conditions' => array(
                        'Sighting.attribute_id = Attribute.id',
                    ),
                ),
            ),
        ));
        $found = empty($row[0]) ? array() : $row[0];
        $total = (int)($found['total'] ?? 0);
        $fp = (int)($found['fp'] ?? 0);
        $expiration = (int)($found['expiration'] ?? 0);
        return array(
            'total' => $total,
            /*
             * **`sighting` is the one the page prints under the word
             * *Sightings***, and it is not `total`. The `sightings`
             * table holds three kinds of row and MISP counts them
             * apart: the Overview's own card reads *47 Sightings · 4
             * False positive · 2 Expiration* on `8.8.8.8`, where the
             * three sum to 53. A fact cell headed *Sightings 53* beside
             * a card headed *47 Sightings* is one word meaning two
             * things on one page, which is the contradiction this
             * feature keeps being bitten by — so the cell prints this
             * and the card's arithmetic is where it comes from.
             *
             * `total` stays, because it is what `listSightings` returns
             * a row for and so what the probe compares against.
             */
            'sighting' => $total - $fp - $expiration,
            'fp' => $fp,
            'expiration' => $expiration,
        );
    }

    /**
     * How many occurrences reach this value through `value2`, by type.
     *
     * The page's occurrence set is `value1 = X OR value2 = X`
     * (`conditionsFor`, and the seam's own docblock says why), so a
     * page about `8.8.8.8` legitimately carries rows whose attribute
     * value is `evil.example|8.8.8.8`. A reader who does not know that
     * reads the occurrence count as wrong, and the Assessment tab's
     * audit hit exactly this on `23.227.38.32`.
     *
     * `value1 !=` is what makes the answer a *disclosure* rather than a
     * tally: a composite whose `value1` is the literal `A|B` with an
     * empty `value2` matches on the first half and is not a second-half
     * row at all. One indexed aggregate over the same conditions every
     * other count on this page uses, grouped so the note can name the
     * type rather than say *some type*.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array [['type' => 'domain|ip', 'count' => 1], …]
     */
    public function value2CountFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.value2' => $value);
        $conditions['AND'][] = array('Attribute.value1 !=' => $value);
        $rows = $attributes->find('all', array(
            'fields' => array(
                'Attribute.type',
                'COUNT(DISTINCT Attribute.id) AS occurrences',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
            'group' => array('Attribute.type'),
            'order' => array('occurrences DESC'),
        ));
        $types = array();
        foreach ($rows as $row) {
            $types[] = array(
                'type' => $row['Attribute']['type'],
                'count' => (int)$row[0]['occurrences'],
            );
        }
        return $types;
    }

    /**
     * Everything the assessment's aggregate class needs about the
     * record, in one query.
     *
     * `occurrenceSummaryFor`'s five numbers plus the three the signal strength
     * ledger reads — how much of the reporting is published, how many
     * occurrences date their own observation, and the worst
     * encoding-against-event lag — because they are all single-row
     * aggregates over the same join and a second query for them would
     * buy nothing. The summary keeps its own contract; five panels
     * already read it and none of them wants these three.
     *
     * **Soft-deleted occurrences are excluded, and that is a
     * judgement rather than tidying.** A withdrawn attribute is a
     * claim its organisation took back; scoring it would let a
     * retracted report keep arguing. `occurrenceSummaryFor` counts
     * them because the Occurrences tab *shows* them — a row a reader
     * can see has to be in the total above it (§14.6) — and an
     * assessment has the opposite obligation.
     *
     * The lag is `Event.date` against the attribute's own timestamp:
     * the encoding date against the date the event says the thing
     * happened. `06-staleness.md` §3.6 makes it one of the two inputs
     * that put the relevance axis into *timeline uncertain*, and
     * `record.temporal_precision` reads the same fact as a signal strength
     * signal.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array
     */
    /**
     * Every date MISP holds for this value, side by side, in one row.
     *
     * The relevance card's provenance table. Its point is that the axis
     * is built on dates whose meanings differ, and that a reader who
     * cannot see which is which cannot argue with the answer — three
     * separate bugs in this feature were a column being read as
     * something it is not (`06-staleness.md` §7.11, §7.12).
     *
     * One aggregate over the same conditions the rest of the panel
     * uses, so it costs one indexed scan and no per-row work.
     *
     * `first_seen` and `last_seen` are `bigint` microseconds and are
     * returned in seconds; `Event.date` is a `date` and is returned as
     * its string, because a day is all it holds and rendering it as a
     * timestamp would invent an hour.
     *
     * **`created_at` is absent, deliberately reported as absent.** MISP
     * stores no attribute creation date; the card draws the row anyway
     * so the gap is visible rather than merely unmentioned, and so that
     * the day it exists there is one obvious place to fill in.
     *
     * @param array $user
     * @param string $value
     * @param array $options
     * @return array
     */
    public function timelineFactsFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.deleted' => 0);
        $row = $attributes->find('first', array(
            'fields' => array(
                'COUNT(DISTINCT Attribute.id) AS occurrences',
                'MIN(FLOOR(Attribute.first_seen / 1000000)) AS first_seen',
                'MAX(FLOOR(Attribute.last_seen / 1000000)) AS last_seen',
                'SUM(Attribute.first_seen IS NOT NULL) AS with_first_seen',
                'SUM(Attribute.last_seen IS NOT NULL) AS with_last_seen',
                'MIN(Attribute.timestamp) AS written_first',
                'MAX(Attribute.timestamp) AS written_last',
                'MIN(Event.date) AS event_date_first',
                'MAX(Event.date) AS event_date_last',
                'MAX(Event.publish_timestamp) AS published_last',
                'COUNT(DISTINCT CASE WHEN Event.published = 1'
                    . ' THEN Event.id END) AS published_events',
                'COUNT(DISTINCT Event.id) AS events',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
        ));
        $found = empty($row[0]) ? array() : $row[0];
        $stamp = function ($key) use ($found) {
            return isset($found[$key]) && $found[$key] !== null
                && (int)$found[$key] > 0
                    ? (int)$found[$key]
                    : null;
        };
        return array(
            'occurrences' => (int)($found['occurrences'] ?? 0),
            'events' => (int)($found['events'] ?? 0),
            'first_seen' => $stamp('first_seen'),
            'last_seen' => $stamp('last_seen'),
            'with_first_seen' => (int)($found['with_first_seen'] ?? 0),
            'with_last_seen' => (int)($found['with_last_seen'] ?? 0),
            'written_first' => $stamp('written_first'),
            'written_last' => $stamp('written_last'),
            'event_date_first' => empty($found['event_date_first'])
                ? null
                : (string)$found['event_date_first'],
            'event_date_last' => empty($found['event_date_last'])
                ? null
                : (string)$found['event_date_last'],
            'published_last' => $stamp('published_last'),
            'published_events' => (int)($found['published_events'] ?? 0),
            /*
             * The column MISP does not have. Reported rather than
             * omitted — see the docblock.
             */
            'created_at' => null,
        );
    }

    /**
     * **Which column is "when this was reported" — the open question.**
     *
     * Every aggregate on this model that means *when* currently reads
     * `Attribute.timestamp`, and that column is **last-modified**: an
     * edit, a tag, a sync update or a delete bumps it, and it is what
     * sync compares to decide which copy is newer. MISP stores **no
     * creation date for an attribute**, so there is nothing to swap it
     * for today.
     *
     * What that costs, measured on this instance:
     *
     *   - the relevance clock's occurrence half is `MIN(timestamp)` per
     *     organisation, so **editing an old occurrence moves that
     *     organisation's "join" date forward** and the value reads as
     *     freshly corroborated. `8.8.8.8` shows 223 days of drift
     *     between DECEA's earliest event date and its computed join
     *     date, and 5 of its 26 occurrences were written after their
     *     event was published. Nothing in the data separates *reported
     *     later* from *edited later*;
     *   - `lifecycle.recency` says *"Last reported N days ago"* off
     *     `MAX(timestamp)`, and `lifecycle.continuity` counts a month
     *     of activity for a month that only contains an edit. Both
     *     score, so this reaches the verdict.
     *
     * **The agreed chain, for when the columns exist.** Prefer a
     * declared observation over a row write, and fall through:
     *
     * ```
     * recency   ← Sighting.date_sighting        (already its own clock event)
     *           ← Attribute.last_seen
     *           ← Attribute.first_seen
     *           ← Attribute.created_at          (when it lands)
     *           ← Attribute.timestamp           (last resort)
     *
     * earliest  ← Attribute.first_seen
     *           ← Attribute.last_seen
     *           ← Attribute.created_at          (when it lands)
     *           ← Attribute.timestamp           (last resort)
     * ```
     *
     * Two directions rather than one list, because the same window
     * answers two questions: *when did this organisation first report
     * it* wants the start, and *how recently was it recorded* wants the
     * end.
     *
     * **`created_at` slots in above `timestamp` and below the seen
     * dates** — it is a real creation date, so it beats a row write,
     * and it is still a recording date, so a declared observation beats
     * it. When it lands, the fallbacks in this file and in
     * `ValueRelevanceTool::joinEvents()` are the sites to change, and
     * §3.6's uncertainty rule gains a fourth answer: a value with a
     * `created_at` and no seen dates is datable to its record, which is
     * not the same as datable to its observation.
     *
     * **Units differ and the comparison must convert.** `first_seen`
     * and `last_seen` are `bigint` **microseconds**; `timestamp` and
     * `date_sighting` are seconds. So `last_seen / 1000000`.
     *
     * **Availability, and why `last_seen` leads the recency chain**
     * (2.92M live attributes on the dev instance):
     *
     * | column | set | note |
     * |---|---|---|
     * | `last_seen` | 473,327 (16.2%) | 295,924 of them carry **no** `first_seen` |
     * | `first_seen` | 179,878 (6.2%) | only 2,475 without a `last_seen` |
     *
     * **And the substitution is safe in the conservative direction.**
     * 472,749 of 473,327 `last_seen` values (99.88%) precede the row
     * write, by 4 days on average and 226 at most; 578 follow it and
     * **none** is in the future. So reading the observation instead of
     * the write moves the clock *earlier* — values read staler, never
     * fresher, which is the direction §3.5's asymmetry asks for.
     *
     * Recorded rather than built: the chain changes what every value on
     * an instance reads, and `06-staleness.md` §7.11 is the standing
     * example of why a date this load-bearing gets decided before it
     * gets written.
     */
    public function recordSummaryFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.deleted' => 0);
        $row = $attributes->find('first', array(
            'fields' => array(
                'COUNT(DISTINCT Attribute.id) AS occurrences',
                'COUNT(DISTINCT Event.id) AS events',
                'COUNT(DISTINCT Event.orgc_id) AS orgs',
                'MIN(' . self::OBSERVED_FROM . ') AS oldest',
                'MAX(' . self::OBSERVED_AT . ') AS newest',
                'COUNT(DISTINCT CASE WHEN Event.published = 1'
                    . ' THEN Event.id END) AS published',
                /*
                 * `max_lag_days` was here, as
                 * `MAX(TIMESTAMPDIFF(DAY, Event.date,
                 * FROM_UNIXTIME(Attribute.timestamp)))`, and it is
                 * gone rather than fixed because there is nothing to
                 * fix it to. **The attributes table has no created
                 * column** — `timestamp` is last-modified, bumped by
                 * an edit, a tag, a sync update or a delete, and it is
                 * what sync compares to decide which copy is newer. So
                 * the expression measured *analyst-assigned event date
                 * → whenever somebody last touched this row*, which is
                 * neither an encoding delay nor anything else with a
                 * name. On `8.8.8.8` its 302-day maximum came from an
                 * attribute last written the day after its event was
                 * published.
                 *
                 * `Event.date` is the other half of the objection: it
                 * is a date an analyst types, so it carries the same
                 * delay the measurement was trying to detect.
                 *
                 * What replaces it is not a measurement at all — see
                 * `ValueRelevanceTool`'s `undated_assumed_days`.
                 */
                'SUM(CASE WHEN Attribute.first_seen IS NOT NULL'
                    . ' THEN 1 ELSE 0 END) AS dated',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
        ));
        $found = empty($row[0]) ? array() : $row[0];
        return array(
            'occurrences' => (int)($found['occurrences'] ?? 0),
            'events' => (int)($found['events'] ?? 0),
            'orgs' => (int)($found['orgs'] ?? 0),
            'published' => (int)($found['published'] ?? 0),
            'dated' => (int)($found['dated'] ?? 0),
            'oldest' => empty($found['oldest'])
                ? null
                : (int)$found['oldest'],
            'newest' => empty($found['newest'])
                ? null
                : (int)$found['newest'],
        );
    }

    /**
     * Each organisation's stake in this value: how many occurrences it
     * holds, and how its occurrences set `to_ids`.
     *
     * Two readers, one query. `reporting.independent_orgs` counts the
     * rows; the lean derivation (`04-dispositions.md` §3) reads the
     * stances, and counts them **per organisation rather than per
     * occurrence** — one org putting forty `to_ids = 1` events on a
     * value is one voice, which is the same independence argument the
     * reporting signal makes.
     *
     * Grouped in SQL rather than folded in PHP for the reason
     * `ownTagsFor` gives: a value can occur 48,255 times and the answer
     * is a handful of rows either way.
     *
     * Organisation *names* are not here. This class owns the value's
     * identity and its occurrence set; who an `orgc_id` belongs to is
     * the Organisation model's, and the caller resolves it in one
     * lookup.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array Rows of `Event.orgc_id` and, under `0`,
     *               `occurrences`, `to_ids_yes`, `to_ids_no`, `newest`,
     *               `oldest`
     */
    public function orgStanceFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.deleted' => 0);
        return $attributes->find('all', array(
            'fields' => array(
                'Event.orgc_id',
                'COUNT(DISTINCT Attribute.id) AS occurrences',
                'SUM(CASE WHEN Attribute.to_ids = 1 THEN 1 ELSE 0 END)'
                    . ' AS to_ids_yes',
                'SUM(CASE WHEN Attribute.to_ids = 0 THEN 1 ELSE 0 END)'
                    . ' AS to_ids_no',
                'MAX(' . self::OBSERVED_AT . ') AS newest',
                /*
                 * When this organisation last wrote a `to_ids = 1` row,
                 * which is when it last made the assertion — the row
                 * date and not the observed date, because a false
                 * positive filed after it is weighed against the
                 * statement, not against the sighting the statement
                 * was about.
                 */
                'MAX(CASE WHEN Attribute.to_ids = 1'
                    . ' THEN Attribute.timestamp END) AS newest_flagged',
                /*
                 * When this organisation first held the value, which is
                 * the relevance clock's occurrence half: the most
                 * recent of these across organisations is the last time
                 * somebody new corroborated the record
                 * (`06-staleness.md` §3.3). One more aggregate on a
                 * query that is already grouped by organisation, so it
                 * costs nothing the stances did not already cost.
                 */
                'MIN(' . self::OBSERVED_FROM . ') AS oldest',
            ),
            /*
             * `OBSERVED_FROM`, not `Attribute.timestamp`: this is the
             * relevance clock's occurrence half, and on a row-write
             * date **editing one old occurrence moved an
             * organisation's join date forward** and the value read as
             * freshly corroborated. `8.8.8.8` carried 223 days of drift
             * between DECEA's earliest event date and its computed
             * join date.
             */
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
            'group' => array('Event.orgc_id'),
            'order' => array('occurrences DESC'),
        ));
    }

    /**
     * Which months this value was reported in, and how often.
     *
     * `lifecycle.continuity` asks whether the reporting is continuous
     * or one burst, and the answer is the longest unbroken run of
     * months — which needs the months, not the span.
     *
     * **An index aggregate, so it is never windowed** (`03-signals.md`
     * §2.3): the row count is the value's age in months, whatever its
     * occurrence count, and bounding it to 90 days would cap every
     * long-lived value's continuity at three months — turning the
     * signal's own subject into an artefact of the budget.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array `YYYY-MM` => occurrences, oldest month first
     */
    public function activityMonthsFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.deleted' => 0);
        $rows = $attributes->find('all', array(
            'fields' => array(
                /*
                 * A month in which the value was **observed**. On
                 * `Attribute.timestamp` an edit invented one — a value
                 * untouched since 2022 grew a 2026 month of "activity"
                 * for a tag — and `lifecycle.continuity` scores this,
                 * so it reached the verdict.
                 */
                'DATE_FORMAT(FROM_UNIXTIME(' . self::OBSERVED_AT . "),"
                    . " '%Y-%m') AS month",
                'COUNT(DISTINCT Attribute.id) AS occurrences',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
            'group' => array('month'),
            'order' => array('month ASC'),
        ));
        $months = array();
        foreach ($rows as $row) {
            if (empty($row[0]['month'])) {
                continue;
            }
            $months[$row[0]['month']] = (int)$row[0]['occurrences'];
        }
        return $months;
    }

    /**
     * How widely each of many values is spread, for this viewer.
     *
     * `occurrenceSummaryFor`'s `events` count, plural — the denominator
     * the Relationships tab's **Most specific** rank divides by. A
     * neighbour that shares five events with the value is worth
     * clicking if those are five of the six events it appears in
     * anywhere, and worth ignoring if they are five of two hundred;
     * ranking cannot tell those apart without this number.
     *
     * **Viewer-scoped, and that is not a detail.** §14.6 makes every
     * count on the page the reader's own, and the printed fraction is
     * read as *"in 8 of its 204 events"* beside a value the reader can
     * open. A denominator over events they cannot see would both leak
     * membership and disagree with the page they land on. The ACL join
     * costs almost nothing here: 775 ms against 626 ms unscoped over
     * `8.8.8.8`'s 9,520 neighbours, the worst fold on the instance.
     *
     * **One bounded probe per value, which is what stops this scaling
     * with the instance.** Identity and storage disagree on composite
     * attributes: a value is an identity when it is `value1` **or**
     * `value2` (`conditionsFor`, and the reason is in this class's own
     * docblock), while the co-occurrence fold keys its rows on
     * `Attribute.value`, which composes to `value1|value2`. 16% of this
     * instance's attributes are composite and 2,231 of `8.8.8.8`'s
     * 10,040 neighbour keys carry a pipe, so neither reading can be
     * skipped. A key's count is the union of the two: the composed
     * value equals `A|B` exactly when `value1` is `A` and `value2` is
     * `B`, or when `value1` is the literal `A|B` and `value2` is empty.
     *
     * This used to be two `IN` passes that grouped every matching row
     * and rebuilt the union in PHP, and its cost tracked the rows the
     * candidates matched rather than the candidates themselves —
     * `PREVALENCE_ROW_CAP` carries the measurements. Each key now asks
     * its own question, capped, and MariaDB answers it off the two
     * value indexes: `EXPLAIN` reports
     * `index_merge … sort_union(value1,value2)` for the plain shape.
     *
     * **The arms are separate statements, not one condition.** A
     * thousand `(value1 = A AND value2 = B)` arms OR'd into a single
     * `WHERE` took **311 seconds** over this fold and matched far more
     * than it was asked about. Chunking them as `UNION ALL` keeps every
     * arm its own indexed lookup with its own `LIMIT`, which is the
     * only way the cap can bind per value.
     *
     * **Equality, so an absent value costs nothing.** The cap would be
     * no protection if a miss had to scan: 200 values that match
     * nothing cost 98 ms, against the 4.5 s a `LIKE '%…'` shape spends
     * discovering the same thing — the trap recorded at
     * `nearMatches`. Every arm here is an equality on an indexed
     * column, so a value nobody holds is a range lookup that finds
     * nothing.
     *
     * @param array $user
     * @param array $values Value strings, as the caller keys them, most
     *                      locally frequent first — the tail past
     *                      `PREVALENCE_PROBE_CAP` goes unprobed
     * @param array $options `unit` counts `event` (default) or
     *                       `object`; otherwise as conditionsFor
     * @return array `counts` (key => exact count, absent when zero),
     *               `capped` (key => true, too common to count),
     *               `row_cap`, `probed`, `unprobed`
     */
    public function prevalenceFor(array $user, array $values,
        array $options = array()
    ) {
        $wanted = array();
        foreach ($values as $value) {
            if ($value !== '' && $value !== null) {
                $wanted[(string)$value] = true;
            }
        }
        /*
         * **Back to strings, and this is not defensive tidying.** PHP
         * turns an array key that looks like an integer into one, so
         * `array_keys` hands back `443` and `1204` — real neighbours,
         * a port and a passive-DNS record count — as ints. CakePHP
         * binds them as integers, MariaDB then compares a varchar
         * column against a number, converts the whole column to do it
         * and abandons the `value1` index.
         */
        $keys = array_map('strval', array_keys($wanted));
        $out = array(
            'counts' => array(),
            'capped' => array(),
            'row_cap' => self::PREVALENCE_ROW_CAP,
            'probed' => 0,
            'unprobed' => 0,
        );
        if (empty($keys)) {
            return $out;
        }
        if (count($keys) > self::PREVALENCE_PROBE_CAP) {
            $out['unprobed'] = count($keys) - self::PREVALENCE_PROBE_CAP;
            $keys = array_slice($keys, 0, self::PREVALENCE_PROBE_CAP);
        }
        $out['probed'] = count($keys);
        $probed = $this->prevalenceProbe($user, $keys, $options);
        $out['counts'] = $probed['counts'];
        $out['capped'] = $probed['capped'];
        return $out;
    }

    /**
     * The probes themselves, chunked into `UNION ALL` statements.
     *
     * `Event` and `Object` are joined because
     * `MispAttribute::buildConditions` names their columns directly,
     * and only the id being counted is selected: the ACL filters on
     * columns it does not have to read back.
     *
     * Each arm reads at most `PREVALENCE_ROW_CAP + 1` occurrences and
     * reports two numbers about them — how many it read, and how many
     * distinct events or objects they were. The first says whether the
     * second can be trusted: an arm that came back short of its limit
     * saw every occurrence there is, so its distinct count is exact;
     * one that filled its limit saw a prefix, and the honest answer
     * about such a value is that it is too common to count rather than
     * whatever the prefix happened to hold. `flood` reads 501 rows
     * spread over one event — the distinct count off a truncated read
     * is not a small number, it is a meaningless one.
     *
     * @param array $user
     * @param array $keys Value strings, already capped and stringified
     * @param array $options As prevalenceFor
     * @return array `counts` and `capped`
     */
    private function prevalenceProbe(array $user, array $keys,
        array $options
    ) {
        $attributes = $this->attributes();
        $db = $attributes->getDataSource();
        $acl = $attributes->buildConditions($user);
        $object = isset($options['unit'])
            && $options['unit'] === 'object';
        $probeField = $object
            ? 'Attribute.object_id AS probe_id'
            : 'Attribute.event_id AS probe_id';
        $joins = array(
            array(
                'table' => $db->fullTableName(ClassRegistry::init('Event')),
                'alias' => 'Event',
                'type' => 'LEFT',
                'conditions' => array('Event.id = Attribute.event_id'),
            ),
            array(
                'table' => $db->fullTableName(
                    ClassRegistry::init('MispObject')
                ),
                'alias' => 'Object',
                'type' => 'LEFT',
                'conditions' => array('Object.id = Attribute.object_id'),
            ),
        );

        $counts = array();
        $capped = array();
        // buildStatement() skips the attribute hooks: translate the value
        // conditions here, every key resolved in one statement
        $terms = array();
        foreach ($keys as $key) {
            $terms[] = (string)$key;
            $cut = strpos($key, '|');
            if ($cut !== false && $cut > 0) {
                $terms[] = substr($key, 0, $cut);
                $terms[] = substr($key, $cut + 1);
            }
        }
        $rewriter = ClassRegistry::init('AttributeValue')
            ->batchRewriter('Attribute', $terms);
        foreach (array_chunk($keys, self::PREVALENCE_CHUNK) as $chunk) {
            $arms = array();
            foreach ($chunk as $key) {
                $conditions = $acl;
                $conditions['AND'][] = $rewriter->rewrite(
                    $this->prevalencePredicate($key)
                );
                if (!empty($options['types'])) {
                    $conditions['AND'][] = array(
                        'Attribute.type' => $options['types'],
                    );
                }
                if ($object) {
                    $conditions['AND'][] = array(
                        'Attribute.object_id !=' => 0,
                    );
                }
                /*
                 * `order` empty on purpose: `MispAttribute` carries a
                 * default `Attribute.event_id DESC` that a `find()`
                 * would append here, and an ordering nobody reads would
                 * turn a bounded index lookup into a sort of everything
                 * the arm matched.
                 */
                $inner = $db->buildStatement(array(
                    'fields' => array($probeField),
                    'table' => $db->fullTableName($attributes),
                    'alias' => 'Attribute',
                    'joins' => $joins,
                    'conditions' => $conditions,
                    'order' => null,
                    'group' => null,
                    'having' => null,
                    'limit' => self::PREVALENCE_ROW_CAP + 1,
                    'offset' => null,
                ), $attributes);
                $arms[] = 'SELECT ' . $db->value($key, 'string')
                    . ' AS probe_key, COUNT(*) AS probe_rows,'
                    . ' COUNT(DISTINCT probe_id) AS probe_ids'
                    . ' FROM (' . $inner . ') AS probe';
            }
            $rows = $db->fetchAll(implode(' UNION ALL ', $arms));
            if (empty($rows)) {
                continue;
            }
            foreach ($rows as $row) {
                /*
                 * Every column here is computed, so CakePHP files them
                 * under the no-table key rather than under an alias.
                 */
                $cells = isset($row[0]) ? $row[0] : reset($row);
                if (!is_array($cells)
                    || !array_key_exists('probe_key', $cells)
                ) {
                    continue;
                }
                $key = (string)$cells['probe_key'];
                if ((int)$cells['probe_rows'] > self::PREVALENCE_ROW_CAP) {
                    $capped[$key] = true;
                    continue;
                }
                $ids = (int)$cells['probe_ids'];
                if ($ids > 0) {
                    $counts[$key] = $ids;
                }
            }
        }
        return array('counts' => $counts, 'capped' => $capped);
    }

    /**
     * Every way one fold key can be stored, as one indexed predicate.
     *
     * A plain key is an identity on either column. A composed key is
     * additionally the pair that spells it — and still the literal, for
     * the attribute whose `value1` carries a pipe of its own with an
     * empty `value2`. All arms are equalities, so the whole predicate
     * stays a set of range lookups over `value1` and `value2`.
     *
     * @param string $key A key as the co-occurrence fold spells it
     * @return array
     */
    private function prevalencePredicate($key)
    {
        $predicate = array(
            'OR' => array(
                array('Attribute.value1' => $key),
                array('Attribute.value2' => $key),
            ),
        );
        $cut = strpos($key, '|');
        if ($cut !== false && $cut > 0) {
            $predicate['OR'][] = array(
                'Attribute.value1' => substr($key, 0, $cut),
                'Attribute.value2' => substr($key, $cut + 1),
            );
        }
        return $predicate;
    }

    /**
     * Only the occurrences that carry at least one sighting.
     *
     * The query this tab could not do without, and the one place in this
     * feature that joins another model's table. **The alternative was
     * measured and it does not work**: scoping
     * `Sighting::listSightings` by the value's whole occurrence set
     * means handing it 48,255 ids on `443`, which it re-resolves through
     * `fetchAttributes` — 1.6 to 3.4 seconds per panel for three
     * sightings. Narrowing first turns that into a millisecond.
     *
     * Tier 2, and it is an aggregate rather than a fetch: one row per
     * occurrence that has been reported, and nothing about the reports
     * themselves. **The sighting policy is not applied here and does not
     * need to be** — `listSightings` applies it to the rows, and this
     * set never reaches the page: an occurrence whose only sighting the
     * reader may not see contributes no row, no count and no curve
     * distinguishable from an un-sighted one.
     *
     * The table name comes off the `Sighting` model rather than being
     * spelled here, so the model that owns the data still owns where it
     * lives.
     *
     * Soft-deleted occurrences are included, because
     * `buildConditions()` includes them; the caller filters them before
     * `listSightings`, which forces `deleted = 0` on its own re-fetch.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array The same shape as occurrenceIdsFor
     */
    public function sightedOccurrenceIdsFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $sightings = ClassRegistry::init('Sighting');
        $rows = $attributes->find('all', array(
            'fields' => array(
                'Attribute.id',
                'Attribute.event_id',
                'Attribute.type',
                'Attribute.timestamp',
                // Both ends of the span, because the Timeline's seen
                // lane is the one consumer that needs the low end and
                // it needs it for the same rows this already reads.
                'Attribute.first_seen',
                'Attribute.last_seen',
                'Attribute.deleted',
                // Who filed it, for the self-sighting exclusion: a
                // sighting is only self-confirmation if it came from
                // the organisation that reported the occurrence, and
                // the join this already makes for the ACL has the
                // column.
                'Event.orgc_id',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
            'joins' => array(array(
                'table' => $sightings->table,
                'alias' => 'ValueSighting',
                'type' => 'INNER',
                'conditions' => array(
                    'ValueSighting.attribute_id = Attribute.id',
                ),
            )),
            'group' => array('Attribute.id'),
        ));
        return self::keyById($rows);
    }

    /**
     * The value's occurrences as an id set, with the two columns any
     * value-scoped aggregate needs to label its own result.
     *
     * §14.3 of the contract sketches this as a bare list of ids, and
     * phase 22 declined to build it because its aggregate already had
     * the ids from its row fetch. Phase 23 is the caller it was waiting
     * for, and it needs slightly more than ids: a sighting is filed
     * against one occurrence, so the list panel's `Reported against`
     * column is that occurrence's event and type. Re-fetching those
     * would be a second resolution of the same value, and two
     * resolutions can disagree.
     *
     * `fields` keeps it to six columns rather than the whole row. It
     * takes `limit` and `order` because its callers cap it: reading
     * every occurrence a value has is what `occurrenceSummaryFor` is
     * for, and doing it by materialising rows cost seconds on the two
     * heaviest values on the instance.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor, plus `limit`/`order`
     * @return array attribute id => event_id, type, timestamp,
     *               last_seen, deleted, and the containing object's
     *               id and span
     */
    public function occurrenceIdsFor(array $user, $value,
        array $options = array()
    ) {
        $params = array(
            'conditions' => $this->conditionsFor($value, $options),
            'fields' => array(
                'Attribute.id',
                'Attribute.event_id',
                'Attribute.type',
                'Attribute.timestamp',
                // Both ends of the span, because the Timeline's seen
                // lane is the one consumer that needs the low end and
                // it needs it for the same rows this already reads.
                'Attribute.first_seen',
                'Attribute.last_seen',
                'Attribute.deleted',
                // Which object the row sits in, so the seen lane can
                // tell an occurrence that has no span of its own from
                // one whose object has none either.
                'Attribute.object_id',
            ),
            /*
             * buildConditions() names Event.* and Object.* directly, so
             * both have to be joined for the ACL to be expressible —
             * and the join was all this asked for until the seen lane
             * needed the object's own span.
             *
             * **Named fields, for the reason `occurrencesFor` records
             * one screen down**: with an explicit `fields` list on the
             * attribute, Containable selects nothing of its own from a
             * `belongsTo` unless it is told what to take. A bare
             * `contain` joins both tables, satisfies the ACL, and hands
             * back rows carrying no `Object` columns at all — which is
             * why the object's `first_seen` was unreachable here for
             * four phases while the table was already in the query.
             */
            'contain' => array(
                'Event' => array('fields' => array('Event.id')),
                'Object' => array('fields' => array(
                    'Object.id',
                    'Object.first_seen',
                    'Object.last_seen',
                )),
            ),
        );
        foreach (array('limit', 'page', 'order') as $key) {
            if (isset($options[$key])) {
                $params[$key] = $options[$key];
            }
        }
        return self::keyById(
            $this->attributes()->fetchAttributesSimple($user, $params)
        );
    }

    /**
     * The shape both id-set accessors return, keyed by
     * attribute id.
     *
     * @param array $rows
     * @return array
     */
    private static function keyById(array $rows)
    {
        $set = array();
        foreach ($rows as $row) {
            $set[(int)$row['Attribute']['id']] = array(
                'event_id' => (int)$row['Attribute']['event_id'],
                'type' => $row['Attribute']['type'],
                'timestamp' => (int)$row['Attribute']['timestamp'],
                'first_seen' => $row['Attribute']['first_seen'] ?? null,
                'last_seen' => $row['Attribute']['last_seen'] ?? null,
                'deleted' => !empty($row['Attribute']['deleted']),
                /*
                 * The object's id and its own span, null on a loose
                 * attribute and on every caller that did not ask the
                 * `Object` association for its columns. Both accessors
                 * share this shape, and only one of them names those
                 * fields — so absent has to mean *not asked for* rather
                 * than *not set*, which is why every read of these is
                 * guarded rather than assumed.
                 */
                'object_id' => isset($row['Attribute']['object_id'])
                    ? (int)$row['Attribute']['object_id']
                    : 0,
                'object_first_seen' => $row['Object']['first_seen'] ?? null,
                'object_last_seen' => $row['Object']['last_seen'] ?? null,
                /*
                 * Who reported it, for the self-sighting exclusion, and
                 * guarded under the same rule as the object columns
                 * above: only `sightedOccurrenceIdsFor` asks the query
                 * for it, so zero here means *not asked for* and the
                 * exclusion treats it as a comparison it cannot make.
                 */
                'orgc_id' => isset($row['Event']['orgc_id'])
                    ? (int)$row['Event']['orgc_id']
                    : 0,
            );
        }
        return $set;
    }

    /**
     * The value's occurrences, as `fetchAttributes` shapes them.
     *
     * `fetchAttributesSimple` rather than `fetchAttributes`, and the
     * difference matters twice. `fetchAttributes` forces
     * `Attribute.deleted = 0` for anyone without `perm_sync`, which
     * would make the soft-deleted occurrences this tab reveals
     * unreachable for every ordinary user; and it forces
     * `Attribute.object_id = 0` unless `flatten`, which would drop
     * every occurrence sitting inside an object — the rows the Context
     * column exists to describe.
     *
     * @param array $user
     * @param string $value
     * @param array $options `types`, plus `limit` and `order` passed to
     *                       the fetcher
     * @return array
     */
    public function occurrencesFor(array $user, $value,
        array $options = array()
    ) {
        $params = array(
            'conditions' => $this->conditionsFor($value, $options),
            'contain' => array(
                'Event',
                'Object',
                // The name behind a distribution-4 row's badge.
                'SharingGroup',
                // Carries tag_id only; attachTagsToAttributes() turns
                // those into the tag records the chips are drawn from.
                'AttributeTag',
            ),
        );
        foreach (array('limit', 'page', 'order') as $key) {
            if (isset($options[$key])) {
                $params[$key] = $options[$key];
            }
        }
        return $this->attributes()->fetchAttributesSimple($user, $params);
    }

    /**
     * What analysts wrote in the `comment` column of this value's
     * occurrences, one row per distinct sentence.
     *
     * **A grouped aggregate rather than a row fetch, and the instance
     * is what settles it.** `94.98.224.81` carries *Xtreme RAT botnet
     * C2 server (confidence level: 100%)* on **1,459** occurrences
     * across five events — one sentence somebody wrote once and a bulk
     * import stamped onto every row. A capped row read would have
     * rendered 300 identical lines and then understated the count by a
     * thousand; this returns the sentence once with the true number
     * beside it. `147.185.221.29` is the same shape smaller: 39
     * commented rows, 11 distinct sentences.
     *
     * **Grouped by the sentence *and* its creating organisation.** A
     * comment has no author column — it is a field on the attribute, so
     * the only attribution it has is the event's `orgc_id` — and two
     * organisations writing the same sentence are two statements, not
     * one made twice. Grouping on the text alone would have merged them
     * under whichever org the aggregate happened to keep.
     *
     * The grouping is byte-exact: `attributes.comment` is
     * `utf8mb3_bin`, so `Blocked` and `blocked` are two rows here. That
     * is the honest reading — this panel reports what was written, and
     * a case fold would be the page deciding two people wrote the same
     * thing.
     *
     * **`limit` bounds the groups drawn, not the work done.** MariaDB
     * reads and groups every matching row before the limit applies, so
     * a caller asking for one more group than it means to draw learns
     * there is a remainder for free rather than paying a second
     * `COUNT`. The counts inside each group are over every row, capped
     * or not.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor, plus `limit`
     * @return array [['comment' => string, 'orgc_id' => int,
     *     'occurrences' => int, 'events' => int, 'first_at' => int,
     *     'last_at' => int, 'event_id' => int, 'deleted' => int], …]
     *     newest-written first
     */
    public function commentsFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        /*
         * `!=` rather than a `LENGTH` test, because a comment of
         * whitespace is a comment somebody typed and this panel is not
         * the place to decide it was a mistake. `NULL` fails `!=` in
         * SQL, which is the wanted answer for a column MISP leaves
         * unset.
         */
        $conditions['AND'][] = array('Attribute.comment !=' => '');
        $params = array(
            'fields' => array(
                'Attribute.comment',
                'Event.orgc_id',
                'COUNT(DISTINCT Attribute.id) AS occurrences',
                'COUNT(DISTINCT Event.id) AS events',
                /*
                 * `Attribute.timestamp` and deliberately not
                 * `OBSERVED_AT`. That chain reads `last_seen` first
                 * because it answers *when was this value observed*,
                 * and a comment is not an observation — it is text in a
                 * column, and the only date the column has is the row
                 * write that last saved it. Reporting a declared
                 * sighting date as when somebody wrote a sentence would
                 * be the page inventing an authorship date it does not
                 * have.
                 */
                'MIN(Attribute.timestamp) AS first_at',
                'MAX(Attribute.timestamp) AS last_at',
                /*
                 * One event to open, and which one is a decision rather
                 * than whichever the aggregate kept: the event of the
                 * group's most recent occurrence, so the link lands
                 * where the sentence was last written. `GROUP_CONCAT`
                 * truncates at `group_concat_max_len` from the tail and
                 * this reads the head, so a group spanning a thousand
                 * events answers as exactly as one spanning two.
                 */
                'SUBSTRING_INDEX(GROUP_CONCAT(Event.id ORDER BY '
                    . 'Attribute.timestamp DESC), \',\', 1) AS event_id',
                /*
                 * Whether *every* row carrying this sentence is
                 * soft-deleted. `MIN` and not `MAX`: a sentence still
                 * live on one occurrence is live, and the panel marks
                 * only the ones nothing carries any more.
                 */
                'MIN(Attribute.deleted) AS deleted',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
            'group' => array('Attribute.comment', 'Event.orgc_id'),
            'order' => array('last_at DESC'),
        );
        if (isset($options['limit'])) {
            $params['limit'] = $options['limit'];
        }
        $out = array();
        foreach ($attributes->find('all', $params) as $row) {
            $out[] = array(
                'comment' => (string)$row['Attribute']['comment'],
                'orgc_id' => (int)$row['Event']['orgc_id'],
                'occurrences' => (int)$row[0]['occurrences'],
                'events' => (int)$row[0]['events'],
                'first_at' => (int)$row[0]['first_at'],
                'last_at' => (int)$row[0]['last_at'],
                'event_id' => (int)$row[0]['event_id'],
                'deleted' => !empty($row[0]['deleted']),
            );
        }
        return $out;
    }

    /**
     * How many of this value's occurrences carry a comment at all.
     *
     * The denominators the grouped read above cannot state. It returns
     * at most a capful of sentences; this says how many there are, how
     * many rows carry one and across how many events — the three
     * numbers the panel's header is a sentence about, and the ones a
     * capped list must not be asked for.
     *
     * `COUNT(DISTINCT comment, orgc_id)` is the same pair the grouped
     * read groups on, so the total can never disagree with the rows
     * drawn under it. It rides along in the aggregate the occurrence
     * count needs anyway, which is why the exact number is affordable
     * where *more than fifty* would have been the alternative.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array `comments`, `occurrences`, `events`
     */
    public function commentSummaryFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.comment !=' => '');
        $row = $attributes->find('first', array(
            'fields' => array(
                'COUNT(DISTINCT Attribute.comment, Event.orgc_id)'
                    . ' AS comments',
                'COUNT(DISTINCT Attribute.id) AS occurrences',
                'COUNT(DISTINCT Event.id) AS events',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
        ));
        return array(
            'comments' => (int)($row[0]['comments'] ?? 0),
            'occurrences' => (int)($row[0]['occurrences'] ?? 0),
            'events' => (int)($row[0]['events'] ?? 0),
        );
    }

    /*
     * ------------------------------------------------------------------
     * The Relationships tab's queries.
     *
     * These are here rather than in `ValueIntelligence` for one reason and it
     * is §14.4's tier 3: *any query that reaches attribute value storage
     * outside `Value`* is forbidden. Every method below either names
     * `value1`/`value2` or selects `Attribute.value`, which is the
     * virtual field over the same two columns
     * (`MispAttribute.php:55`) — so all of them are value storage and
     * all of them belong to the seam.
     *
     * That is a real cost: this file was to stay small, and the tab adds
     * five methods to it. The alternative was worse. A neighbour
     * aggregate written in `ValueIntelligence` would put the column names in
     * a second file, and the whole of §14.3 is the promise that when the
     * value table lands, **one** file changes.
     * ------------------------------------------------------------------
     */

    /**
     * The MISP types this value is stored under, most common first.
     *
     * The near-match section asks the engines about a type rather than
     * about a value — CIDR containment runs for `ip-dst` and not for
     * `sha256` — so it needs to know what this value *is* before it can
     * say which engine declines it. It is the viewer's own: a value
     * with no occurrence the reader may see correctly has no type at
     * all rather than a guessed one.
     *
     * `type` is the stored attribute type, which is what the occurrence
     * table filters on. `as` says which half of a composite the value
     * sits in, by that half's type: `443` found in `8.8.8.8|443` is a
     * `port`, not an `ip-dst|port`. Callers asking what the value *is*
     * fold it with `asTypes()`.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor
     * @return array [['type' => 'ip-dst|port', 'count' => 7,
     *                 'as' => ['port' => 7]], …]
     */
    public function typesFor(array $user, $value, array $options = array())
    {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.deleted' => 0);
        // Folded like the conditions, so a case variant counts as this half
        $ids = ClassRegistry::init('AttributeValue')
            ->resolveCi(array((string)$value))[(string)$value] ?? array();
        $first = empty($ids)
            ? '0'
            : 'Attribute.value1_id IN ('
                . implode(', ', array_map('intval', $ids)) . ')';
        $rows = $attributes->find('all', array(
            'fields' => array(
                'Attribute.type',
                '(' . $first . ') AS first_half',
                'COUNT(DISTINCT Attribute.id) AS occurrences',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
            'group' => array('Attribute.type', 'first_half'),
        ));
        $types = array();
        foreach ($rows as $row) {
            $type = $row['Attribute']['type'];
            $count = (int)$row[0]['occurrences'];
            $as = self::halfType($type, empty($row[0]['first_half']) ? 1 : 0);
            if (!isset($types[$type])) {
                $types[$type] = array(
                    'type' => $type,
                    'count' => 0,
                    'as' => array(),
                );
            }
            $types[$type]['count'] += $count;
            $types[$type]['as'][$as] = $count
                + ($types[$type]['as'][$as] ?? 0);
        }
        usort($types, function ($a, $b) {
            return $b['count'] - $a['count'];
        });
        return $types;
    }

    /**
     * `typesFor()` folded onto the type of the half the value sits in,
     * most common first. `stored` keeps the attribute types behind each
     * entry, for fetching an occurrence of it.
     *
     * @param array $types As typesFor returns
     * @return array [['type' => 'port', 'count' => 9,
     *                 'stored' => ['port', 'ip-dst|port']], …]
     */
    public static function asTypes(array $types)
    {
        $out = array();
        foreach ($types as $type) {
            $halves = isset($type['as'])
                ? $type['as']
                : array($type['type'] => $type['count']);
            foreach ($halves as $as => $count) {
                if (!isset($out[$as])) {
                    $out[$as] = array(
                        'type' => $as,
                        'count' => 0,
                        'stored' => array(),
                    );
                }
                $out[$as]['count'] += $count;
                $out[$as]['stored'][] = $type['type'];
            }
        }
        usort($out, function ($a, $b) {
            return $b['count'] - $a['count'];
        });
        return $out;
    }

    /**
     * The attribute types a value of this type can be stored under:
     * the type itself and every composite with a half of that type.
     *
     * @param string $type
     * @return array
     */
    public function storedTypesOf($type)
    {
        $stored = array($type);
        $composites = $this->attributes()->getCompositeTypes();
        foreach ($composites as $composite) {
            if (self::halfType($composite, 0) === $type
                || self::halfType($composite, 1) === $type
            ) {
                $stored[] = $composite;
            }
        }
        return $stored;
    }

    /**
     * The type of one half of a composite type; a plain type is its
     * own half.
     *
     * @param string $type
     * @param int $half 0 for value1, 1 for value2
     * @return string
     */
    public static function halfType($type, $half)
    {
        if ($type === 'malware-sample') {
            $type = 'filename|md5';
        }
        $parts = explode('|', $type);
        if (count($parts) !== 2) {
            return $type;
        }
        $part = $parts[$half ? 1 : 0];
        if ($part === 'ip') {
            return 'ip-dst';
        }
        if ($part === 'value') {
            return 'text';
        }
        return $part;
    }

    /**
     * The events this value occurs in, newest occurrence first.
     *
     * One grouped aggregate rather than a row fetch, for the reason
     * `occurrenceSummaryFor` gives: the answer is one number per event
     * and materialising 48,255 rows to derive 1,844 of them is seconds
     * rather than milliseconds.
     *
     * The order is what makes the co-occurrence section's cut
     * defensible. A value in 1,844 events cannot have all of them read,
     * so *which* ones are read has to be a rule a reader would accept,
     * and "the events where this value was seen most recently" is the
     * one a person asking about an indicator today would pick.
     *
     * `flagged` counts the occurrences with `to_ids = 1`: an event in
     * which the reporter marked this value for detection, which is what
     * lets the event's own attribution reach it.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor, plus `limit`
     * @return array event id => ['occurrences' => int, 'last' => int,
     *               'flagged' => int]
     */
    public function occurrenceEventsFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.deleted' => 0);
        $params = array(
            'fields' => array(
                'Attribute.event_id',
                'COUNT(DISTINCT Attribute.id) AS occurrences',
                'MAX(Attribute.timestamp) AS last_seen',
                'SUM(Attribute.to_ids) AS flagged',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
            'group' => array('Attribute.event_id'),
            'order' => array('last_seen DESC'),
        );
        if (isset($options['limit'])) {
            $params['limit'] = $options['limit'];
        }
        $events = array();
        foreach ($attributes->find('all', $params) as $row) {
            $events[(int)$row['Attribute']['event_id']] = array(
                'occurrences' => (int)$row[0]['occurrences'],
                'last' => (int)$row[0]['last_seen'],
                'flagged' => (int)$row[0]['flagged'],
            );
        }
        return $events;
    }

    /**
     * The labels this value's own occurrences carry.
     *
     * The tightest way a label reaches a value: not *an event
     * mentioning APT29 contained this address*, but *this address, in
     * this event, is marked APT29*. Both the neighbourhood card and the
     * co-occurrence fold print the difference on the row, so they have
     * to be able to tell them apart.
     *
     * **Galaxy and taxonomy tags together, and `is_galaxy` decides
     * which is which downstream.** They live in one table and one join,
     * so asking for one of them was costing the other a second query
     * once the co-occurrence fold started reading both — the reason
     * §10.2 gives for one table of neighbours rather than two reads.
     * A galaxy tag is still worthless until `fetchGalaxyClusters` says
     * the viewer may know its cluster exists; that ruling belongs to
     * the caller, and the flag is what lets it find the names to ask
     * about.
     *
     * **Grouped, not fetched.** A value can occur 48,255 times, and the
     * answer is a handful of names either way — so this aggregates in
     * SQL rather than materialising occurrences and folding them in
     * PHP. `attribute_tags` is joined explicitly because it is a
     * `hasMany` that would otherwise cost its own query per id, and the
     * answer needs no attribute rows at all.
     *
     * The colour and the flag join the grouping rather than riding
     * along outside it: they are constant per tag, but MySQL under
     * `ONLY_FULL_GROUP_BY` recognises that only through a key it can
     * see, and a selected column it cannot prove constant is an error
     * rather than a guess.
     *
     * The event scope is the caller's, and it is what makes the ACL
     * argument short: those ids came from `occurrenceEventsFor`, so the
     * events are ones this viewer may read. `buildConditions($user)` is
     * still applied, because an attribute inside a readable event can
     * be org-only — and applying it is what obliges the `Object` join
     * below, since those conditions name `Object.distribution` directly
     * for anybody who is not a site admin.
     *
     * @param array $user
     * @param string $value
     * @param array $eventIds Events the caller has already resolved
     * @param array $options As conditionsFor
     * @return array tag name => `tag` (id, name, colour, is_galaxy,
     *     local) and `events` (event id => `occurrences`, `last`)
     */
    public function ownTagsFor(array $user, $value,
        array $eventIds, array $options = array()
    ) {
        if (empty($eventIds)) {
            return array();
        }
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array(
            'Attribute.event_id' => array_values($eventIds),
            'Attribute.deleted' => 0,
        );
        $rows = $attributes->find('all', array(
            'fields' => array(
                'Tag.id',
                'Tag.name',
                'Tag.colour',
                'Tag.is_galaxy',
                'Attribute.event_id',
                'COUNT(DISTINCT Attribute.id) AS occurrences',
                /*
                 * So a label row's **Last together** reads the same
                 * clock as a value row's. Free — the group is already
                 * over these attributes, and the alternative was the
                 * carrying event's stamp, which is the day the report
                 * moved rather than the day this occurrence did.
                 */
                'MAX(Attribute.timestamp) AS last',
                /*
                 * **A tag is local only where every occurrence carrying
                 * it is**, hence `MIN` and not `MAX`. `local` means *not
                 * shared*, so the two errors are not symmetric: marking
                 * a shared tag local understates where it has already
                 * travelled, which is the direction that misleads. A
                 * tag applied locally on one occurrence and globally on
                 * another has travelled, and reads as global here.
                 *
                 * An aggregate rather than a grouped column, so the
                 * group stays what it was and no existing caller sees a
                 * row split in two.
                 */
                'MIN(AttributeTag.local) AS local',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            // Both, as everywhere else here: the ACL is not expressible
            // without them. `Event` alone threw for every reader who was
            // not a site admin, and took the whole panel down with it.
            'contain' => array('Event', 'Object'),
            'joins' => array(
                array(
                    'table' => 'attribute_tags',
                    'alias' => 'AttributeTag',
                    'type' => 'INNER',
                    'conditions' => array(
                        'AttributeTag.attribute_id = Attribute.id',
                    ),
                ),
                array(
                    'table' => 'tags',
                    'alias' => 'Tag',
                    'type' => 'INNER',
                    'conditions' => array(
                        'Tag.id = AttributeTag.tag_id',
                    ),
                ),
            ),
            'group' => array(
                'Tag.id',
                'Tag.name',
                'Tag.colour',
                'Tag.is_galaxy',
                'Attribute.event_id',
            ),
        ));
        $found = array();
        foreach ($rows as $row) {
            $name = $row['Tag']['name'];
            $eventId = (int)$row['Attribute']['event_id'];
            if (!isset($found[$name])) {
                $found[$name] = array(
                    'tag' => array(
                        'id' => (int)$row['Tag']['id'],
                        'name' => $name,
                        'colour' => $row['Tag']['colour'],
                        'is_galaxy' => !empty($row['Tag']['is_galaxy']),
                        'local' => true,
                    ),
                    'events' => array(),
                );
            }
            if (empty($row[0]['local'])) {
                $found[$name]['tag']['local'] = false;
            }
            $found[$name]['events'][$eventId] = array(
                'occurrences' => (int)$row[0]['occurrences'],
                'last' => (int)$row[0]['last'],
            );
        }
        return $found;
    }

    /**
     * Which of a few known tags this value's own occurrences carry, per
     * event — the occurrence half of what a reporter stated about its
     * claim.
     *
     * `ownTagsFor`'s join narrowed to the tag ids asked about, and to
     * global tags only: a local tag is the host instance's note on
     * somebody else's report, not the reporter's statement.
     *
     * @param array $user
     * @param string $value
     * @param array $eventIds Events the caller has already resolved
     * @param array $tagIds
     * @param array $options As conditionsFor
     * @return array event id => [tag id, …]
     */
    public function statementTagsFor(array $user, $value,
        array $eventIds, array $tagIds, array $options = array()
    ) {
        if (empty($eventIds) || empty($tagIds)) {
            return array();
        }
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array(
            'Attribute.event_id' => array_values($eventIds),
            'Attribute.deleted' => 0,
            'AttributeTag.tag_id' => array_values($tagIds),
            'AttributeTag.local' => 0,
        );
        $rows = $attributes->find('all', array(
            'fields' => array('Attribute.event_id', 'AttributeTag.tag_id'),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
            'joins' => array(
                array(
                    'table' => 'attribute_tags',
                    'alias' => 'AttributeTag',
                    'type' => 'INNER',
                    'conditions' => array(
                        'AttributeTag.attribute_id = Attribute.id',
                    ),
                ),
            ),
            'group' => array('Attribute.event_id', 'AttributeTag.tag_id'),
        ));
        $found = array();
        foreach ($rows as $row) {
            $found[(int)$row['Attribute']['event_id']][] =
                (int)$row['AttributeTag']['tag_id'];
        }
        return $found;
    }

    /**
     * The objects this value sits in, newest occurrence first.
     *
     * The sibling section's input. Grouped for the same reason as
     * `occurrenceEventsFor`, and capped by the same argument: `0.0.0.0`
     * sits in 32,921 distinct objects on the verification instance, so
     * a section that read them all would be the slowest thing on the
     * page by two orders of magnitude.
     *
     * **And which relation the object files this value under**, which
     * is what turns a sibling into a labelled edge: `passive-dns ·
     * rrname → rdata` needs both ends, and only the far end is on the
     * sibling row. `MIN()` rather than the bare column, so the group is
     * legal under `ONLY_FULL_GROUP_BY` as well as without it; a value
     * filed twice in one object under two relations is rare enough that
     * naming the first alphabetically beats a second query.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor, plus `limit`
     * @return array object id => ['last' =>, 'relation' =>, 'name' =>]
     */
    public function occurrenceObjectIdsFor(array $user, $value,
        array $options = array()
    ) {
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->conditionsFor($value, $options);
        $conditions['AND'][] = array('Attribute.object_id >' => 0);
        $params = array(
            'fields' => array(
                'Attribute.object_id',
                'MAX(Attribute.timestamp) AS last_seen',
                'MIN(Attribute.object_relation) AS our_relation',
                /*
                 * The template's name, so a mark drawn from an object
                 * can say which kind of object it came from — `MIN()`
                 * for the same `ONLY_FULL_GROUP_BY` reason as the
                 * relation above, and free here: `Object` is already
                 * joined for the ACL.
                 */
                'MIN(Object.name) AS object_name',
            ),
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Event', 'Object'),
            'group' => array('Attribute.object_id'),
            'order' => array('last_seen DESC'),
        );
        if (isset($options['limit'])) {
            $params['limit'] = $options['limit'];
        }
        $objects = array();
        foreach ($attributes->find('all', $params) as $row) {
            $objects[(int)$row['Attribute']['object_id']] = array(
                'last' => (int)$row[0]['last_seen'],
                'relation' => $row[0]['our_relation'] === null
                    ? ''
                    : $row[0]['our_relation'],
                'name' => $row[0]['object_name'] === null
                    ? ''
                    : $row[0]['object_name'],
            );
        }
        return $objects;
    }

    /**
     * The `datetime` attributes of the objects this value sits in —
     * the dates an object template records in its own fields, as
     * opposed to the `first_seen`/`last_seen` columns MISP keeps beside
     * every attribute and object.
     *
     * **A third place a date about this value can live**, and the one
     * the page reached only sideways: `ValueRelationTool::dated` folds
     * these into the Relationships tab's *Dated relations*, but it
     * needs two of them plus a linking value in the same object,
     * because what it dates is a *relation between two values*. What
     * this returns dates the object itself, so one row is enough and no
     * far value is required.
     *
     * The vocabulary is the template's, not MISP's, and it is not all
     * one notion: on the verification instance the `datetime` rows are
     * `time_generated` (32,892), `first-seen` (11,318), `last-seen`
     * (11,193), `last-submission` (6,744), `time_first`/`time_last`
     * (665 each) and a long tail down through `compilation-timestamp`,
     * `creation-date` and `send-date`. So a caller may not merge these
     * into a *seen* claim — the relation has to travel with the row and
     * be shown, which is why `object_relation` is in the field list.
     *
     * ACL'd through `fetchAttributesSimple` and not by the object's
     * permission: a sibling attribute carries its own distribution, so
     * an object a reader may open can still hold a row they may not.
     *
     * **Newest first, and the ordering is this file's rather than the
     * caller's.** A caller asking for `Attribute.value1 DESC` would be
     * spelling the column name outside this seam, which §14.3 forbids —
     * and the sort is not incidental: the date lives in `value1` as a
     * string, and ISO 8601 sorts lexically the way it sorts
     * chronologically, which is the property that lets a `varchar` date
     * column be ordered at all. A value table landing later has to keep
     * that property or give this method a real column.
     *
     * @param array $user
     * @param array $objectIds The objects this value sits in
     * @param array $options `limit` reaches the fetcher
     * @return array fetchAttributesSimple rows
     */
    public function objectDatesFor(array $user, array $objectIds,
        array $options = array()
    ) {
        if (empty($objectIds)) {
            return array();
        }
        $params = array(
            'conditions' => array(
                'Attribute.object_id' => array_values($objectIds),
                'Attribute.type' => self::DATE_TYPE,
                'Attribute.deleted' => 0,
            ),
            'fields' => array(
                'Attribute.id',
                'Attribute.event_id',
                'Attribute.object_id',
                'Attribute.object_relation',
                'Attribute.value',
                'Attribute.timestamp',
            ),
            'contain' => self::CONTEXT_FIELDS,
            'order' => array('Attribute.value' => 'DESC'),
        );
        if (isset($options['limit'])) {
            $params['limit'] = $options['limit'];
        }
        $out = array();
        foreach ($this->attributes()->fetchAttributesSimple($user, $params)
            as $row
        ) {
            $out[] = array(
                'id' => (int)$row['Attribute']['id'],
                'event_id' => (int)$row['Attribute']['event_id'],
                'object_id' => (int)$row['Attribute']['object_id'],
                'relation' => $row['Attribute']['object_relation'] === null
                    ? ''
                    : $row['Attribute']['object_relation'],
                'at' => $row['Attribute']['value'],
                'object' => isset($row['Object']['name'])
                    ? $row['Object']['name']
                    : '',
            );
        }
        return $out;
    }

    /**
     * The same rows as a per-day tally, so the lane's spine can be
     * binned over all of them while the chronology carries only the
     * newest cap-many.
     *
     * §16.1's rule, and this is the reader that needs it most: a value
     * in 32,922 objects reaches **32,893** `datetime` rows on the
     * verification instance, so a lane tallying what it drew would draw
     * eleven years of dates as whichever fortnight the cap left it.
     *
     * The day comes from the left ten characters of the stored value
     * rather than from a date function, because the column is a string:
     * MISP validates a `datetime` attribute to ISO 8601, so the first
     * ten characters are its calendar day in every row and the grouping
     * needs no parse. A row whose value is not a date groups under
     * whatever it starts with and is dropped by the caller's own parse,
     * which is the same rule the rows take.
     *
     * **Grouped by relation as well as by day**, and the second half is
     * what lets the lane name its own vocabulary honestly. The rows it
     * draws are the newest cap-many, so tallying relations from those
     * would report `0.0.0.0`'s eleven kinds of date as whichever one
     * happens to be newest — and it is not a close call there:
     * `time_generated` is 32,892 of its 32,893 rows.
     *
     * @param array $user
     * @param array $objectIds The objects this value sits in
     * @return array ['by_day' => day => n, 'by_relation' => rel => n,
     *               'total' =>, 'first' =>, 'last' =>]
     */
    public function objectDateCountsFor(array $user, array $objectIds)
    {
        $empty = array(
            'by_day' => array(),
            'by_relation' => array(),
            'total' => 0,
            'first' => null,
            'last' => null,
        );
        if (empty($objectIds)) {
            return $empty;
        }
        $attributes = $this->attributes();
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = array(
            'Attribute.object_id' => array_values($objectIds),
            'Attribute.type' => self::DATE_TYPE,
            'Attribute.deleted' => 0,
        );
        $rows = $attributes->find('all', array(
            'conditions' => $conditions,
            'fields' => array(
                'LEFT(DateValue.value, 10) AS day',
                'Attribute.object_relation',
                'COUNT(*) AS n',
            ),
            'joins' => array(array(
                'table' => 'attribute_values',
                'alias' => 'DateValue',
                'type' => 'INNER',
                'conditions' => array('DateValue.id = Attribute.value1_id'),
            )),
            'group' => array('day', 'Attribute.object_relation'),
            'order' => array('day' => 'ASC'),
            'recursive' => -1,
            // Named for the ACL, exactly as the aggregate one screen up
            // does: `buildConditions` spells both tables.
            'contain' => array('Event', 'Object'),
        ));
        $out = $empty;
        foreach ($rows as $row) {
            $day = $row[0]['day'];
            if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)$day)) {
                continue;
            }
            $n = (int)$row[0]['n'];
            $relation = $row['Attribute']['object_relation'] === null
                ? ''
                : $row['Attribute']['object_relation'];
            $out['by_day'][$day] = $n + (isset($out['by_day'][$day])
                ? $out['by_day'][$day]
                : 0);
            $out['by_relation'][$relation] = $n + (
                isset($out['by_relation'][$relation])
                    ? $out['by_relation'][$relation]
                    : 0
            );
            $out['total'] += $n;
            if ($out['first'] === null || $day < $out['first']) {
                $out['first'] = $day;
            }
            if ($out['last'] === null || $day > $out['last']) {
                $out['last'] = $day;
            }
        }
        // Commonest first, because the lane names only its head.
        arsort($out['by_relation']);
        return $out;
    }

    /**
     * The value's occurrences as UUIDs, which is how analyst data
     * addresses them.
     *
     * `Relationship` hangs off an `object_uuid`, never off an id, so
     * the asserted section's lookup is a UUID set and not the integer
     * set every other panel on this page uses. Keeping the two
     * accessors apart rather than adding `uuid` to `occurrenceIdsFor`
     * keeps those panels' cost visible: both callers cap their own set,
     * and every other panel on the page reads the integer accessor and
     * pays nothing for a column it has no use for. The Timeline's
     * analyst lane is the second caller — same shape, same reason, and
     * its cap is `ValueIntelligence::TIMELINE_ANALYST_CAP`.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor, plus `limit`/`order`
     * @return array uuid => ['id' =>, 'event_id' =>, 'type' =>]
     */
    public function occurrenceUuidsFor(array $user, $value,
        array $options = array()
    ) {
        $params = array(
            'conditions' => $this->conditionsFor($value, $options),
            'fields' => array(
                'Attribute.id',
                'Attribute.uuid',
                'Attribute.event_id',
                // Zero on a plain attribute, which is how a claim
                // about "the parent object" is told from no parent.
                'Attribute.object_id',
                'Attribute.type',
                /*
                 * Named explicitly, because `fields` and Containable
                 * together select exactly what is listed: the `Event`
                 * and `Object` joins are already in the query — the
                 * ACL needs them — but their columns are not fetched
                 * unless asked for. Every earlier caller read only
                 * `Attribute.*`, so the omission cost nothing until a
                 * container's uuid was wanted.
                 */
                'Event.uuid',
                'Object.uuid',
                /*
                 * The object's name, for the one caller that has to
                 * print what the occurrence sits in rather than only
                 * match against it: the Analyst tab's attachment chip
                 * says *network-connection in #1284*, and a uuid is
                 * not a thing to show a reader. Free — the join is
                 * already here for the uuid beside it.
                 */
                'Object.name',
            ),
            'contain' => array('Event', 'Object'),
        );
        foreach (array('limit', 'order') as $key) {
            if (isset($options[$key])) {
                $params[$key] = $options[$key];
            }
        }
        $set = array();
        $rows = $this->attributes()->fetchAttributesSimple($user, $params);
        foreach ($rows as $row) {
            $set[$row['Attribute']['uuid']] = array(
                'id' => (int)$row['Attribute']['id'],
                'event_id' => (int)$row['Attribute']['event_id'],
                'type' => $row['Attribute']['type'],
                /*
                 * The containers this occurrence sits in, by uuid,
                 * because an analyst's claim can be written about any
                 * of the three and `relationships` names its ends by
                 * uuid alone. Taken from the records this fetch
                 * already contains rather than looked up again: the
                 * `Event` and `Object` joins above are what make the
                 * asserted section able to ask about a container
                 * without a second query per occurrence.
                 *
                 * `object_uuid` is null for a plain attribute —
                 * `object_id` is 0 there, and a claim can no more be
                 * written about object 0 than about a missing event.
                 */
                'event_uuid' => isset($row['Event']['uuid'])
                    ? $row['Event']['uuid']
                    : null,
                'object_uuid' => empty($row['Attribute']['object_id'])
                    || empty($row['Object']['uuid'])
                        ? null
                        : $row['Object']['uuid'],
                'object_name' => empty($row['Attribute']['object_id'])
                    || empty($row['Object']['name'])
                        ? null
                        : $row['Object']['name'],
            );
        }
        return $set;
    }

    /**
     * Every proposal that is about this value, from either direction.
     *
     * **Two scopes, and the instance holds exactly one row that proves
     * both are needed.** Proposal 12 proposes `2.2.2.3` against
     * attribute 1495259, which holds `2.2.2.2`:
     *
     * - `2.2.2.2` reaches it only through the *target*, and what it
     *   says there is *someone proposed replacing this*.
     * - `2.2.2.3` reaches it only through the proposal's own columns,
     *   and what it says there is *someone proposed this as a
     *   replacement*.
     *
     * Sixteen of the other seventeen attribute-targeted proposals carry
     * the same value as their target and are reached both ways, which
     * is why the union is deduplicated by id rather than concatenated.
     *
     * **Two statements and not one `OR`.** The two scopes sit on
     * different columns of different tables — `ShadowAttribute.value1`
     * and `Attribute.value1` — and an `OR` spanning them is the shape
     * that cost the co-occurrence panel a full table scan. Each half
     * here matches a prefix index of its own: `shadow_attributes` has
     * `value1(255)` and `value2(255)`, the same shape `attributes`
     * carries.
     *
     * **The target scope is a join and not an id list.** `old_id` is a
     * `belongsTo` to `MispAttribute`, so `ShadowAttribute::buildConditions`
     * has already joined `Attribute` in order to express its own ACL —
     * which means the value predicate can be written against that join
     * for nothing. The alternative was `old_id IN (occurrence ids)`,
     * and on `443` that is an `IN` list of 48,255 integers.
     *
     * **The gate is MISP's own**, `ShadowAttribute::buildConditions`,
     * which is what `ShadowAttributesController::index` uses. It is not
     * the attribute ACL with an extra clause: `value-intelligence-coverage.md`
     * §2.2 found that a standalone proposal (`old_id = 0`) is OR'd past
     * the whole attribute-and-object distribution test, because there is
     * no attribute to test, and is therefore gated by **event visibility
     * alone**. That is looser than the occurrence fetcher, and it is
     * MISP's rule rather than this page's — so it is applied as MISP
     * wrote it and stated here rather than tightened silently.
     *
     * Soft-deleted proposals are kept. A withdrawn proposal is still a
     * dated thing that happened to this value, and the row says so —
     * unlike the co-occurrence panel, whose subject is what the value
     * currently sits beside.
     *
     * **`reach` narrows to one scope, and costs a query rather than
     * saving one.** The Timeline's lane wants both and pays two
     * statements for them. A caller after *standalone* proposals wants
     * only `proposed`: a proposal with `old_id = 0` has no target
     * attribute for the `target` scope's join to match, so that half
     * can never return one and running it is a second statement whose
     * result is discarded by construction.
     *
     * @param array $user
     * @param string $value
     * @param array $options As conditionsFor, minus `alias`; `reach`
     *                       limits the scopes to `proposed`, `target`
     *                       or both
     * @return array id => the proposal row, its event and its org
     */
    public function proposalsFor(array $user, $value,
        array $options = array()
    ) {
        $model = $this->proposals();
        $fields = array(
            'ShadowAttribute.id',
            'ShadowAttribute.old_id',
            'ShadowAttribute.event_id',
            'ShadowAttribute.type',
            'ShadowAttribute.category',
            'ShadowAttribute.value',
            'ShadowAttribute.comment',
            // What the proposal asks the flag to be. The occurrence
            // table carries an IDS column and a proposed addition
            // renders beside it, so its absence would read as the
            // proposal not having said.
            'ShadowAttribute.to_ids',
            'ShadowAttribute.deleted',
            'ShadowAttribute.proposal_to_delete',
            'ShadowAttribute.timestamp',
            'Org.id',
            'Org.name',
            'Event.id',
            'Event.info',
            // What the target holds today, so a row that changes the
            // value can name both ends of the change. An association's
            // value columns are ids, given its text through `valueKeys`.
            'Attribute.id',
            'Attribute.value1_id',
            'Attribute.value2_id',
        );
        // `alias` is passed on a fresh array and never on the caller's,
        // so a page-wide options array cannot pick it up and re-point
        // some other fetcher at a table it does not read. The target
        // scope names the joined Attribute, which no proposal hook
        // rewrites.
        $scopes = array(
            'proposed' => $this->conditionsFor($value,
                array('alias' => 'ShadowAttribute')),
            'target' => ClassRegistry::init('AttributeValue')
                ->rewriteConditions($this->conditionsFor($value), 'Attribute'),
        );
        if (!empty($options['reach'])) {
            $scopes = array_intersect_key(
                $scopes,
                array_flip((array)$options['reach'])
            );
        }
        $found = array();
        foreach ($scopes as $reach => $scope) {
            $conditions = $model->buildConditions($user);
            $conditions['AND'][] = $scope;
            $rows = $model->find('all', array(
                'fields' => $fields,
                'conditions' => $conditions,
                'recursive' => -1,
                /*
                 * All three, and each for a different job: `Event` and
                 * `Attribute` are what `buildConditions` names, so the
                 * ACL is not expressible without them; `Org` is the
                 * proposing organisation, which every row on the
                 * Timeline is attributed to.
                 */
                'contain' => array('Event', 'Attribute', 'Org'),
                'valueKeys' => array('value'),
            ));
            foreach ($rows as $row) {
                $id = (int)$row['ShadowAttribute']['id'];
                if (isset($found[$id])) {
                    // Reached both ways. The first reach wins, which is
                    // `proposed`, because a proposal naming this value
                    // is about it more directly than one that merely
                    // targets a row holding it.
                    continue;
                }
                $found[$id] = self::proposalRow($row, $reach);
            }
        }
        return $found;
    }

    /**
     * One proposal row, flattened, with the reach that found it.
     *
     * @param array $row One `ShadowAttribute` find record
     * @param string $reach `proposed` or `target`
     * @return array
     */
    private static function proposalRow(array $row, $reach)
    {
        $proposal = $row['ShadowAttribute'];
        $target = isset($row['Attribute']['id'])
            ? $row['Attribute']
            : null;
        return array(
            'id' => (int)$proposal['id'],
            'old_id' => (int)$proposal['old_id'],
            'event_id' => (int)$proposal['event_id'],
            'type' => $proposal['type'],
            'category' => $proposal['category'],
            'value' => (string)$proposal['value'],
            'comment' => $proposal['comment'],
            'to_ids' => !empty($proposal['to_ids']),
            'deleted' => !empty($proposal['deleted']),
            'to_delete' => !empty($proposal['proposal_to_delete']),
            'timestamp' => (int)$proposal['timestamp'],
            'reach' => $reach,
            'org' => isset($row['Org']['name']) && $row['Org']['name'] !== null
                ? $row['Org']['name']
                : __('Unknown organisation'),
            // For callers that link the organisation rather than only
            // naming it; null where the row no longer resolves to one.
            'org_id' => empty($row['Org']['id'])
                ? null
                : (int)$row['Org']['id'],
            'event' => array(
                'id' => (int)$proposal['event_id'],
                'info' => isset($row['Event']['info'])
                    ? $row['Event']['info']
                    : null,
            ),
            /*
             * Null for a standalone proposal, which is the state
             * `old_id = 0` names and the one the whole page is blind to
             * everywhere else (`value-intelligence-coverage.md` §2.2).
             */
            'target' => $target === null ? null : array(
                'id' => (int)$target['id'],
                'value' => (string)$target['value'],
            ),
        );
    }

    /**
     * Everything else in a given set of events, or a given set of
     * objects — the co-occurrence section's rows and the sibling
     * section's rows, which are the same query against two scopes.
     *
     * **Rows and not an aggregate, deliberately, and this is the one
     * place on the page where that is the cheaper answer.** The panel
     * needs six things per neighbour — how many events it shares, when
     * it was last seen with us, which organisations reported it, which
     * events, which object template, what distribution — and five of
     * them are multi-valued per neighbour. As aggregates that is one
     * `GROUP BY` per column, each re-scanning the same rows;
     * `GROUP_CONCAT` would fold them into one query but appears nowhere
     * else in MISP and is not portable. Scanning the rows once and
     * folding in PHP costs one query and gives all six.
     *
     * It is only affordable because **the caller has already bounded
     * the scope**, which is the whole of the co-occurrence design: the
     * event set is chosen and capped before this runs, so the row count
     * is bounded by a number the panel prints rather than by how
     * popular the value is. §14.4's warning about counting in PHP is
     * about tallying *a page* and calling it a total; this folds the
     * complete scope and the panel states what the scope was.
     *
     * `Attribute.value` — the virtual field — rather than the two
     * columns, so a composite neighbour reads `example.com|1.2.3.4` the
     * way it does everywhere else in MISP.
     *
     * Soft-deleted rows are excluded. The Occurrences tab reveals a
     * soft-deleted occurrence *of this value* because the reader is
     * asking about that value's history; a withdrawn attribute in the
     * same event is not something this value co-occurs with.
     *
     * @param array $user
     * @param string $value The value to exclude — our own occurrences
     * @param array $scope `events` or `objects`, a list of ids
     * @param array $options As conditionsFor, plus `limit`
     * @return array fetchAttributesSimple rows
     */
    public function neighbourRowsFor(array $user, $value, array $scope,
        array $options = array()
    ) {
        $ids = isset($scope['events'])
            ? $scope['events']
            : (isset($scope['objects']) ? $scope['objects'] : array());
        if (empty($ids)) {
            return array();
        }
        $column = isset($scope['events'])
            ? 'Attribute.event_id'
            : 'Attribute.object_id';
        $params = array(
            'conditions' => array(
                $column => array_values($ids),
                'Attribute.deleted' => 0,
                'NOT' => $this->conditionsFor($value, $options),
            ),
            'fields' => array(
                'Attribute.id',
                'Attribute.event_id',
                'Attribute.object_id',
                'Attribute.object_relation',
                'Attribute.type',
                'Attribute.category',
                'Attribute.value',
                'Attribute.timestamp',
                'Attribute.distribution',
                'Attribute.sharing_group_id',
                /*
                 * MISP's own record of which attributes in an object
                 * are there to link and which are there to describe.
                 * The Dated relations fold reads it to tell a far value
                 * from a bookkeeping column: in `passive-dns` it is 0
                 * on `rrname` and `rdata` and 1 on `rrtype`, `count`,
                 * `origin` and both timestamps.
                 */
                'Attribute.disable_correlation',
            ),
            'contain' => self::CONTEXT_FIELDS,
        );
        /*
         * The tag join is the caller's to ask for. It is a `hasMany`
         * rather than a join, so it costs its own query over every id
         * in the scope, and the sibling scope renders no tag column.
         */
        if (!empty($options['tags'])) {
            $params['contain']['AttributeTag'] = array();
        }
        if (isset($options['limit'])) {
            $params['limit'] = $options['limit'];
        }
        return $this->attributes()->fetchAttributesSimple($user, $params);
    }

    /**
     * The far ends of a set of object references, as this viewer may
     * see them.
     *
     * A reference names an object or an attribute by id and says
     * nothing about who may read it, so the row is worthless until the
     * thing it points at has been through `buildConditions($user)`.
     * That is the whole job here: an end that resolves to nothing
     * contributes no row to the panel, which is §14.6 applied to
     * somebody else's object.
     *
     * **One query for both kinds**, because they are the same table
     * under two conditions. The object branch takes only the
     * identifying attributes — MISP's own `disable_correlation = 0` —
     * since a far object is named by what it links, not by its
     * bookkeeping columns. The attribute branch takes the row whatever
     * its flag says: a reference that points at one attribute is
     * pointing at that attribute, and hiding it because the template
     * marked it non-correlating would drop the reference entirely.
     *
     * @param array $user
     * @param array $objectIds Far objects to identify
     * @param array $attributeIds Far attributes to resolve
     * @param int $limit
     * @return array fetchAttributesSimple rows
     */
    public function referenceFacesFor(array $user, array $objectIds,
        array $attributeIds, $limit = 500
    ) {
        $branches = array();
        if (!empty($objectIds)) {
            $branches[] = array_merge(
                array('Attribute.object_id' => array_values($objectIds)),
                ValueFieldKind::linkingConditions()
            );
        }
        if (!empty($attributeIds)) {
            $branches[] = array(
                'Attribute.id' => array_values($attributeIds),
            );
        }
        if (empty($branches)) {
            return array();
        }
        return $this->attributes()->fetchAttributesSimple($user, array(
            'conditions' => array(
                'Attribute.deleted' => 0,
                'OR' => $branches,
            ),
            'fields' => array(
                'Attribute.id',
                'Attribute.event_id',
                'Attribute.object_id',
                'Attribute.object_relation',
                'Attribute.type',
                'Attribute.value',
                'Attribute.timestamp',
                'Attribute.distribution',
                'Attribute.sharing_group_id',
            ),
            'contain' => self::CONTEXT_FIELDS,
            'limit' => $limit,
        ));
    }

    /**
     * Occurrences of *other* values — a set of them, given by name.
     *
     * The near-match section's second query. Having decided which
     * network blocks contain this address, it needs each block as an
     * attribute the viewer may actually see, so the row can carry an
     * event, a reporter and a distribution rather than a bare string
     * out of a Redis set. A block nobody may see contributes no row,
     * which is §14.6 applied to somebody else's value.
     *
     * One query for all of them, newest first, and `limit` bounds it —
     * a `/8` block can be an attribute in a hundred events and the
     * panel names each block once.
     *
     * @param array $user
     * @param array $values
     * @param array $options `types` narrows, `limit` bounds
     * @return array fetchAttributesSimple rows
     */
    public function occurrencesForAny(array $user, array $values,
        array $options = array()
    ) {
        if (empty($values)) {
            return array();
        }
        $conditions = array(
            'OR' => array(
                'Attribute.value1' => $values,
                'Attribute.value2' => $values,
            ),
            'Attribute.deleted' => 0,
        );
        if (!empty($options['types'])) {
            $conditions['Attribute.type'] = $options['types'];
        }
        return $this->attributes()->fetchAttributesSimple($user, array(
            'conditions' => $conditions,
            'fields' => array(
                'Attribute.id',
                'Attribute.event_id',
                'Attribute.object_id',
                'Attribute.type',
                'Attribute.value',
                'Attribute.timestamp',
                'Attribute.distribution',
                'Attribute.sharing_group_id',
            ),
            /*
             * Named fields rather than a bare `contain`. With an
             * explicit `fields` list on the attribute, Containable
             * selects nothing of its own from a `belongsTo` unless it
             * is told what to take — so a bare contain joins the two
             * tables, satisfies `buildConditions`, and hands back rows
             * with no `Event.distribution` on them at all. The ACL is
             * right and every reader of the row is wrong.
             */
            'contain' => self::CONTEXT_FIELDS,
            'order' => array('Attribute.timestamp DESC'),
            'limit' => isset($options['limit'])
                ? $options['limit']
                : 200,
        ));
    }

    /**
     * The distinct values of a type, except this value's own, for an
     * engine that wants to compare rather than to display.
     *
     * The ssdeep engine's candidate set, and it is **not** MISP's.
     * `Correlation::ssdeepCorrelation` narrows through
     * `fuzzy_correlate_ssdeep`, a chunk index that
     * `query_ssdeep_chunks` populates as a side effect of being
     * queried — so it only ever holds attributes saved *since* the
     * extension started working. Measured here: **952 chunk rows
     * covering 13 of 1,399 `ssdeep` attributes**, the 13 being the
     * seeded ones. Narrowing through it would miss the other 1,386 and
     * report *no match* where it means *no index*. Comparing against
     * the type directly is what `ssdeep_fuzzy_compare` is for and
     * cannot inherit an index nobody backfilled.
     *
     * **Values, not occurrences, and that is what makes the whole
     * population affordable.** The engine used to take this set as
     * fully-decorated rows and compare against the hundred most recent
     * of them; a comparison needs the string and nothing else.
     * Dropping eight fields to two roughly halves the fetch — 34.6 ms
     * to 15.8 ms over this instance's 1,399 `ssdeep` attributes — and
     * de-duplicating here means a hash held in thirty events is
     * compared once instead of thirty times. The survivors are
     * re-fetched with their context by `occurrencesForAny`, and there
     * are never many: §14 measured 1,612 pairs over the threshold
     * across the entire instance, and 45 partners on its busiest
     * value.
     *
     * `contain` is deliberately not passed, so `fetchAttributesSimple`
     * keeps its own default `['Event', 'Object']` join — the ACL's
     * conditions are written against `Event`, and dropping that join
     * to save a few milliseconds would drop the predicate with it.
     * These rows must not be read for anything but the value, which is
     * the trap `occurrencesForAny` documents above.
     *
     * @param array $user
     * @param string $type
     * @param string $value The value to exclude
     * @param int $limit Rows fetched, before de-duplication
     * @return array {values: string[], fetched: int, saturated: bool}
     */
    public function valuesOfType(array $user, $type, $value, $limit)
    {
        $rows = $this->attributes()->fetchAttributesSimple($user, array(
            'conditions' => array(
                'Attribute.type' => $type,
                'Attribute.deleted' => 0,
                'NOT' => $this->conditionsFor($value),
            ),
            'fields' => array('Attribute.id', 'Attribute.value'),
            /*
             * Unordered on purpose. The old set was `timestamp DESC`
             * because it was about to be truncated to a hundred rows;
             * ordering a set you intend to keep whole is a sort nobody
             * reads, and on this table it is a filesort.
             */
            'order' => false,
            'limit' => (int)$limit,
        ));
        $values = array();
        foreach ($rows as $row) {
            $values[$row['Attribute']['value']] = true;
        }
        return array(
            'values' => array_keys($values),
            'fetched' => count($rows),
            'saturated' => count($rows) >= (int)$limit,
        );
    }

    /**
     * How this instance actually spells these values, for this viewer:
     * the members of each value's group that an attribute the viewer
     * can read holds. The group folds case and accents, so the caller
     * decides which spelling counts as the reader's.
     *
     * Bounded by `$limit` rows read, not by the value's size; a few
     * rather than one, so a caller can prefer the reader's own spelling
     * where the instance holds several.
     *
     * @param array $user
     * @param array $values Values to look for, exactly as spelled
     * @param array $options As conditionsFor
     * @param int $limit Rows read, not values returned
     * @return array<string> The distinct spellings those rows hold
     */
    public function spellingsFor(array $user, array $values,
        array $options = array(), $limit = self::SPELLING_ROW_CAP
    ) {
        $wanted = array();
        foreach ($values as $value) {
            if ($value !== '' && $value !== null) {
                $wanted[(string)$value] = true;
            }
        }
        if (empty($wanted)) {
            return array();
        }
        $dictionary = ClassRegistry::init('AttributeValue');
        $members = array();
        $groups = $dictionary->resolveCi(
            array_map('strval', array_keys($wanted))
        );
        foreach ($groups as $ids) {
            foreach ($ids as $id) {
                $members[(int)$id] = true;
            }
        }
        if (empty($members)) {
            return array();
        }
        $ids = array_keys($members);
        $conditions = array('OR' => array(
            'Attribute.value1_id' => $ids,
            'Attribute.value2_id' => $ids,
        ));
        if (!empty($options['types'])) {
            $conditions = array(
                $conditions,
                array('Attribute.type' => $options['types']),
            );
        }
        $rows = $this->attributes()->fetchAttributesSimple($user, array(
            'conditions' => $conditions,
            'fields' => array('Attribute.value1_id', 'Attribute.value2_id'),
            'limit' => (int)$limit,
        ));
        $isMember = array();
        foreach ($dictionary->fetchValues($ids) as $text) {
            $isMember[(string)$text] = true;
        }
        $spellings = array();
        foreach ($rows as $row) {
            $halves = array(
                isset($row['Attribute']['value1'])
                    ? (string)$row['Attribute']['value1'] : '',
                isset($row['Attribute']['value2'])
                    ? (string)$row['Attribute']['value2'] : '',
            );
            foreach ($halves as $half) {
                if ($half !== '' && isset($isMember[$half])) {
                    $spellings[$half] = true;
                }
            }
        }
        // `array_keys` hands back `443` as an integer
        return array_map('strval', array_keys($spellings));
    }

    /**
     * Ids of the stored spellings of each term that differ from it in
     * case at most, its own spelling first. Narrower than the value
     * group, which folds accents too: an accent can make a different
     * domain.
     *
     * @param array<string> $terms
     * @return array<string, array<int>> term => ids, empty when the
     *                                   instance holds no such spelling
     */
    public function caseIdsFor(array $terms)
    {
        $dictionary = ClassRegistry::init('AttributeValue');
        $groups = $dictionary->resolveCi(array_map('strval', $terms));
        $members = array();
        foreach ($groups as $ids) {
            foreach ($ids as $id) {
                $members[(int)$id] = true;
            }
        }
        $texts = empty($members)
            ? array()
            : $dictionary->fetchValues(array_keys($members));
        $out = array();
        foreach ($groups as $term => $ids) {
            $term = (string)$term;
            $folded = mb_strtolower($term);
            $own = $others = array();
            foreach ($ids as $id) {
                $text = isset($texts[(int)$id]) ? $texts[(int)$id] : null;
                if ($text === $term) {
                    $own[] = (int)$id;
                } elseif ($text !== null && mb_strtolower($text) === $folded) {
                    $others[] = (int)$id;
                }
            }
            $out[$term] = array_merge($own, $others);
        }
        return $out;
    }

    /**
     * Stored values matching a search text that an attribute the reader
     * can see holds, ranked by rankMatches(): those with a word starting
     * with the text; those starting with it, when it holds no word the
     * index can look up; or, for a CIDR block, the addresses and blocks
     * overlapping it. Hidden and unheld values are left out alike.
     *
     * The candidates are read before the ACL, so a text matching more than
     * ValueConditionRewriter::OVERFLOW stored values is refused whoever
     * asks; that count is the instance's, never the reader's.
     *
     * `$anywhere` matches the text anywhere in a value, inside words too,
     * the way look-alike domains are hunted; it reads the whole dictionary,
     * so it is the reader's choice, never the default. A CIDR block is
     * matched as a block either way.
     *
     * @param array $user
     * @param string $text
     * @param int $page
     * @param int $limit
     * @param bool $anywhere
     * @return array `text`, `mode` (words, prefix, anywhere or block),
     *               `refused` (null, short or many), `values` on this page,
     *               `page` and `more`
     */
    public function matchesFor(array $user, $text, $page = 1,
        $limit = self::MATCH_PAGE, $anywhere = false
    ) {
        $text = trim((string)$text);
        $page = max(1, (int)$page);
        $out = array(
            'text' => $text,
            'mode' => null,
            'refused' => null,
            'values' => array(),
            'page' => $page,
            'more' => false,
        );
        if (mb_strlen($text) < self::MATCH_MIN_LENGTH) {
            $out['refused'] = 'short';
            return $out;
        }
        $dictionary = ClassRegistry::init('AttributeValue');
        $range = strpos($text, '/') === false
            ? null
            : ValueFacetTool::ipRange($text);
        if ($range !== null) {
            $out['mode'] = 'block';
            $found = $dictionary->facets()->overlapping(
                array($range),
                ValueConditionRewriter::OVERFLOW
            );
            $found['overflow'] = $found['starts'] !== null;
        } elseif ($anywhere) {
            $out['mode'] = 'anywhere';
            $found = $dictionary->resolveLike(
                '%' . addcslashes($text, '\\%_') . '%',
                ValueConditionRewriter::OVERFLOW
            );
        } elseif (preg_match('/[\p{L}\p{N}_]{3,}/u', $text)) {
            $out['mode'] = 'words';
            $found = $dictionary->resolveSearch(
                $text,
                ValueConditionRewriter::OVERFLOW
            );
        } else {
            $out['mode'] = 'prefix';
            $found = $dictionary->resolveLike(
                addcslashes($text, '\\%_') . '%',
                ValueConditionRewriter::OVERFLOW
            );
        }
        if ($found['overflow']) {
            $out['refused'] = 'many';
            return $out;
        }
        $texts = empty($found['ids'])
            ? array()
            : $dictionary->fetchValues($found['ids']);
        $texts = self::rankMatches($texts, $text);
        $wanted = $page * (int)$limit + 1;
        $visible = array();
        $attributes = $this->attributes();
        foreach (array_chunk(array_keys($texts), self::MATCH_CHUNK) as $chunk) {
            $held = array_flip($attributes->visibleValueIds(
                $user,
                $chunk,
                count($chunk)
            ));
            foreach ($chunk as $id) {
                if (isset($held[$id])) {
                    $visible[] = (string)$texts[$id];
                    if (count($visible) >= $wanted) {
                        break 2;
                    }
                }
            }
        }
        $out['values'] = array_slice(
            $visible,
            ($page - 1) * (int)$limit,
            (int)$limit
        );
        $out['more'] = count($visible) > $page * (int)$limit;
        return $out;
    }

    /**
     * Matches in the order a reader looking for an indicator wants them:
     * the text itself, then values starting with it, then the rest;
     * shorter before longer within each, so a pasted rule or report that
     * happens to contain the text comes last.
     *
     * @param array $texts id => text
     * @param string $text
     * @return array id => text, ranked
     */
    private static function rankMatches(array $texts, $text)
    {
        $needle = mb_strtolower($text);
        $keys = array();
        foreach ($texts as $id => $value) {
            $folded = mb_strtolower((string)$value);
            $keys[$id] = array(
                $folded === $needle ? 0 : (strpos($folded, $needle) === 0 ? 1 : 2),
                mb_strlen((string)$value),
            );
        }
        uksort($texts, function ($a, $b) use ($keys, $texts) {
            return $keys[$a][0] <=> $keys[$b][0]
                ?: $keys[$a][1] <=> $keys[$b][1]
                ?: strnatcasecmp((string)$texts[$a], (string)$texts[$b]);
        });
        return $texts;
    }
}
