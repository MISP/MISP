<?php

App::uses('ValueSignalLoader', 'Tools/ValueIntelligence');
App::uses('ValueExclusionTool', 'Tools/ValueIntelligence');
App::uses('ValueEnrichmentTool', 'Tools/ValueIntelligence');
App::uses('ValueRendererTool', 'Tools/ValueIntelligence');
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');
App::uses('ValueTrustTool', 'Tools/ValueIntelligence');
App::uses('ValueVerdictTool', 'Tools/ValueIntelligence');
App::uses('ValueLeanTool', 'Tools/ValueIntelligence');
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
App::uses('ModuleLocality', 'Tools');
App::uses('WarninglistCategory', 'Tools');

/**
 * The editor's mechanics: what each section of a profile looks like as a
 * form, what a posted form does to the document, and which edits are
 * refusable before they are saved.
 *
 * prd/analyst-profile/09-editor.md, phase 8a. **This file renders
 * nothing.** It produces a *view-model* — a description of the document
 * in blocks and fields — and three deliberately different designs
 * (phase 8b) draw the same view-model three ways. The seam exists
 * because two of those three designs get thrown away and the mechanics
 * should not go with them.
 *
 * ## Four block kinds, and no fifth
 *
 * A section is a list of blocks; a block is one of four shapes. D2 says
 * the sections have genuinely different shapes and deserve different
 * treatments, and this is that statement made mechanical — a template
 * that can render four block kinds can render all seven sections,
 * including a section a later phase adds.
 *
 * - **`fields`** — labelled scalars. `thresholds`' supermajority,
 *   `relevance`'s clock, `enrichment`'s reuse window. A numeric field may
 *   carry a `unit` — the suffix a design draws after the input — because
 *   without one the settings smuggle their unit into the key name
 *   (`ttl_days`, `undated_assumed_days`) and the ones that do not are
 *   read in whatever unit the reader guesses.
 * - **`map`** — key→value pairs with an *add* affordance and a named
 *   source for the keys. `relevance.ttl_days`, `reference.org_trust`.
 *   Never a row per candidate key: the source is
 *   what the picker searches, not what the table lists (§4). A row's
 *   value may itself be a map — `enrichment.auto_run` is a module→state
 *   one (D17), which is why it is no longer a multiselect: a checklist
 *   has two states and the declaration has three.
 * - **`items`** — a list of togglable entries, each with its own fields.
 *   `signals`, `escalations`, `exclusions`. An item carries its state as
 *   well as its values, because a profile may name a signal this
 *   instance does not have and the palette has to say so rather than
 *   drop it (`03-signals.md` §4.4).
 * - **`strip`** — the signal-strength bands against the attainable bound. One
 *   block, one section, and it exists because a boundary is only wrong
 *   *relative to* something and the something has to be drawn.
 *
 * ## A field addresses itself by path, and the form posts nested names
 *
 * Every field carries `path` — its segments from the root of
 * `parameters`. A template turns that into
 * `data[AnalystProfile][parameters][signals][reporting.independent_orgs][points][per_org]`,
 * which PHP parses back into the same nested array, and `merge()` needs
 * no per-section code to apply it.
 *
 * Nested bracket names rather than a dot-joined string, because the keys
 * are not safe for a separator: a signal id contains dots
 * (`reporting.independent_orgs`), an attribute type contains a pipe
 * (`domain|ip`), an organisation key is a uuid. PHP replaces `.` only in
 * the part of a parameter name before the first bracket, so keys inside
 * brackets survive verbatim — checked rather than assumed.
 *
 * ## The lists are addressed by id and stored as lists
 *
 * `signals`, `escalations` and `exclusions` are JSON *arrays* in the
 * document and *maps keyed by id* in the form, because a position is
 * not a stable address — a save that renumbered would rewrite the entry
 * the analyst was not looking at. `merge()` is where the two
 * representations meet, and it is the one place that knows the document
 * is a list.
 */
class AnalystProfileFormTool
{
    /**
     * The sections, in the order the editor presents them: what the
     * assessment is computed *from* first, then what it is computed
     * *against*, then the two that feed the other axes.
     *
     * `format` is not here. It is the document's version marker, not a
     * judgement, and an editor offering to change it offers to make the
     * document unreadable.
     */
    /**
     * The one value an attribution row can carry.
     *
     * The list stores keys and nothing else, so the column exists to
     * let a row be *there* and removable in the same control every
     * other map uses. Naming it rather than spelling `'counts'` in
     * three places is how the transpose and the form stay the same
     * answer.
     */
    const ATTRIBUTION_COUNTS = 'counts';

    /** The markings map's one value, for the same reason. */
    const MARKING_SHOWN = 'shown';

    const SECTION_ORDER = array(
        'signals',
        'thresholds',
        'escalations',
        'exclusions',
        'relevance',
        'reference',
        'enrichment',
        'context',
        'galaxies',
    );

    /**
     * Which of the three axes each section configures.
     *
     * Here rather than in a template because every surface that lists
     * the sections has to say the same thing about them, and because a
     * wrong entry teaches the wrong thing on every page. Six of the
     * seven reach exactly one axis, which is the fastest available
     * proof that a profile is not a set of signal-strength weights.
     *
     * `thresholds` reaches two: the signal-strength bands are cut from the
     * score, and `lean_supermajority` lives in the same section. It is
     * the one section whose blocks carry their own tag as well.
     *
     * A section configuring an axis does not mean the axis reads the
     * section — relevance reads none of the others and none of them
     * reads it, and enrichment emits no ledger row at all.
     */
    const SECTION_AXIS = array(
        /*
         * `lean + signal strength` since `review-2026-09-13.md` §D1, because
         * the catalogue stopped being one axis. Nine signals weigh the
         * record and two read the value — `lifecycle.warninglist`'s
         * hits and `sightings.false_positive` — and an analyst editing
         * either of those two is moving the reading, not the band. The
         * chip said `signal_strength` over a table where that was true of nine
         * rows out of eleven.
         *
         * The per-row half is `sectionSignals()`, which labels each
         * signal with its own axis; this is the header, and a header
         * over a mixed table names both.
         */
        'signals' => 'lean + signal strength',
        'thresholds' => 'lean + signal strength',
        'escalations' => 'lean',
        'exclusions' => 'signal_strength',
        'relevance' => 'relevance',
        'reference' => 'signal strength — trust weighting',
        'enrichment' => 'no axis — context',
        /*
         * `context` reaches no axis at all: it decides which labels a
         * surface draws first and which it draws when they are absent,
         * and nothing it says reaches a ledger row. `galaxies` does
         * reach one — it is the eligibility filter `attribution.galaxy`
         * reads — and the two are separate sections for exactly that
         * reason (D43): a CERT demoting `firearms` down the card must
         * not change anybody's score.
         */
        'context' => 'no axis — display order',
        'galaxies' => 'lean + signal strength',
    );

    /**
     * The groups the rail draws the sections under, in order.
     *
     * The axis tag answers *what does this move?*, which is the right
     * question once you are already editing. It is the wrong question
     * when you are looking for the section to edit, because a reader
     * arrives knowing what they want to change, not which of three
     * numbers it lands on — and the axes do not partition the list
     * anyway, since `thresholds` and `signals` reach two apiece.
     *
     * These do partition it, and they sort by the kind of knob:
     *
     *   assessment  what counts as evidence, and what it is worth
     *   behaviour   what the engine does with it — resolve, skip, age,
     *               and go and ask
     *   display     what you look at first, which reaches no score
     *
     * Orthogonal to the axis on purpose: `escalations` is grouped as
     * behaviour and still tagged `lean`, because *when signals
     * contradict each other, refuse to lean* is a rule about conduct
     * that happens to land on that axis. The rail shows both, and a
     * reader who wants the axes has the tags.
     */
    const SECTION_GROUP = array(
        'signals' => 'assessment',
        'thresholds' => 'assessment',
        'exclusions' => 'assessment',
        'reference' => 'assessment',
        'galaxies' => 'assessment',
        'escalations' => 'behaviour',
        'relevance' => 'behaviour',
        'enrichment' => 'behaviour',
        'context' => 'display',
    );

    /**
     * What a bench value's simulation reads into the sections: each
     * signal's contribution, the relevance runway for the curve, the
     * totals for the band strip, and the lean the direction pair follows.
     *
     * @param array|null $detail The bench's `detail`
     * @return array `ledger`, `runway`, `marks`, `lean`
     */
    public static function benchReadings($detail)
    {
        $ledger = array();
        if ($detail === null) {
            return array('ledger' => $ledger, 'runway' => null,
                'marks' => array(), 'lean' => null);
        }
        foreach ($detail['rows'] as $row) {
            if ($row['after'] !== null) {
                $ledger[$row['id']] = $row['after'];
            }
        }
        return array(
            'ledger' => $ledger,
            'runway' => isset($detail['axes']['relevance']['runway'])
                ? $detail['axes']['relevance']['runway']
                : null,
            'marks' => array(
                'was' => $detail['totals']['before'],
                'now' => $detail['totals']['after'],
            ),
            'lean' => isset($detail['axes']['lean']['after'])
                ? $detail['axes']['lean']['after']
                : null,
        );
    }

    /**
     * The groups in the order a rail draws them, key => label.
     *
     * Ordered narrowest-blast-radius last: everything in `assessment`
     * and `behaviour` changes a number somebody else may be reading,
     * and `display` changes only what this reader sees.
     *
     * @return array
     */
    public function groups()
    {
        return array(
            'assessment' => __('Assessment'),
            'behaviour' => __('Behaviour'),
            'display' => __('Display'),
        );
    }

    /**
     * The whole view-model for `view` and `edit`.
     *
     * @param array $parameters The profile's decoded `parameters`
     * @param array $sources Option lists the tool may not fetch for
     *                       itself: `attribute_types`, `orgs`,
     *                       `warninglists`, `modules`, plus `ledger`
     *                       and `not_counted` when a value is in play
     * @return array Section id => section
     */
    public function sections(array $parameters, array $sources = array())
    {
        $sections = array();
        foreach (self::SECTION_ORDER as $id) {
            $method = 'section' . ucfirst($id);
            $sections[$id] = $this->$method($parameters, $sources);
            $sections[$id]['axis'] = $this->axisLabel($id);
            $sections[$id]['group'] = self::SECTION_GROUP[$id];
        }
        return $sections;
    }

    /**
     * The axis tag a section carries, translated.
     *
     * The constant holds the keys so a caller can compare them; this
     * holds the words so `__()` sees a literal.
     *
     * @param string $id
     * @return string
     */
    private function axisLabel($id)
    {
        $labels = array(
            'signal_strength' => __('signal strength'),
            'lean + signal strength' => __('lean + signal strength'),
            'lean' => __('lean'),
            'relevance' => __('relevance'),
            'signal strength — trust weighting' => __(
                'signal strength — trust weighting'
            ),
            'no axis — context' => __('context'),
            'no axis — display order' => __('display order'),
        );
        $key = self::SECTION_AXIS[$id];
        return isset($labels[$key]) ? $labels[$key] : $key;
    }

    /**
     * `signals` — one item per signal, and the points columns differ per
     * row because `points` has no fixed schema by design.
     *
     * The palette is the union of two sets, which is the whole of D12
     * made visible: everything the loader discovered, plus everything
     * the profile names. A signal in the first set and not the second is
     * *available* — droppable in, not yet active. One in the second and
     * not the first is *missing* — this instance cannot compute it, the
     * engine already says so in `not_counted`, and an editor that
     * quietly dropped the entry would lose an analyst's configuration
     * for a signal a redeploy would bring back.
     *
     * @param array $parameters
     * @param array $sources
     * @return array
     */
    private function sectionSignals(array $parameters, array $sources)
    {
        return array(
            'id' => 'signals',
            'title' => __('Signals'),
            /*
             * The second sentence onward goes behind the `i`, so what
             * is always on screen stays one line. What is behind it is
             * the question every reader of this table asks first, in
             * the words they would ask it in: *why is this number
             * negative, and negative toward what?*
             */
            /*
             * Rewritten 2026-09-13. It described the anchoring in plain
             * words — *when the verdict comes out benign, the whole
             * column is flipped* — which was true of every row until
             * `review-2026-09-13.md` §D1 and is now true of two. An
             * analyst reading the old sentence would set a
             * corroboration weight expecting it to invert on benign
             * values, which is exactly the reasoning the split removed.
             */
            'blurb' => __(
                'What each kind of evidence is worth. The lean is'
                . ' decided separately, by counting how many'
                . ' organisations called the value one thing or the'
                . ' other, so nothing in this table sets it on its own.'
                . ' Most signals score the record itself: a plus means'
                . ' it carries something — widely reported, published,'
                . ' attributed — and a minus that it lacks it, whichever'
                . ' way the lean came out. The two marked "reads the'
                . ' value", a warninglist hit and a false-positive'
                . ' sighting, argue for or against the lean instead and'
                . ' are kept apart from the signal strength.'
            ),
            'primer' => $this->signalPrimer($parameters),
            'blocks' => array(
                array(
                    'kind' => 'items',
                    'id' => 'signals',
                    'path' => array('signals'),
                    'items' => $this->signalPalette($parameters, $sources),
                    'groups' => $this->signalGroups($parameters),
                ),
            ),
        );
    }

    /**
     * Every signal this instance has or this profile names.
     *
     * @param array $parameters
     * @param array $sources
     * @return array
     */
    public function signalPalette(array $parameters, array $sources = array())
    {
        $catalogue = ValueSignalLoader::catalogue(
            ValueSignalLoader::SUBJECT_SIGNAL
        );
        $entries = $this->entriesById($parameters, 'signals');
        $ledger = isset($sources['ledger']) ? $sources['ledger'] : array();
        $notCounted = isset($sources['not_counted'])
            ? $sources['not_counted']
            : array();

        $items = array();
        foreach ($catalogue as $id => $config) {
            $items[$id] = $this->signalItem($id, $config,
                isset($entries[$id]) ? $entries[$id] : null,
                $ledger, $notCounted);
        }
        foreach ($entries as $id => $entry) {
            if (isset($items[$id])) {
                continue;
            }
            $items[$id] = $this->signalItem($id, null, $entry,
                $ledger, $notCounted);
        }
        return $this->orderByGroup($items);
    }

    /**
     * The palette in the ledger's own order — the four groups as
     * `ValueVerdictTool` renders them, then any group a custom signal
     * named, and inside a group by id.
     *
     * The loader's order is the filesystem's, which is alphabetical by
     * filename and puts `attribution.galaxy` above
     * `reporting.independent_orgs` for no reason a reader can see. An
     * analyst checking whether the sightings were counted twice wants
     * them next to each other, which is the same argument the ledger's
     * own grouping already makes.
     *
     * @param array $items id => item
     * @return array
     */
    private function orderByGroup(array $items)
    {
        $groups = array();
        foreach ($this->baseGroups() as $group) {
            $groups[$group] = array();
        }
        foreach ($items as $id => $item) {
            $group = $item['group'] === null ? '' : $item['group'];
            if (!isset($groups[$group])) {
                $groups[$group] = array();
            }
            $groups[$group][$id] = $item;
        }
        $out = array();
        foreach ($groups as $group => $members) {
            ksort($members);
            foreach ($members as $item) {
                $out[] = $item;
            }
        }
        return $out;
    }

    /**
     * @param string $id
     * @param array|null $config From the loader; null when the instance
     *                           does not have this signal
     * @param array|null $entry From the profile; null when the profile
     *                          does not carry it
     * @param array $ledger id => contribution
     * @param array $notCounted id => note
     * @return array
     */
    private function signalItem($id, $config, $entry, array $ledger,
        array $notCounted
    ) {
        $inProfile = $entry !== null;
        $enabled = $inProfile
            && (!array_key_exists('enabled', $entry)
                || !empty($entry['enabled']));
        if ($config === null) {
            $state = 'missing';
        } elseif (!$inProfile) {
            $state = 'available';
        } else {
            $state = 'active';
        }
        $badges = array();
        /*
         * Which axis this signal's points land on, on the row itself,
         * because the table holds both since `review-2026-09-13.md`
         * §D1 and the section header can only name the pair. Only the
         * exception is badged: nine of eleven weigh the record, so a
         * chip on every row would be noise, and the one an analyst has
         * to think differently about is the one that says what the
         * value *is*.
         */
        if ($config !== null
            && isset($config['axis'])
            && $config['axis'] === ValueVerdictTool::AXIS_LEAN
        ) {
            $badges[] = array(
                'id' => 'lean',
                'label' => __('reads the value'),
                'title' => __(
                    'This signal says what the value is, not how well'
                    . ' documented it is, so its points are scored'
                    . ' against the verdict — a plus supports the'
                    . ' reading, a minus argues with it — and they sum'
                    . ' beside the signal strength rather than into it.'
                    . ' A big'
                    . ' enough minus turns the verdict contested.'
                ),
            );
        }
        if ($config !== null && !empty($config['is_custom'])) {
            $badges[] = array(
                'id' => 'custom',
                'label' => __('custom'),
                'title' => __(
                    'Added on this instance, so a colleague reading this'
                    . ' profile elsewhere cannot reproduce the number it'
                    . ' contributes.'
                ),
            );
        }
        if ($state === 'missing') {
            $badges[] = array(
                'id' => 'missing',
                'label' => __('not implemented here'),
                'title' => __(
                    'This profile configures a signal this instance does'
                    . ' not have. It contributes nothing and is listed'
                    . ' in the assessment as not counted. The'
                    . ' configuration is kept, so deploying the'
                    . ' implementation brings it back.'
                ),
            );
        }
        $item = array(
            'id' => $id,
            'title' => $this->helpName($id, $config),
            'description' => $config === null
                ? null
                : $config['description'],
            'state' => $state,
            'enabled' => $enabled,
            'in_profile' => $inProfile,
            'badges' => $badges,
            'group' => $entry !== null && !empty($entry['group'])
                ? $entry['group']
                : ($config === null ? null : $config['group']),
            'evidence_class' => $config === null
                ? null
                : $config['evidence_class'],
            'trust_weighted' => $entry !== null
                && !empty($entry['trust_weighted']),
            'absence_key' => $config === null
                ? null
                : $config['absence_key'],
            'path' => array('signals', $id),
            'contribution' => array_key_exists($id, $ledger)
                ? (int)$ledger[$id]
                : null,
            'not_counted' => array_key_exists($id, $notCounted)
                ? $notCounted[$id]
                : null,
            'fields' => array(),
        );
        /*
         * The toggle comes first, then the generated maps. There is no
         * editorial band: D16 removed it, because what a signal is worth
         * in principle is `points.cap` in the next column, in points,
         * and *band* now means the signal-strength band and nothing else.
         *
         * **And there is no ledger group.** It was a select on every
         * signal row and it is the one control here that cannot change
         * an assessment: `group` picks the heading a row is read under
         * and touches no arithmetic. The default is already right —
         * every signal declares its own in its implementation — and
         * overriding it puts a row under a heading whose note
         * (`ValueVerdictTool::groupNote()`) then describes something
         * else, or under a custom heading with no note at all. So the
         * densest pane in the editor paid eleven selects for an outcome
         * that was either invisible or wrong.
         *
         * The **document** keeps the key: `anchor()` still resolves
         * `$entry['group'] ?: $signal->group`, so a profile that arrives
         * by import or by the Raw JSON pane with a `group` set is still
         * honoured. What went away is the control, not the schema —
         * `$item['group']` below still groups this pane's own rows.
         */
        $item['fields'][] = array(
            'key' => 'enabled',
            'label' => __('Enabled'),
            'type' => 'bool',
            'value' => $enabled,
            'default' => true,
            'path' => array('signals', $id, 'enabled'),
        );
        foreach (array('points', 'config') as $map) {
            $schema = $config === null
                ? array()
                : $config[$map . '_schema'];
            $stored = $entry !== null && isset($entry[$map])
                && is_array($entry[$map])
                ? $entry[$map]
                : array();
            foreach ($this->generatedFields($schema, $stored,
                array('signals', $id, $map)) as $field) {
                $field['map'] = $map;
                /*
                 * Every entry in a `points_schema` is in points —
                 * that is what the map is — so the unit is the form's
                 * to state rather than eleven signal files'. A schema
                 * that declares its own still wins. `config` gets no
                 * default: its entries are in days, ratios and names.
                 */
                if ($map === 'points' && !isset($field['unit'])) {
                    $field['unit'] = __('points');
                }
                $item['fields'][] = $field;
            }
        }
        if ($config !== null) {
            $readsValue = isset($config['axis'])
                && $config['axis'] === ValueVerdictTool::AXIS_LEAN;
            $tags = array($readsValue
                ? array('style' => 'pill', 'label' => __('reads the value'))
                : array('style' => 'tag', 'label' => __('signal strength')));
            $lands = $readsValue
                ? __('It argues whether the value is harmful or harmless,'
                    . ' so its points are weighed against the reading and'
                    . ' kept out of the signal strength.')
                : __('Its points add up with the other signals\' into the'
                    . ' signal strength: how well documented the record is,'
                    . ' whichever way it leans.');
            if ($item['trust_weighted']) {
                $tags[] = array('style' => 'mult',
                    'label' => __('trust weighted'));
                $lands .= ' ' . __('Each organisation\'s part is scaled by'
                    . ' the grade you gave it under Sources & reputation.');
            }
            $item['help'] = $this->itemHelp($item,
                isset($config['help']) ? $config['help'] : null,
                array(
                    'tags' => $tags,
                    'lands' => $lands,
                    'how_title' => __('How it scores'),
                ));
        }
        return $item;
    }

    /**
     * A signal's or rule's name for a reader, or its id when it declares
     * none.
     *
     * @param string $id
     * @param array|null $config From the loader
     * @return string
     */
    private function helpName($id, $config)
    {
        return $config !== null && !empty($config['help']['name'])
            ? (string)$config['help']['name']
            : $id;
    }

    /**
     * What a row's "How it works" popover says: the row's own `help`,
     * filled in from its schema where that says nothing.
     *
     * @param array $item
     * @param mixed $help As `ValueSignalBase::$help`
     * @param array $frame What the kind of row adds: `tags` (each a
     *                     `style` of pill, tag or mult, a `label`, an
     *                     optional `key` and `title`), `lands` (where
     *                     its effect goes) and `how_title`
     * @return array
     */
    private function itemHelp(array $item, $help, array $frame)
    {
        $help = is_array($help) ? $help : array();
        $texts = isset($help['settings']) && is_array($help['settings'])
            ? $help['settings']
            : array();
        $settings = array();
        $values = array();
        foreach ($item['fields'] as $field) {
            if ($field['key'] === 'enabled' && $field['type'] === 'bool') {
                continue;
            }
            $key = $field['key'];
            $values[$key] = array(
                'value' => $field['value'] !== null
                    ? $field['value']
                    : $field['default'],
                'fallback' => isset($field['resolved'])
                    ? $field['resolved']
                    : null,
                'input' => self::fieldId($field['path']),
            );
            $settings[] = array(
                'key' => $key,
                'text' => isset($texts[$key]) ? $texts[$key] : $field['label'],
            );
        }
        return array(
            'id' => $item['id'],
            'name' => isset($help['name']) ? $help['name'] : $item['title'],
            'what' => isset($help['what'])
                ? $help['what']
                : $item['description'],
            'how' => isset($help['how']) ? $help['how'] : null,
            'note' => isset($help['note']) ? $help['note'] : null,
            'settings' => $settings,
            'recipes' => isset($help['recipes']) && is_array($help['recipes'])
                ? $help['recipes']
                : array(),
            'values' => $values,
            'tags' => $frame['tags'],
            'lands' => $frame['lands'],
            'how_title' => $frame['how_title'],
        );
    }

    /**
     * The numbers the Signals pane's primer quotes, from this profile.
     * `kind` picks the element that renders a primer, `label` its button.
     *
     * @param array $parameters
     * @return array
     */
    private function signalPrimer(array $parameters)
    {
        $thresholds = $this->section($parameters, 'thresholds');
        $bands = isset($thresholds['signal_strength_bands'])
            && is_array($thresholds['signal_strength_bands'])
            ? $thresholds['signal_strength_bands']
            : array();
        $clamp = isset($thresholds['thin_record_clamp'])
            && is_array($thresholds['thin_record_clamp'])
            ? $thresholds['thin_record_clamp']
            : array();
        return array(
            'kind' => 'signal',
            'label' => __('How signals add up'),
            'medium' => isset($bands['medium']) ? (int)$bands['medium'] : 30,
            'high' => isset($bands['high']) ? (int)$bands['high'] : 60,
            'min_signals' => isset(
                $thresholds['signal_strength_high_min_signals']
            )
                ? (int)$thresholds['signal_strength_high_min_signals']
                : 4,
            'clamp' => empty($clamp['max_band'])
                ? null
                : array(
                    'voices' => isset($clamp['max_voices'])
                        ? $clamp['max_voices'] + 0
                        : 1,
                    'sightings' => isset($clamp['max_sightings'])
                        ? $clamp['max_sightings'] + 0
                        : 0,
                    'band' => (string)$clamp['max_band'],
                ),
        );
    }

    /**
     * Which groups this profile's signals actually land in, in the
     * ledger's own order, so a design can section the table the way the
     * assessment sections its ledger.
     *
     * @param array $parameters
     * @return array
     */
    private function signalGroups(array $parameters)
    {
        $catalogue = ValueSignalLoader::catalogue();
        $seen = array();
        foreach ($this->entriesById($parameters, 'signals') as $id => $entry) {
            if (!empty($entry['group'])) {
                $seen[$entry['group']] = true;
            } elseif (isset($catalogue[$id])) {
                $seen[$catalogue[$id]['group']] = true;
            }
        }
        $ordered = array();
        foreach ($this->baseGroups() as $group) {
            if (isset($seen[$group])) {
                $ordered[] = $group;
                unset($seen[$group]);
            }
        }
        return array_merge($ordered, array_keys($seen));
    }

    /**
     * `thresholds` — the lean supermajority, the band boundaries, and
     * the thin-record clamp, with the band strip beside them.
     *
     * @param array $parameters
     * @param array $sources
     * @return array
     */
    private function sectionThresholds(array $parameters, array $sources)
    {
        $section = $this->section($parameters, 'thresholds');
        $bands = isset($section['signal_strength_bands'])
            && is_array($section['signal_strength_bands'])
            ? $section['signal_strength_bands']
            : array();
        $clamp = isset($section['thin_record_clamp'])
            && is_array($section['thin_record_clamp'])
            ? $section['thin_record_clamp']
            : array();
        return array(
            'id' => 'thresholds',
            'title' => __('Thresholds'),
            'blurb' => __(
                'Where a score turns from low to medium to high, and how'
                . ' one-sided the reporting has to be before a value'
                . ' leans one way.'
            ),
            'guide' => array(
                'title' => __('When to tune these'),
                'intro' => __(
                    'The shipped numbers suit most instances. Move them'
                    . ' when the bands on your value pages stop matching'
                    . ' your own read of them — try a value on the right'
                    . ' and it is rescored as you type.'
                ),
                'items' => array(
                    array(
                        'symptom' => __('Nearly everything reads high'),
                        'remedy' => __('Raise High from.'),
                    ),
                    array(
                        'symptom' => __('Little ever gets past low'),
                        'remedy' => __('Lower Medium from.'),
                    ),
                    array(
                        'symptom' => __('Clear majorities still read'
                            . ' contested'),
                        'remedy' => __('Lower the supermajority share,'
                            . ' or raise it when split reporting looks'
                            . ' settled.'),
                    ),
                    array(
                        'symptom' => __('A lone report looks as solid as'
                            . ' a corroborated one'),
                        'remedy' => __('Keep the single-source cap on,'
                            . ' under Fine-tuning.'),
                    ),
                ),
            ),
            'fold' => array(
                'label' => __('Fine-tuning'),
                'summary' => $this->thresholdReadout($section, $clamp),
            ),
            'blocks' => array(
                array(
                    'kind' => 'strip',
                    'id' => 'signal_strength_bands',
                    'title' => __('Signal-strength bands'),
                    'axis' => __('signal strength'),
                    'blurb' => __(
                        'These two numbers cut the points a value earns'
                        . ' from its signals into low, medium and high —'
                        . ' the strip shows how far the enabled signals'
                        . ' can reach.'
                    ),
                    'fields' => array(
                        array(
                            'key' => 'medium',
                            'label' => __('Medium from'),
                            'type' => 'int',
                            'unit' => __('points'),
                            'value' => isset($bands['medium'])
                                ? $bands['medium']
                                : null,
                            'default' => 30,
                            'path' => array('thresholds',
                                'signal_strength_bands', 'medium'),
                        ),
                        array(
                            'key' => 'high',
                            'label' => __('High from'),
                            'type' => 'int',
                            'unit' => __('points'),
                            'value' => isset($bands['high'])
                                ? $bands['high']
                                : null,
                            'default' => 60,
                            'path' => array('thresholds',
                                'signal_strength_bands', 'high'),
                        ),
                    ),
                ) + $this->bandStrip($parameters),
                array(
                    'kind' => 'fields',
                    'id' => 'lean',
                    'title' => __('The lean'),
                    'axis' => __('lean'),
                    'fields' => array(
                        array(
                            'key' => 'lean_supermajority',
                            'label' => __('Supermajority share'),
                            'type' => 'float',
                            'value' => isset($section['lean_supermajority'])
                                ? $section['lean_supermajority']
                                : null,
                            'default' => 0.66,
                            'help' => __(
                                'At 0.66, two thirds of the reporting'
                                . ' organisations must agree before the'
                                . ' value leans; anything less reads as'
                                . ' contested. An organisation that only'
                                . ' recorded it with to_ids unset is on'
                                . ' neither side, and a value nobody'
                                . ' flagged reads as unflagged.'
                            ),
                            'path' => array('thresholds',
                                'lean_supermajority'),
                        ),
                    ),
                ),
                array(
                    'kind' => 'fields',
                    'id' => 'thin_record_clamp',
                    'advanced' => true,
                    'title' => __('Single-source cap'),
                    'axis' => __('signal strength'),
                    'blurb' => __(
                        'Holds a value that rests on one reporter down,'
                        . ' however many points it scores. Both'
                        . ' conditions must hold before the cap applies,'
                        . ' and the lean is untouched.'
                    ),
                    'fields' => array(
                        array(
                            'key' => 'max_voices',
                            'label' => __('Reported by at most'),
                            'type' => 'float',
                            'unit' => __('sources'),
                            'value' => isset($clamp['max_voices'])
                                ? $clamp['max_voices']
                                : (isset($clamp['max_orgs'])
                                    ? $clamp['max_orgs']
                                    : null),
                            'default' => 1,
                            'help' => __(
                                'A graded organisation counts for less:'
                                . ' G for none, E for a quarter.'
                            ),
                            'path' => array('thresholds',
                                'thin_record_clamp', 'max_voices'),
                        ),
                        array(
                            'key' => 'max_sightings',
                            'label' => __('Sighted by others at most'),
                            'type' => 'int',
                            'unit' => __('times'),
                            'value' => isset($clamp['max_sightings'])
                                ? $clamp['max_sightings']
                                : null,
                            'default' => 0,
                            'help' => __(
                                'Sightings by organisations that did not'
                                . ' report it, and graded enrichment'
                                . ' verdicts that agree with the'
                                . ' reporters.'
                            ),
                            'path' => array('thresholds',
                                'thin_record_clamp', 'max_sightings'),
                        ),
                        array(
                            'key' => 'max_band',
                            'label' => __('Cap the band at'),
                            'type' => 'select',
                            /*
                             * An absent `max_band` is no clamp at all,
                             * so the blank option is how one is posted
                             * away rather than saved as `none`.
                             */
                            'options' => array_merge(
                                array(array(
                                    'value' => '',
                                    'label' => __('no cap'),
                                )),
                                ValueVerdictTool::BANDS
                            ),
                            'value' => isset($clamp['max_band'])
                                ? $clamp['max_band']
                                : null,
                            'path' => array('thresholds',
                                'thin_record_clamp', 'max_band'),
                        ),
                    ),
                ),
                array(
                    'kind' => 'fields',
                    'id' => 'thin_record_clamp_by_grade',
                    'advanced' => true,
                    'layout' => 'dense',
                    'title' => __('Cap by the reporter\'s grade'),
                    'blurb' => __(
                        'Lets a single source you graded go further — one'
                        . ' A-graded reporter allowed up to medium, say.'
                    ),
                    'fields' => $this->clampGradeFields($clamp),
                ),
                array(
                    'kind' => 'fields',
                    'id' => 'guards',
                    'advanced' => true,
                    'title' => __('Other guards'),
                    'fields' => array(
                        array(
                            'key' => 'signal_strength_high_min_signals',
                            'label' => __('Signals needed for high'),
                            'type' => 'int',
                            'unit' => __('signals'),
                            'value' => isset(
                                $section['signal_strength_high_min_signals'])
                                ? $section['signal_strength_high_min_signals']
                                : null,
                            'default' => 4,
                            'help' => __(
                                'So that one generous signal cannot buy'
                                . ' the high band on its own.'
                            ),
                            'path' => array('thresholds',
                                'signal_strength_high_min_signals'),
                        ),
                        array(
                            'key' => 'dispute_stale_factor',
                            'label' => __('Weight of an old dispute'),
                            'type' => 'float',
                            'value' => isset(
                                $section['dispute_stale_factor']
                            )
                                ? $section['dispute_stale_factor']
                                : null,
                            'default' => 0.5,
                            'help' => __(
                                'A false positive filed before another'
                                . ' organisation reasserted the value'
                                . ' counts this much against it: 1 in'
                                . ' full, 0 not at all.'
                            ),
                            'path' => array('thresholds',
                                'dispute_stale_factor'),
                        ),
                    ),
                ),
            ),
        );
    }

    /**
     * What the folded settings currently say, for the fold's closed
     * summary.
     *
     * @param array $section The stored `thresholds`
     * @param array $clamp The stored `thin_record_clamp`
     * @return string
     */
    private function thresholdReadout(array $section, array $clamp)
    {
        $parts = array();
        $band = isset($clamp['max_band']) ? (string)$clamp['max_band'] : '';
        $parts[] = $band === ''
            ? __('no single-source cap')
            : sprintf(__('single-source values capped at %s'), $band);
        $byGrade = isset($clamp['max_band_by_grade'])
            && is_array($clamp['max_band_by_grade'])
            ? count(array_filter($clamp['max_band_by_grade'], 'strlen'))
            : 0;
        if ($byGrade > 0) {
            $parts[] = sprintf(__n('%d grade capped apart',
                '%d grades capped apart', $byGrade), $byGrade);
        }
        $signals = isset($section['signal_strength_high_min_signals'])
            ? (int)$section['signal_strength_high_min_signals']
            : 4;
        $parts[] = sprintf(__n('high needs %d signal',
            'high needs %d signals', $signals), $signals);
        $stale = isset($section['dispute_stale_factor'])
            && is_numeric($section['dispute_stale_factor'])
            ? (float)$section['dispute_stale_factor']
            : 0.5;
        $parts[] = sprintf(__('old disputes count ×%s'),
            rtrim(rtrim(number_format($stale, 2), '0'), '.'));
        return implode(' · ', $parts);
    }

    /**
     * One select per grade for `max_band_by_grade`.
     *
     * @param array $clamp The stored `thin_record_clamp`
     * @return array
     */
    private function clampGradeFields(array $clamp)
    {
        $byGrade = isset($clamp['max_band_by_grade'])
            && is_array($clamp['max_band_by_grade'])
            ? $clamp['max_band_by_grade']
            : array();
        $fields = array();
        foreach (ValueTrustTool::GRADES as $grade) {
            $fields[] = array(
                'key' => 'max_band_by_grade_' . $grade,
                'label' => $this->gradeLabel($grade),
                'type' => 'select',
                'options' => array_merge(
                    array(array(
                        'value' => '',
                        'label' => __('same as above'),
                    )),
                    ValueVerdictTool::BANDS
                ),
                'value' => isset($byGrade[$grade]) ? $byGrade[$grade] : null,
                'path' => array('thresholds', 'thin_record_clamp',
                    'max_band_by_grade', $grade),
            );
        }
        return $fields;
    }

    /**
     * `escalations` — the conflict rules, discovered the same way
     * signals are and with the same three states.
     *
     * v1 ships two, so this is two checkboxes and their prose. It is
     * still `items` rather than `fields`, because the set is a directory
     * read and the count is not the design's business.
     *
     * @param array $parameters
     * @param array $sources
     * @return array
     */
    private function sectionEscalations(array $parameters, array $sources)
    {
        $items = $this->escalationPalette($parameters);
        return array(
            'id' => 'escalations',
            'title' => __('Conflict rules'),
            'blurb' => __(
                'For when the record contradicts itself too badly for'
                . ' any lean to be honest. A rule can only ever mark the'
                . ' value contested.'
            ),
            'primer' => $this->escalationPrimer($parameters, $items),
            'blocks' => array(
                array(
                    'kind' => 'items',
                    'id' => 'escalations',
                    'path' => array('escalations'),
                    'items' => $items,
                ),
            ),
        );
    }

    /**
     * What the Conflict rules pane's primer quotes: the order this
     * profile tries its rules in, and the share the count falls back to.
     *
     * @param array $parameters
     * @param array $items From escalationPalette()
     * @return array
     */
    private function escalationPrimer(array $parameters, array $items)
    {
        $names = array();
        foreach ($items as $item) {
            $names[$item['id']] = isset($item['help']['name'])
                ? $item['help']['name']
                : $item['id'];
        }
        $order = array();
        foreach (array_keys($this->entriesById($parameters, 'escalations'))
            as $id
        ) {
            $order[] = array(
                'id' => $id,
                'name' => isset($names[$id]) ? $names[$id] : $id,
            );
        }
        return array(
            'kind' => 'escalation',
            'label' => __('How conflict rules decide'),
            'order' => $order,
            'supermajority' => ValueLeanTool::supermajority(
                array('parameters' => $parameters)
            ),
        );
    }

    /**
     * @param array $parameters
     * @return array
     */
    public function escalationPalette(array $parameters)
    {
        $catalogue = ValueSignalLoader::catalogue(
            ValueSignalLoader::SUBJECT_ESCALATION
        );
        $entries = $this->entriesById($parameters, 'escalations');
        $items = array();
        foreach ($catalogue as $id => $config) {
            $items[$id] = $this->escalationItem($id, $config,
                isset($entries[$id]) ? $entries[$id] : null,
                $parameters);
        }
        foreach ($entries as $id => $entry) {
            if (!isset($items[$id])) {
                $items[$id] = $this->escalationItem($id, null, $entry,
                    $parameters);
            }
        }
        return array_values($items);
    }

    /**
     * @param string $id
     * @param array|null $config
     * @param array|null $entry
     * @param array $parameters The whole document, for a `when` spec
     *                          whose fallback is another setting in it
     * @return array
     */
    private function escalationItem($id, $config, $entry,
        array $parameters = array()
    ) {
        $inProfile = $entry !== null;
        $enabled = $inProfile
            && (!array_key_exists('enabled', $entry)
                || !empty($entry['enabled']));
        $badges = array();
        if ($config !== null && !empty($config['is_custom'])) {
            $badges[] = array(
                'id' => 'custom',
                'label' => __('custom'),
                'title' => __('Added on this instance.'),
            );
        }
        if ($config === null) {
            $badges[] = array(
                'id' => 'missing',
                'label' => __('not implemented here'),
                'title' => __(
                    'This profile configures a rule this instance does'
                    . ' not have. It cannot fire; the configuration is'
                    . ' kept.'
                ),
            );
        }
        $item = array(
            'id' => $id,
            'title' => $this->helpName($id, $config),
            'description' => $config === null
                ? null
                : $config['description'],
            'state' => $config === null
                ? 'missing'
                : ($inProfile ? 'active' : 'available'),
            'enabled' => $enabled,
            'in_profile' => $inProfile,
            'badges' => $badges,
            'emits' => $config === null
                ? (isset($entry['emits']) ? $entry['emits'] : null)
                : $config['emits'],
            'path' => array('escalations', $id),
            'fields' => array(
                array(
                    'key' => 'enabled',
                    'label' => __('Enabled'),
                    'type' => 'bool',
                    'value' => $enabled,
                    'default' => true,
                    'path' => array('escalations', $id, 'enabled'),
                ),
            ),
        );
        $when = $entry !== null && isset($entry['when'])
            && is_array($entry['when'])
            ? $entry['when']
            : array();
        $schema = $config === null ? array() : $config['when_schema'];
        foreach ($this->generatedFields($schema, $when,
            array('escalations', $id, 'when'), $parameters) as $field) {
            $field['map'] = 'when';
            $item['fields'][] = $field;
        }
        if ($config !== null) {
            $item['help'] = $this->itemHelp(
                $item,
                isset($config['help']) ? $config['help'] : null,
                array(
                    'tags' => array(array('style' => 'tag',
                        'key' => __('makes it'),
                        'label' => __('contested'))),
                    'lands' => __('It is tried before the count of'
                        . ' organisations decides the lean. The first ticked'
                        . ' rule that fires decides instead, and the reading'
                        . ' carries its sentence. It adds no points and'
                        . ' leaves the signal strength alone.'),
                    'how_title' => __('When it fires'),
                )
            );
        }
        return $item;
    }

    /**
     * `exclusions` — the closed set of four, declared beside the code
     * that applies them.
     *
     * @param array $parameters
     * @param array $sources
     * @return array
     */
    private function sectionExclusions(array $parameters, array $sources)
    {
        return array(
            'id' => 'exclusions',
            'title' => __('Exclusions'),
            'blurb' => __(
                'Evidence you have decided not to count. Anything an'
                . ' exclusion removes is listed in the assessment as not'
                . ' counted, naming the rule.'
            ),
            'primer' => array(
                'kind' => 'exclusion',
                'label' => __('How exclusions work'),
                'layers' => ValueExclusionTool::layers(),
            ),
            'blocks' => array(
                array(
                    'kind' => 'items',
                    'id' => 'exclusions',
                    'path' => array('exclusions'),
                    'items' => $this->exclusionItems($parameters),
                ),
            ),
        );
    }

    /**
     * One layer's word, or the key itself where this version has no
     * word for it — a profile naming a layer nothing declares is a
     * document from a later version, and the key is still truer than
     * blank.
     *
     * @param string|null $layer
     * @param string $part `label` or `title`
     * @return string|null
     */
    private function layerLabel($layer, $part)
    {
        if ($layer === null) {
            return null;
        }
        $layers = ValueExclusionTool::layers();
        return isset($layers[$layer][$part])
            ? $layers[$layer][$part]
            : ($part === 'label' ? $layer : null);
    }

    /**
     * @param array $parameters
     * @return array
     */
    public function exclusionItems(array $parameters)
    {
        $entries = $this->entriesById($parameters, 'exclusions');
        $items = array();
        foreach (ValueExclusionTool::catalogue() as $id => $declaration) {
            $entry = isset($entries[$id]) ? $entries[$id] : null;
            $enabled = $entry !== null
                && (!array_key_exists('enabled', $entry)
                    || !empty($entry['enabled']));
            $item = array(
                'id' => $id,
                'title' => $declaration['title'],
                'description' => $declaration['description'],
                'state' => $entry === null ? 'available' : 'active',
                'enabled' => $enabled,
                'in_profile' => $entry !== null,
                'layer' => $declaration['layer'],
                'badges' => array(),
                'layer_label' => $this->layerLabel($declaration['layer'],
                    'label'),
                'layer_title' => $this->layerLabel($declaration['layer'],
                    'title'),
                'path' => array('exclusions', $id),
                'fields' => array(
                    array(
                        'key' => 'enabled',
                        'label' => __('Enabled'),
                        'type' => 'bool',
                        'value' => $enabled,
                        'default' => false,
                        'path' => array('exclusions', $id, 'enabled'),
                    ),
                ),
            );
            /*
             * The entry itself, minus the two keys that are not
             * settings: `id` is the entry's address and `enabled` is
             * the row's own checkbox, drawn above. Passed whole, both
             * came back as *undeclared* keys — so the pane offered to
             * edit an exclusion's id, and posted `enabled` twice under
             * the same name.
             */
            $stored = $entry === null ? array() : $entry;
            unset($stored['id'], $stored['enabled']);
            foreach ($this->generatedFields(
                $declaration['schema'],
                $stored,
                array('exclusions', $id)
            ) as $field) {
                $item['fields'][] = $field;
            }
            $item['help'] = $this->itemHelp(
                $item,
                isset($declaration['help']) ? $declaration['help'] : null,
                array(
                    'tags' => array(array('style' => 'tag',
                        'key' => __('applies to'),
                        'label' => $item['layer_label'],
                        'title' => $item['layer_title'])),
                    'lands' => __('It removes evidence before any signal'
                        . ' reads it, so it changes what the signals count'
                        . ' rather than what a point is worth. What it'
                        . ' removes is listed in the assessment under not'
                        . ' counted.'),
                    'how_title' => __('What it removes'),
                )
            );
            $items[] = $item;
        }
        foreach ($entries as $id => $entry) {
            if (isset(ValueExclusionTool::catalogue()[$id])) {
                continue;
            }
            $items[] = array(
                'id' => $id,
                'title' => $id,
                'description' => null,
                'state' => 'missing',
                'enabled' => false,
                'in_profile' => true,
                'layer' => null,
                'badges' => array(array(
                    'id' => 'missing',
                    'label' => __('not an exclusion this version has'),
                    'title' => __(
                        'The exclusion set is closed in code. This entry'
                        . ' does nothing.'
                    ),
                )),
                'path' => array('exclusions', $id),
                'fields' => array(),
            );
        }
        return $items;
    }

    /**
     * `relevance` — the second axis. Added by phase 5, after §4 of the
     * spec was written, which is why the spec says six sections and
     * there are seven.
     *
     * @param array $parameters
     * @param array $sources
     * @return array
     */
    private function sectionRelevance(array $parameters, array $sources)
    {
        $section = $this->section($parameters, 'relevance');
        $types = isset($sources['attribute_types'])
            ? $sources['attribute_types']
            : array();
        /*
         * D18. `ValueRelevanceTool::section()` is the one place that
         * reads both the bucket shape and the flat per-type map every
         * existing fork still carries, so the editor reads its output
         * rather than the raw section — a fork opens with its TTLs
         * intact and saving writes the current shape.
         */
        $shelf = ValueRelevanceTool::section($parameters);
        $buckets = $shelf['ttl_buckets'];
        $assigned = $shelf['ttl_types'];
        $overrides = $shelf['ttl_overrides'];

        /*
         * One row per bucket, each holding the types assigned to it —
         * not one row per attribute type. MISP has 194 types and the
         * old picker offered all of them, so an analyst saying *hashes
         * keep longer than IPs* had to say it once per type.
         *
         * **The day count is in the row too.** It used to be a column
         * of five number boxes above the table, and the table then
         * spent its key column repeating them — `Short — 90 days`
         * beside the chips, four hundred pixels from the box that
         * decides the 90. One row now carries the bucket, its length
         * and what is in it, which is the whole of what a bucket is.
         */
        $byBucket = array();
        foreach (ValueRelevanceTool::BUCKETS as $bucket) {
            $byBucket[$bucket] = array();
        }
        foreach ($assigned as $type => $bucket) {
            if (!isset($byBucket[$bucket])) {
                continue;
            }
            $byBucket[$bucket][] = (string)$type;
        }
        $assignmentEntries = array();
        foreach ($byBucket as $bucket => $members) {
            sort($members);
            $assignmentEntries[] = array(
                'key' => $bucket,
                'label' => $this->bucketLabel($bucket),
                'key_field' => array(
                    'key' => $bucket,
                    'type' => 'int',
                    'min' => 1,
                    'value' => isset($buckets[$bucket])
                        ? $buckets[$bucket]
                        : null,
                    'default' => ValueRelevanceTool::BUCKET_DAYS[$bucket],
                    'path' => array('relevance', 'ttl_buckets', $bucket),
                ),
                'value' => $members,
                'type' => 'types',
                'options' => $types,
                'taken' => $assigned,
                'path' => array('relevance', 'ttl_types'),
            );
        }
        /*
         * The default is a lifetime with no bucket, so it is the last
         * row rather than a field of its own: the table is then the
         * whole answer to *how long does this instance keep a type*,
         * and nothing is assigned to it by hand — what it holds is
         * everything the four rows above do not.
         */
        $assignmentEntries[] = array(
            'key' => 'ttl_default',
            'label' => __('Every other type'),
            'class' => 'ttl-def',
            'key_field' => array(
                'key' => 'ttl_default',
                'type' => 'int',
                'min' => 1,
                'value' => $shelf['ttl_default'],
                'default' => ValueRelevanceTool::DEFAULTS['ttl_default'],
                'path' => array('relevance', 'ttl_default'),
            ),
            'note' => __('everything not named above'),
        );

        $entries = array();
        foreach ($overrides as $type => $days) {
            $entries[] = array(
                'key' => (string)$type,
                'label' => (string)$type,
                'value' => $days,
                'type' => 'int',
                'unit' => __('days'),
                'min' => 1,
                'path' => array('relevance', 'ttl_overrides',
                    (string)$type),
            );
        }
        return array(
            'id' => 'relevance',
            'title' => __('Relevance'),
            'blurb' => __(
                'Whether what the record says still holds today. Kept'
                . ' separate from signal strength: an old value is not a'
                . ' better-evidenced one.'
            ),
            'blocks' => array(
                array(
                    'kind' => 'fields',
                    'id' => 'clock',
                    'title' => __('The clock'),
                    'fields' => array(
                        array(
                            'key' => 'clock',
                            'label' => __('Measure from'),
                            'type' => 'select',
                            'options' => $this->clockOptions(),
                            'value' => isset($section['clock'])
                                ? $section['clock']
                                : null,
                            'default' => 'last_independent_corroboration',
                            'help' => __(
                                'Somebody else confirming it means'
                                . ' anyone other than the original'
                                . ' reporter saying it again. Any'
                                . ' sighting counts sightings alone. Its'
                                . ' own newest record uses the most'
                                . ' recent time the value was recorded,'
                                . ' which every value has.'
                            ),
                            'path' => array('relevance', 'clock'),
                        ),
                        array(
                            'key' => 'decay_speed',
                            'label' => __('Decay speed'),
                            'type' => 'float',
                            /*
                             * `min` is inclusive, so it cannot say
                             * *above zero* — the server still refuses
                             * exactly 0. What it can do is stop the
                             * negatives, which is the case nothing was
                             * stopping.
                             */
                            'min' => 0,
                            'value' => isset($section['decay_speed'])
                                ? $section['decay_speed']
                                : null,
                            'default' => 1.0,
                            'help' => __(
                                '1 is a straight line. Below 1 holds its'
                                . ' value then drops off; above 1 drops'
                                . ' at once then lingers.'
                            ),
                            'path' => array('relevance', 'decay_speed'),
                        ),
                        array(
                            'key' => 'aging_fraction',
                            'label' => __('Call it aging below'),
                            'type' => 'float',
                            'min' => 0,
                            'max' => 1,
                            'unit' => __('of the lifetime left'),
                            'value' => isset($section['aging_fraction'])
                                ? $section['aging_fraction']
                                : null,
                            'default' => 0.33,
                            /*
                             * `Aging from` beside a box holding `0.33`
                             * reads as a date the box cannot take, and
                             * *the share of the TTL left* explained the
                             * units without ever saying what the number
                             * does. The label is the sentence now, and
                             * the help is the one thing a fraction
                             * cannot show on its own: which day it
                             * lands on, at the shelf life next to it.
                             */
                            'help' => $this->agingHelp(),
                            'path' => array('relevance', 'aging_fraction'),
                        ),
                        array(
                            'key' => 'undated_assumed_days',
                            'label' => __('Assume undated values are'
                                . ' older by'),
                            'type' => 'int',
                            'unit' => __('days'),
                            /*
                             * Zero is a real answer — *assume nothing*
                             * — so the bound is 0 and not 1. Negative
                             * is not: it would read a value as younger
                             * than its own record, which is the one
                             * direction the missing date cannot go.
                             */
                            'min' => 0,
                            /*
                             * Reads the old key too, so a fork written
                             * before the rename opens with the number
                             * its author chose rather than silently
                             * back at the default.
                             */
                            'value' => isset(
                                $section['undated_assumed_days']
                            )
                                ? $section['undated_assumed_days']
                                : (isset($section['lag_uncertain_days'])
                                    ? $section['lag_uncertain_days']
                                    : null),
                            'default' => 30,
                            'help' => __(
                                'When a value has no first-seen date,'
                                . ' read it as this many days older than'
                                . ' its record, and say so on every page'
                                . ' showing it. It ages sooner, but'
                                . ' never expires on the assumption. Set'
                                . ' 0 to add nothing.'
                            ),
                            'path' => array('relevance',
                                'undated_assumed_days'),
                        ),
                        array(
                            'key' => 'type_rule',
                            'label' => __('When a value has several'
                                . ' types'),
                            'type' => 'select',
                            'options' => $this->typeRuleOptions(),
                            'value' => isset($section['type_rule'])
                                ? $section['type_rule']
                                : null,
                            'default' => 'shortest',
                            'help' => __(
                                'One value can be an ip-src in one'
                                . ' event and an ip-dst in another, and'
                                . ' the two can sit in different'
                                . ' buckets. The shortest lifetime is'
                                . ' the cautious choice — a value stale'
                                . ' in any of its roles is worth'
                                . ' re-checking. The other two let a'
                                . ' type it barely appears as extend its'
                                . ' life.'
                            ),
                            'path' => array('relevance', 'type_rule'),
                        ),
                    ),
                ),
                array(
                    'kind' => 'map',
                    'id' => 'ttl_buckets',
                    'title' => __('Lifetime'),
                    'blurb' => __(
                        'How long a report stays relevant without being'
                        . ' confirmed again, for each bucket of attribute'
                        . ' types. Assign only the types you have an'
                        . ' opinion about; every other type takes the'
                        . ' last row.'
                    ),
                    'key_label' => __('Bucket'),
                    'key_field_label' => __('Days'),
                    'value_label' => __('Attribute types'),
                    'value_type' => 'types',
                    'path' => array('relevance', 'ttl_types'),
                    'entries' => $assignmentEntries,
                ),
                array(
                    'kind' => 'map',
                    'id' => 'ttl_overrides',
                    'title' => __('Types with their own lifetime'),
                    'blurb' => __(
                        'For a type that fits none of the buckets. The'
                        . ' shipped profile needs only one.'
                    ),
                    'key_label' => __('Attribute type'),
                    'value_label' => __('Days'),
                    'value_type' => 'int',
                    'path' => array('relevance', 'ttl_overrides'),
                    'entries' => $entries,
                    'add' => array(
                        'label' => __('Override a type'),
                        'source' => 'attribute_types',
                        'options' => $this->unusedKeys($types,
                            $overrides),
                    ),
                ),
            ),
        );
    }

    /**
     * A bucket's name in the reader's words. `very_long` is a key and
     * *very long* is a label, and the key is what a stored document
     * carries.
     *
     * @param string $bucket
     * @return string
     */
    private function bucketLabel($bucket)
    {
        $labels = array(
            'short' => __('Short'),
            'medium' => __('Medium'),
            'long' => __('Long'),
            'very_long' => __('Very long'),
        );
        return isset($labels[$bucket]) ? $labels[$bucket] : $bucket;
    }

    /**
     * The clock settings, as answers rather than as constant names.
     *
     * `ValueRelevanceTool::CLOCKS` is a validation list and stays one —
     * the stored document keeps `last_independent_corroboration`. What
     * was wrong is that the picker showed it: a `<select>` narrow
     * enough to fit the column rendered
     * `last_independent_corroborat…`, which is a key with its end cut
     * off rather than a choice being offered. The field asks *measure
     * from*, so each option finishes that sentence.
     *
     * @return array `{value, label}` pairs
     */
    private function clockOptions()
    {
        $labels = array(
            'last_independent_corroboration' => __('Somebody else'
                . ' confirming it'),
            'last_sighting' => __('Any sighting'),
            'last_occurrence' => __('Its own newest record'),
        );
        return $this->labelled(ValueRelevanceTool::CLOCKS, $labels);
    }

    /**
     * The `type_rule` settings, likewise.
     *
     * `shortest` alone does not say shortest *what*, and the three read
     * as adjectives with no noun. Each names the lifetime it takes.
     *
     * @return array `{value, label}` pairs
     */
    private function typeRuleOptions()
    {
        $labels = array(
            'shortest' => __('Take the shortest lifetime'),
            'longest' => __('Take the longest lifetime'),
            'most_common' => __('Take the type it appears as most'),
        );
        return $this->labelled(ValueRelevanceTool::TYPE_RULES, $labels);
    }

    /**
     * Pair a validation list with display labels, keeping its order.
     *
     * A setting with no label falls back to its own key rather than
     * vanishing: the constant is the authority on what may be stored,
     * and a value this map has not caught up with must still be
     * selectable.
     *
     * @param array $values
     * @param array $labels
     * @return array
     */
    private function labelled(array $values, array $labels)
    {
        $options = array();
        foreach ($values as $value) {
            $options[] = array(
                'value' => $value,
                'label' => isset($labels[$value])
                    ? $labels[$value]
                    : $value,
            );
        }
        return $options;
    }

    /**
     * What `aging_fraction` means.
     *
     * Two wrong readings, in the order they were reported. `Aging from`
     * over a box holding `0.33` read as a date the box cannot take; the
     * replacement, *Aging starts with this much left*, was worse in a
     * more interesting way — **it says aging begins there, and it does
     * not.** A value loses relevance continuously from the moment its
     * clock last reset. Nothing happens to the value at this point at
     * all: it is where the *page* stops calling it `current` and starts
     * calling it `aging`, which is a labelling threshold and not an
     * event. `Call it aging below` says that and cannot be read the
     * other way.
     *
     * **The day it lands on is deliberately not here.** It is what a
     * reader actually wants — and it is not `day 30` of 90 either,
     * because the decay speed bends the curve between the fraction and
     * the day — but this help is rendered once with the section, while
     * the curve beside it now redraws on every edit. A number printed
     * here would be right until the first keystroke and then argue with
     * the mark it is describing. It lives on the figure, which moves.
     *
     * @return string
     */
    private function agingHelp()
    {
        /*
         * The first sentence is the only one the pane shows, so it has
         * to carry the question that keeps being asked — *is aging the
         * same as expired?* It is not: `aging` is the middle of three
         * states and the value is still inside its lifetime there.
         * Saying what the number is a fraction *of* comes second,
         * because a reader who has the states wrong is not helped by
         * getting the units right.
         */
        return __(
            'Aging is the band between current and expired, not the end'
            . ' of the lifetime. This is a fraction of the lifetime'
            . ' left, not a number of days — the value has been losing'
            . ' relevance since its clock last reset, and the curve'
            . ' beside this marks the day it works out to.'
        );
    }

    /**
     * `reference` — what the analyst believes about their sources. Two
     * override maps and the scale they resolve through.
     *
     * Both maps default to *only what this profile overrides*, never a
     * row per organisation or per warninglist on the instance. An
     * instance has hundreds of organisations and the profile has an
     * opinion about four.
     *
     * @param array $parameters
     * @param array $sources
     * @return array
     */
    private function sectionReference(array $parameters, array $sources)
    {
        $section = $this->section($parameters, 'reference');
        $trust = isset($section['org_trust'])
            && is_array($section['org_trust'])
            ? $section['org_trust']
            : array();
        $scale = isset($section['org_trust_scale'])
            && is_array($section['org_trust_scale'])
            ? $section['org_trust_scale']
            : array();
        $categories = isset($section['warninglist_category'])
            && is_array($section['warninglist_category'])
            ? $section['warninglist_category']
            : array();
        $orgs = isset($sources['orgs']) ? $sources['orgs'] : array();
        $lists = isset($sources['warninglists'])
            ? $sources['warninglists']
            : array();
        /*
         * The scale as the engine will read it — the shipped defaults
         * with whatever this profile overrode — so the row can print
         * what the grade beside it is actually worth. A grade is a
         * letter until the number is next to it, and the number lives
         * in the block underneath, where nothing connects it to the
         * organisation it applies to.
         */
        $plan = ValueTrustTool::planFor($parameters);
        $factors = $plan['scale'];

        $trustEntries = array();
        foreach ($trust as $uuid => $grade) {
            $trustEntries[] = array(
                'key' => (string)$uuid,
                'label' => isset($orgs[$uuid])
                    ? $orgs[$uuid]
                    : (string)$uuid,
                'sub_label' => isset($orgs[$uuid]) ? (string)$uuid : null,
                'missing' => !isset($orgs[$uuid]),
                'value' => $grade,
                'type' => 'select',
                'options' => $this->gradeOptions(),
                'factor' => $this->factorLabel($factors, $grade),
                'path' => array('reference', 'org_trust', (string)$uuid),
            );
        }
        $scaleFields = array();
        $scaleMoved = 0;
        foreach (ValueTrustTool::DEFAULT_SCALE as $grade => $factor) {
            if (isset($scale[$grade]) && is_numeric($scale[$grade])
                && (float)$scale[$grade] !== (float)$factor
            ) {
                $scaleMoved++;
            }
            $scaleFields[] = array(
                'key' => (string)$grade,
                'label' => $this->gradeLabel((string)$grade),
                'type' => 'float',
                'value' => isset($scale[$grade]) ? $scale[$grade] : null,
                'default' => $factor,
                'path' => array('reference', 'org_trust_scale',
                    (string)$grade),
            );
        }
        $categoryEntries = array();
        foreach ($categories as $name => $category) {
            $categoryEntries[] = array(
                'key' => (string)$name,
                'label' => (string)$name,
                'missing' => !empty($lists) && !isset($lists[$name]),
                'value' => $category,
                'type' => 'select',
                'options' => $this->categoryLabelOptions(),
                'path' => array('reference', 'warninglist_category',
                    (string)$name),
            );
        }
        return array(
            'id' => 'reference',
            'title' => __('Sources & reputation'),
            'blurb' => __(
                'What you believe about your sources, and what a'
                . ' warninglist hit means.'
            ),
            'guide' => array(
                'title' => __('When to tune these'),
                'intro' => __(
                    'None of it is needed to start: every organisation'
                    . ' counts at face value and module verdicts are'
                    . ' shown without being counted. Grade the sources'
                    . ' you have an opinion about.'
                ),
                'items' => array(
                    array(
                        'symptom' => __('A partner is reliably careful,'
                            . ' or reliably not'),
                        'remedy' => __('Grade the organisation, and its'
                            . ' reports count for more or less.'),
                    ),
                    array(
                        'symptom' => __('An enrichment service\'s'
                            . ' verdicts should weigh in'),
                        'remedy' => __('Grade the module. Until then its'
                            . ' answers are shown, never counted.'),
                    ),
                    array(
                        'symptom' => __('A list hit reads as a false'
                            . ' positive, but the list is shared'
                            . ' infrastructure'),
                        'remedy' => __('Override that list as known'
                            . ' infrastructure.'),
                    ),
                ),
            ),
            'fold' => array(
                'label' => __('Fine-tuning'),
                'summary' => $scaleMoved === 0
                    ? __('grade multipliers as shipped')
                    : sprintf(__n('%d grade multiplier changed',
                        '%d grade multipliers changed', $scaleMoved),
                        $scaleMoved),
            ),
            'blocks' => array(
                array(
                    'kind' => 'map',
                    'id' => 'org_trust',
                    'title' => __('Organisation reputation'),
                    'blurb' => __(
                        "An organisation's reputation, as an Admiralty"
                        . ' grade, multiplies what its reports'
                        . ' contribute. F is neutral, the same as C —'
                        . ' the shipped taxonomy says so — and G is not'
                        . ' a low reputation but an accusation of'
                        . ' deception: worth nothing, deliberately.'
                        . ' Only the organisations you have graded;'
                        . ' every other one is unrated and worth 1.00,'
                        . ' and an empty map switches the weighting off'
                        . ' entirely.'
                    ),
                    'key_label' => __('Organisation'),
                    'value_label' => __('Grade'),
                    'empty_label' => __('No organisation graded'),
                    'empty_note' => __('Every organisation counts at'
                        . ' face value, ×1.00.'),
                    'value_type' => 'select',
                    'value_options' => $this->gradeOptions(),
                    'value_factors' => $factors,
                    /*
                     * Where the page reads a factor back from once the
                     * analyst edits one. The block below posts to this
                     * path, so the row's multiplier follows an edit to
                     * the scale instead of arguing with it.
                     */
                    'value_factor_path' => array('reference',
                        'org_trust_scale'),
                    'path' => array('reference', 'org_trust'),
                    'entries' => $trustEntries,
                    'add' => array(
                        'label' => __('Grade an organisation'),
                        'source' => 'orgs',
                        /*
                         * The only map here whose keys are not a list
                         * the page can hold. An instance carries
                         * thousands of organisations and the key is a
                         * uuid, so both a picker listing them all and a
                         * box taking one typed by hand are out — §4's
                         * restraint about what is *rendered* applied to
                         * what is *offered*. The names come one query
                         * at a time and the row keeps the uuid.
                         */
                        'search' => true,
                        'placeholder' => __('search organisations…'),
                        'options' => array(),
                    ),
                ),
                $this->moduleTrustBlock($section, $factors, $sources),
                array(
                    'kind' => 'fields',
                    'id' => 'org_trust_scale',
                    'advanced' => true,
                    'layout' => 'dense',
                    'title' => __('What a grade is worth'),
                    'blurb' => __(
                        'The multiplier each grade applies to what a'
                        . ' source contributes. A voice graded E counts as'
                        . ' a quarter of one.'
                    ),
                    'fields' => $scaleFields,
                ),
                array(
                    'kind' => 'map',
                    'id' => 'warninglist_category',
                    'title' => __('Warninglist categories'),
                    'blurb' => __(
                        'What a hit on each list means: known'
                        . ' infrastructure is not a false positive.'
                        . ' Each warninglist declares which kind it is;'
                        . ' this is where you override it.'
                    ),
                    'key_label' => __('Warninglist'),
                    'value_label' => __('Means'),
                    'empty_label' => __('No list overridden'),
                    'empty_note' => __('Each list keeps the category'
                        . ' it declares.'),
                    'value_type' => 'select',
                    'value_options' => $this->categoryLabelOptions(),
                    'value_legend' => $this->categoryLegend($parameters),
                    'path' => array('reference', 'warninglist_category'),
                    'entries' => $categoryEntries,
                    'add' => array(
                        'label' => __('Override a list'),
                        'source' => 'warninglists',
                        /*
                         * Small enough to send, too long to read. The
                         * whole roster fits in the page — unlike the
                         * organisations above — but a warninglist is
                         * named as a sentence and an instance carries
                         * a hundred of them, so the control offers the
                         * list and narrows it as you type rather than
                         * asking anybody to scroll to `Top 1000
                         * website from Alexa`.
                         */
                        'search' => true,
                        'placeholder' => __('filter warninglists…'),
                        'options' => $this->unusedKeys(
                            array_keys($lists), $categories),
                    ),
                ),
            ),
        );
    }

    /**
     * The admiralty grades, each one saying what it is.
     *
     * `A` through `G` and `unrated` are the whole vocabulary, and a
     * list of eight letters is a list of eight things the analyst has
     * to already know. The two that most need saying out loud are the
     * two a reader guesses wrong: `F` looks like the bottom of an
     * A–G scale and means *reliability cannot be judged*, which is
     * neutral, and `G` looks like the step below it and is not a
     * quality judgement at all.
     *
     * @return array `value`/`label` pairs, in scale order
     */
    private function gradeOptions()
    {
        $options = array();
        $grades = array_merge(ValueTrustTool::GRADES,
            array(ValueTrustTool::UNRATED));
        foreach ($grades as $grade) {
            $options[] = array(
                'value' => $grade,
                'label' => $this->gradeLabel($grade),
            );
        }
        return $options;
    }

    /**
     * What a grade is worth, as the row should print it.
     *
     * Two decimals always, so a column of them lines up and `1` and
     * `1.0` do not read as different numbers. A grade the scale has no
     * entry for prints nothing rather than `0.00` — an unresolvable
     * grade weights nothing *because it is dropped*
     * (`ValueTrustTool::planFor()` puts it in `invalid`), and printing
     * a zero would claim the organisation was deliberately zeroed.
     *
     * @param array $factors grade => float, the scale in force
     * @param mixed $grade
     * @return string|null
     */
    private function factorLabel(array $factors, $grade)
    {
        $key = ValueTrustTool::normaliseGrade($grade);
        if ($key === null || !isset($factors[$key])) {
            return null;
        }
        return '×' . number_format((float)$factors[$key], 2);
    }


    /**
     * The two warninglist categories, as a picker can offer them.
     *
     * `known` and `false_positive` are the column's own words and they
     * are the wrong way round for a reader: `known` sounds like *known
     * bad* and means *known infrastructure*, and a value can be both
     * that and malicious at once. The label carries the test rather
     * than the noun — `WarninglistCategory`'s *can a competent report
     * naming this value be simultaneously true?* — so the option says
     * which way the hit cuts without anybody having to look it up.
     *
     * Separate from `categoryOptions()`, which stays a list of bare
     * values because `referenceErrors()` validates against it.
     *
     * @return array `value`/`label` pairs
     */
    private function categoryLabelOptions()
    {
        return array(
            array(
                'value' => WarninglistCategory::FALSE_POSITIVE,
                'label' => __('false positive — the hit refutes the'
                    . ' report'),
            ),
            array(
                'value' => WarninglistCategory::KNOWN,
                'label' => __('known infrastructure — the hit explains'
                    . ' the report'),
            ),
        );
    }

    /**
     * What the two categories mean, and what choosing one does.
     *
     * The map let an analyst override a category and said nowhere what
     * either one was, so the control asked a question whose answer was
     * in a class docblock. Both halves are needed and they are
     * different halves: *what it means* is a fact about warninglists,
     * and *what it does* is a fact about **this** profile — the points
     * and the two rules are settings a few panes away, and quoting
     * them is the difference between explaining the mechanism and
     * describing it.
     *
     * So the numbers are read out of the document rather than written
     * here. A profile that zeroes `false_positive_hit` gets a legend
     * saying so, and one that disables the signal gets told that a
     * category currently decides nothing at all — which is the state
     * in which this whole map is a no-op, and the state most worth
     * being told about before editing it.
     *
     * @param array $parameters
     * @return array
     */
    private function categoryLegend(array $parameters)
    {
        $signals = $this->entriesById($parameters, 'signals');
        $rules = $this->entriesById($parameters, 'escalations');
        $signal = isset($signals['lifecycle.warninglist'])
            ? $signals['lifecycle.warninglist']
            : array();
        $on = !array_key_exists('enabled', $signal)
            || !empty($signal['enabled']);
        $points = isset($signal['points']) && is_array($signal['points'])
            ? $signal['points']
            : array();

        $entries = array(
            array(
                'value' => WarninglistCategory::FALSE_POSITIVE,
                'label' => __('false positive'),
                'meaning' => __(
                    'The list says the value is not an indicator at'
                    . ' all — a resolver address, an RFC1918 range, a'
                    . ' top-1000 domain. A competent report naming it'
                    . ' as malicious cannot also be true, so the hit'
                    . ' refutes the report.'
                ),
                'effect' => $this->categoryEffect(
                    $on,
                    $this->signalPoints($points, 'false_positive_hit'),
                    'conflict:listed-vs-asserted',
                    $rules,
                    __('flags the value contested, so the disagreement'
                        . ' is named rather than scored away')
                ),
            ),
            array(
                'value' => WarninglistCategory::KNOWN,
                'label' => __('known infrastructure'),
                'meaning' => __(
                    'The list says the value is shared infrastructure —'
                    . ' a CDN front, a hosting range. It does not argue'
                    . ' the value is harmless, only that it cannot be'
                    . ' attributed to one tenant, so a report naming it'
                    . ' can be true at the same time and the hit'
                    . ' explains the report rather than refuting it.'
                ),
                'effect' => $this->categoryEffect(
                    $on,
                    $this->signalPoints($points, 'known_hit'),
                    'conflict:known-infrastructure-vs-reporting',
                    $rules,
                    __('flags the value contested when enough'
                        . ' organisations still report it, rather than'
                        . ' the hit and the reporting netting off')
                ),
            ),
        );

        return array(
            'title' => __('What a category means, and what it does here'),
            'entries' => $entries,
            'note' => __(
                'A list this map does not name keeps the category it'
                . ' declares; a list that declares none reads as a false'
                . ' positive.'
            ),
        );
    }

    /**
     * One sentence on what a hit in this category is worth.
     *
     * @param bool $on Whether `lifecycle.warninglist` is enabled
     * @param int|null $points What the profile scores such a hit
     * @param string $rule The escalation keyed on this category
     * @param array $rules The profile's rules, by id
     * @param string $emits What that rule does when it fires
     * @return string
     */
    private function categoryEffect($on, $points, $rule, array $rules,
        $emits)
    {
        if (!$on) {
            return sprintf(
                __('Nothing, in this profile: lifecycle.warninglist is'
                    . ' switched off, so a hit scores no points at all.'
                    . ' The rule %s still reads the category.'),
                $rule
            );
        }
        $scored = $points === null
            ? __('Scores whatever lifecycle.warninglist is set to.')
            : sprintf(
                $points === 0
                    ? __('Scores %s on lifecycle.warninglist — counted'
                        . ' for neither side.')
                    : __('Scores %s on lifecycle.warninglist.'),
                $this->signed($points)
            );
        $enabled = !array_key_exists('enabled', isset($rules[$rule])
            ? $rules[$rule]
            : array())
            || !empty($rules[$rule]['enabled']);
        return $scored . ' ' . sprintf(
            $enabled
                ? __('The rule %1$s then %2$s.')
                : __('The rule %1$s would then %2$s, but it is switched'
                    . ' off in this profile.'),
            $rule,
            $emits
        );
    }

    /**
     * A points entry from the profile, or the signal's own default
     * where the profile names none.
     *
     * @param array $points
     * @param string $key
     * @return int|null
     */
    private function signalPoints(array $points, $key)
    {
        if (isset($points[$key]) && is_numeric($points[$key])) {
            return (int)$points[$key];
        }
        $signal = ValueSignalLoader::get('lifecycle.warninglist');
        if ($signal === null || !isset($signal->points_schema[$key])
            || !isset($signal->points_schema[$key]['default'])
        ) {
            return null;
        }
        return (int)$signal->points_schema[$key]['default'];
    }

    /**
     * A points figure with its sign, because the direction is the
     * whole point of the sentence it sits in.
     *
     * @param int $points
     * @return string
     */
    private function signed($points)
    {
        return $points > 0 ? '+' . $points : (string)$points;
    }

    /**
     * One grade, as the letter and what it means.
     *
     * The letter stays in front because it is what the document
     * stores, what the ledger's evidence line prints, and what an
     * analyst comparing this pane against the `admiralty-scale`
     * taxonomy is looking for.
     *
     * @param string $grade
     * @return string
     */
    private function gradeLabel($grade)
    {
        if (!isset(ValueTrustTool::GRADE_LABELS[$grade])) {
            return (string)$grade;
        }
        return sprintf('%s — %s', $grade,
            __(ValueTrustTool::GRADE_LABELS[$grade]));
    }

    /**
     * The warninglist categories a profile may assert.
     *
     * Taken from `WarninglistCategory` so the editor and the resolution
     * agree, and so the reference pane's override map and both conflict
     * rules' `when` offer one list rather than three copies of it.
     *
     * @return array
     */
    private function categoryOptions()
    {
        return WarninglistCategory::CATEGORIES;
    }

    /**
     * The shipped ledger groups.
     *
     * `ValueSignalBase` is included by the loader's scan rather than by
     * `App::uses` — it lives under `Model/ValueSignals/`, which is not a
     * package path, and the loader requires it directly so that it stays
     * runnable with no CakePHP booted. So the constant is reached
     * through a scan rather than assumed to be loaded, and the coupling
     * is one line here instead of a second copy of the list.
     *
     * @return array
     */
    private function baseGroups()
    {
        ValueSignalLoader::classes();
        return ValueSignalBase::GROUPS;
    }

    /**
     * `enrichment` — which modules the profile declares, for which
     * attribute types, and where each of them answers from.
     *
     * Nothing auto-runs (D15): the tab arrives with these ticked and a
     * run still takes a press, because MISP records nowhere that a
     * module has run and "run the defaults on page open" therefore
     * means running them on every page open.
     *
     * ## Keyed by module, though the document is keyed by type
     *
     * `auto_run` stores `type => {module: state}` and this block draws
     * `module => {type: state}`. The transpose is the whole redesign,
     * and it is arithmetic rather than taste. Measured on the dev
     * instance: **194 attribute types, 146 modules**, and the block
     * drawn the other way round was a 194-key map whose every row
     * offered all 146 — a table nobody could read and nobody could
     * maintain.
     *
     * Three facts make the transposed one small:
     *
     * - **A module declares what it accepts.** `mispattributes.input`
     *   has been there all along and the editor never read it, so a
     *   reader could file `virustotal` under `pdb` and hear about it
     *   only from the value tab, as `C_TYPE_MISMATCH`, long after.
     *   Median module accepts **3** types; 80 of 112 accept four or
     *   fewer. A row is short.
     * - **Rows are bounded by what an administrator enabled**, not by
     *   what MISP can store. Nine modules are enabled on the dev
     *   instance; the whole editable surface is nine rows.
     * - **Most types have no module at all.** The 146 accept 71
     *   distinct types between them, so 123 of the 194 could never
     *   have meant anything, and offering them was offering a
     *   declaration that could not resolve.
     *
     * ## The transpose costs nothing, once the tab is read correctly
     *
     * It looked like it did. The argument was that a type this map
     * does not carry keeps every enabled module *ticked*, so naming
     * one module for `ip-dst` would silently untick the rest — a
     * consequence visible keyed by type and invisible keyed by module,
     * which would need a second block to state.
     *
     * **The premise was false, and the old block blurb said it too.**
     * `value_enrichment_rail.ctp` builds `$picked` from
     * `$enrichment['profile']['selected']` and checks a box only for a
     * name in it, and `selected` holds exactly what the profile
     * declared for the types this value has. Measured on `8.8.8.8`
     * with the shipped default: **5 eligible modules, 3 ticked** — the
     * three declared, not five minus the declared. A module the
     * profile says nothing about arrives **unticked**, always.
     *
     * So the declaration adds ticks rather than removing them, there
     * is no hidden un-ticking to disclose, and a per-type summary
     * would have been restating the rows above it.
     *
     * @param array $parameters
     * @param array $sources
     * @return array
     */
    private function sectionEnrichment(array $parameters, array $sources)
    {
        $section = $this->section($parameters, 'enrichment');
        $source = isset($sources['modules']) && is_array($sources['modules'])
            ? $sources['modules']
            : array();
        $catalogue = isset($source['catalogue'])
            && is_array($source['catalogue'])
            ? $source['catalogue']
            : array();
        $reachable = !isset($source['reachable'])
            || !empty($source['reachable']);

        /*
         * D17: a declaration names a state per module, so the value is
         * a map and not a checklist — a checklist cannot express three
         * states, and `never` is the one that has to be expressible
         * because it is enforced where a run happens.
         *
         * `planFor()` is the one place that reads both the current
         * shape and the pre-D17 list, so the entries are built from
         * its output rather than from the raw section.
         */
        $plan = ValueEnrichmentTool::planFor(
            array('enrichment' => $section)
        );
        $byModule = $this->modulesByName($plan['auto_run']);
        $autoEntries = array();
        foreach ($byModule as $name => $states) {
            $autoEntries[] = $this->moduleEntry(
                $name,
                $states,
                $catalogue,
                $reachable
            );
        }
        return array(
            'id' => 'enrichment',
            'title' => __('Enrichment'),
            'blurb' => __(
                'Which modules to offer for each attribute type, and'
                . ' which of their answers to draw first. Nothing here'
                . ' runs a module on its own unless you choose that and'
                . ' an administrator has allowed it.'
            ),
            'blocks' => array(
                $this->shapeOrderBlock($section),
                array(
                    'kind' => 'map',
                    'id' => 'auto_run',
                    'title' => __('Modules, and the types you want them'
                        . ' asked about'),
                    'blurb' => __(
                        'One row per module, offering only the'
                        . ' attribute types that module accepts. This'
                        . ' decides which boxes arrive ticked on the'
                        . ' Enrichment tab — nothing here runs a'
                        . ' module, and a module you leave alone is'
                        . ' still there to tick by hand. Assume asking'
                        . ' a module tells somebody outside this'
                        . ' instance unless its row says otherwise.'
                    ),
                    'key_label' => __('Module'),
                    'value_label' => __('Attribute types'),
                    'empty_label' => __('No module declared'),
                    'empty_note' => __('Every module arrives unticked on'
                        . ' the Enrichment tab.'),
                    'value_legend' => $this->stateLegend(),
                    'value_type' => 'state_map',
                    /*
                     * What the page needs to draw this row itself.
                     * Without them the row it adds is a bare text box
                     * — the control `valueControl()` falls back to
                     * when it recognises no vocabulary — so declaring
                     * a module posted an empty value, the merge
                     * dropped the key, and the module was gone by the
                     * time the page came back. Exactly §7f.1's *the
                     * row the page added took a typed grade*, in the
                     * one map whose value is not a scalar.
                     *
                     * Keyed by module rather than one flat list,
                     * because the sub-rows now differ per row: every
                     * type row offered the same 146 modules, and no
                     * two module rows offer the same types.
                     */
                    'value_options' => $this->stateOptions(),
                    'value_rows' => $this->acceptedTypes($catalogue),
                    'unavailable_label' => __('not accepted'),
                    /*
                     * Past a dozen rows the table stops being
                     * scannable. The number is the point where the
                     * shipped default lands — twelve modules — so a
                     * profile that has only ever been forked from it
                     * does not get a control it has no use for.
                     */
                    'row_filter' => 12,
                    'row_filter_placeholder' => __('filter these'
                        . ' modules…'),
                    'path' => array('enrichment', 'auto_run_modules'),
                    'entries' => $autoEntries,
                    'add' => array(
                        'label' => __('Declare a module'),
                        'source' => 'modules',
                        /*
                         * Only modules this reader could actually use:
                         * present in the build, enabled here, and not
                         * reserved for another organisation. A module
                         * the instance has turned off is still drawn
                         * as a row when the profile already names it —
                         * see `moduleEntry()` — but offering it as a
                         * new choice would be offering a declaration
                         * that cannot resolve.
                         */
                        'search' => true,
                        'placeholder' => __('filter modules…'),
                        'options' => $this->unusedKeys(
                            $this->usableModules($catalogue),
                            $byModule
                        ),
                    ),
                ),
                /*
                 * Drawn again since phase 11. D23 withdrew it for the
                 * same reason it withdrew `auto` — there was no store,
                 * so the window governed nothing and a box for it was
                 * an unfinished promise. `value_enrichment_runs` is
                 * that store, and the number now decides how long an
                 * answer is served instead of asked for again.
                 */
                array(
                    'kind' => 'fields',
                    'id' => 'max_age_hours',
                    'title' => __('How long an answer stays good for'),
                    'blurb' => __(
                        'Once a module has answered about a value, that'
                        . ' answer is kept and shown to everyone in your'
                        . ' organisation rather than the module being'
                        . ' asked again. This is how long it is used'
                        . ' for. It bounds only what happens on its own'
                        . ' — pressing Run always asks again.'
                    ),
                    'fields' => array(
                        array(
                            'key' => 'max_age_hours',
                            'label' => __('Reuse an answer for'),
                            'type' => 'int',
                            'unit' => __('hours'),
                            'value' => isset($section['max_age_hours'])
                                ? $section['max_age_hours']
                                : null,
                            'default' =>
                                ValueEnrichmentTool::DEFAULT_MAX_AGE_HOURS,
                            'path' => array('enrichment', 'max_age_hours'),
                        ),
                    ),
                ),
            ),
        );
    }

    /**
     * How far this profile believes each enrichment module.
     *
     * The same judgement as the block above it, applied to a second
     * kind of source, so it uses the same vocabulary, the same scale
     * and the same control. *How far do I trust this?* asked twice
     * with two grading schemes would be the analyst learning the
     * question twice.
     *
     * **And the one asymmetry, which the blurb has to state**: an
     * ungraded organisation is worth 1.00 and an ungraded module is
     * worth nothing. MISP's own reports count by default; an outside
     * vendor's opinion is not something the shipped profile may assert
     * a weight for, so the rows appear in the ledger marked as not
     * counted until somebody grades the module. That makes grading one
     * a single visible act rather than a setting whose effect nobody
     * can find, and it is why this block sits beside the organisation
     * map rather than in the enrichment section: what it changes is a
     * score, not what gets run.
     *
     * @param array $section The stored `reference` section
     * @param array $factors The scale in force
     * @param array $sources
     * @return array
     */
    private function moduleTrustBlock(array $section, array $factors,
        array $sources
    ) {
        $grades = isset($section['module_trust'])
            && is_array($section['module_trust'])
            ? $section['module_trust']
            : array();
        $source = isset($sources['modules']) && is_array($sources['modules'])
            ? $sources['modules']
            : array();
        $catalogue = isset($source['catalogue'])
            && is_array($source['catalogue'])
            ? $source['catalogue']
            : array();
        $entries = array();
        foreach ($grades as $module => $grade) {
            $entries[] = array(
                'key' => (string)$module,
                'label' => (string)$module,
                /*
                 * A graded module the instance does not offer is drawn
                 * rather than dropped, the same way a graded
                 * organisation this instance does not have is: the
                 * grade is the analyst's judgement about a source and
                 * survives the source being turned off here.
                 */
                'missing' => !empty($catalogue)
                    && !isset($catalogue[(string)$module]),
                'value' => $grade,
                'type' => 'select',
                'options' => $this->gradeOptions(),
                'factor' => $this->factorLabel($factors, $grade),
                'path' => array('reference', 'module_trust',
                    (string)$module),
            );
        }
        return array(
            'kind' => 'map',
            'id' => 'module_trust',
            'title' => __('Enrichment module reputation'),
            'blurb' => __(
                'The same Admiralty grade, for the outside services'
                . ' your modules ask. It multiplies what a verdict from'
                . ' that module contributes to the assessment — and'
                . ' unlike an organisation, a module you have not'
                . ' graded is worth nothing rather than worth one. Its'
                . ' answers still appear in the ledger, marked as not'
                . ' counted, so you can see what was said before you'
                . ' decide whether it should count. Only verdicts are'
                . ' scored at all: where an address is, who announces'
                . ' it and when it was registered are drawn and never'
                . ' counted.'
            ),
            'key_label' => __('Module'),
            'value_label' => __('Grade'),
            'value_type' => 'select',
            'value_options' => $this->gradeOptions(),
            'value_factors' => $factors,
            'value_factor_path' => array('reference', 'org_trust_scale'),
            'empty_label' => __('No module graded'),
            'empty_note' => __('Module verdicts are shown, and none of'
                . ' them counts.'),
            'path' => array('reference', 'module_trust'),
            'entries' => $entries,
            'add' => array(
                'label' => __('Grade a module'),
                'source' => 'modules',
                'search' => true,
                'placeholder' => __('filter modules…'),
                /*
                 * Every module the build offers rather than only the
                 * enabled ones: a grade is knowledge about a source, and an analyst
                 * recording what they think of a service is right to
                 * do it before it is turned on rather than after.
                 */
                'options' => $this->unusedKeys(
                    array_keys($catalogue),
                    $grades
                ),
            ),
        );
    }

    /**
     * The ranking of visualisations, as an ordered block.
     *
     * The one setting in this section that is about **reading** rather
     * than about running: which of the answers already held get a
     * widget on the Overview, and in what order. It is a ranking of
     * *shapes* and never of modules, so the list stays about a dozen
     * stable entries instead of tracking every module name in the
     * build, and it survives a module being replaced by another that
     * answers the same question.
     *
     * **Only shapes this instance can draw are offered**, because a
     * ranking that names something no renderer here claims is a
     * declaration that cannot resolve. A shape the *document* already
     * names is drawn as a row whatever its standing — the same
     * restraint the module rows make — with what is wrong with it
     * stated on the row, so a profile written where a custom renderer
     * is installed survives being opened where it is not.
     *
     * **Three standings, not two**, and the middle one is the useful
     * one: a shape whose renderer is here but which nothing in the
     * modules build emits yet can be ranked, will keep a slot, and
     * will read *not asked* until somebody upstream moves. Saying that
     * at declaration time is the whole reason the renderers carry a
     * producer note.
     *
     * @param array $section The stored `enrichment` section
     * @return array
     */
    private function shapeOrderBlock(array $section)
    {
        $catalogue = ValueRendererTool::catalogue();
        $ranked = ValueEnrichmentTool::planFor(
            array('enrichment' => $section)
        );
        $ranked = $ranked['shapes'];
        $standing = ValueRendererTool::standingOf($ranked);
        $entries = array();
        foreach ($ranked as $shape) {
            $entries[] = array(
                'key' => $shape,
                'label' => $this->shapeLabel($shape),
                'description' => isset($catalogue[$shape])
                    ? $catalogue[$shape]['description']
                    : null,
                'standing' => $standing[$shape],
                'note' => $this->shapeNote($shape, $catalogue,
                    $standing[$shape]),
            );
        }
        $options = array();
        foreach ($catalogue as $id => $shape) {
            if (!in_array($id, $ranked, true)) {
                $options[$id] = $this->shapeLabel($id);
            }
        }
        asort($options);
        return array(
            'kind' => 'order',
            'id' => 'shapes',
            'title' => __('Which visualisations come first'),
            'blurb' => __(
                'The Overview draws up to five of these as widgets,'
                . ' in this order, out of answers already held — it'
                . ' runs nothing. Anything you rank keeps its place'
                . ' even when no module has answered it yet, and the'
                . ' slot says so; anything you leave off can still be'
                . ' drawn, in the order this instance ships for each'
                . ' attribute type. Rank nothing and that shipped order'
                . ' is what applies.'
            ),
            'empty_label' => __('Nothing ranked'),
            'empty_note' => __('Each attribute type uses the order this'
                . ' instance ships.'),
            'cap' => ValueRendererTool::STRIP_MAX,
            'cap_note' => __('Past the fifth, a ranking only matters'
                . ' when something above it is not drawn.'),
            'path' => array('enrichment', 'shapes'),
            'entries' => $entries,
            'add' => array(
                'label' => __('Rank a visualisation'),
                'search' => true,
                'placeholder' => __('filter visualisations…'),
                'options' => $options,
            ),
        );
    }

    /**
     * A shape id as a heading.
     *
     * Derived rather than looked up, for the reason the strip derives
     * it too: a table of seventeen labels is a second place for a
     * shape's name to live, and the ids are already written to be read.
     *
     * @param string $shape
     * @return string
     */
    private function shapeLabel($shape)
    {
        return ucfirst(str_replace('-', ' ', $shape));
    }

    /**
     * What is wrong with a ranked shape, where something is.
     *
     * @param string $shape
     * @param array $catalogue
     * @param string $standing
     * @return string|null
     */
    private function shapeNote($shape, array $catalogue, $standing)
    {
        if ($standing === 'unknown') {
            return __('No renderer on this instance draws this shape.'
                . ' It stays in your document and will draw again'
                . ' wherever one is installed.');
        }
        if ($standing === 'no_producer') {
            $note = isset($catalogue[$shape]['producer_note'])
                ? $catalogue[$shape]['producer_note']
                : null;
            return $note === null
                ? __('Nothing emits this shape yet.')
                : $note;
        }
        return null;
    }

    /**
     * The stored `type => {module: state}` read the other way up.
     *
     * Both orderings are stable: `planFor()` hands the types over in
     * document order and each module keeps the types in the order it
     * was declared for them, so a document that did not change does
     * not draw differently on the next load.
     *
     * @param array $autoRun From `planFor()`
     * @return array module => type => state
     */
    private function modulesByName(array $autoRun)
    {
        $out = array();
        foreach ($autoRun as $type => $states) {
            foreach ($states as $name => $state) {
                if (!isset($out[$name])) {
                    $out[$name] = array();
                }
                $out[$name][(string)$type] = $state;
            }
        }
        ksort($out);
        return $out;
    }

    /**
     * One row: a module, the types it accepts, and what this instance
     * has to say about it.
     *
     * **A declared module is drawn whatever its state**, which is the
     * half of this that only matters for a profile somebody else
     * wrote. Import is how most profiles arrive, the instance that
     * wrote one had a different set of modules enabled, and a row that
     * vanished — or worse, one that looked fine — would hide exactly
     * the gaps the reader needs to see before trusting the document.
     * So the four states `Module::getEnabledModules()` collapses are
     * kept apart here, in the order it applies them, and each says
     * what a reader would have to do about it.
     *
     * The types offered are the module's own `accepts`, plus any the
     * profile already filed it under that it does not accept — those
     * are flagged rather than dropped, for the same reason: a
     * declaration that cannot resolve is worth seeing.
     *
     * @param string $name
     * @param array $states type => state, from `modulesByName()`
     * @param array $catalogue From the controller
     * @param bool $reachable Whether the modules service answered
     * @return array
     */
    private function moduleEntry($name, array $states, array $catalogue,
        $reachable
    ) {
        $declared = array_keys($states);
        $facts = isset($catalogue[$name]) ? $catalogue[$name] : null;
        $accepts = $facts === null ? array() : $facts['accepts'];
        $options = $accepts;
        foreach ($declared as $type) {
            if (!in_array($type, $options, true)) {
                $options[] = $type;
            }
        }
        $entry = array(
            'key' => (string)$name,
            'label' => (string)$name,
            'value' => $states,
            'type' => 'state_map',
            'options' => $options,
            'state_options' => $this->stateOptions(),
            'states_built' => ValueEnrichmentTool::statesBuilt(),
            'unavailable' => $facts === null
                ? array()
                : array_values(array_diff($declared, $accepts)),
            'path' => array('enrichment', 'auto_run_modules',
                (string)$name),
            /*
             * One control that writes every select in the row. Most
             * declarations are *this module, for everything it
             * accepts* — `circl_passivedns` alone is six identical
             * choices — and setting them one at a time was the bulk of
             * the work the table asked for.
             */
            'bulk_label' => __('All types'),
            /*
             * Past this many, the row is a wall. Most are nowhere near
             * it (median 3), and the handful that are — 21 for
             * `farsight_passivedns` — are what the threshold is for.
             */
            'collapse_after' => 6,
        );
        $note = $this->moduleNote($facts, $reachable);
        if ($note !== null) {
            $entry['missing'] = true;
            $entry['missing_note'] = $note;
        }
        if ($facts !== null && !empty($facts['description'])) {
            $entry['sub_label'] = $facts['description'];
        }
        $entry['tags'] = $this->moduleTags($name, $facts);
        return $entry;
    }

    /**
     * The two things worth knowing beside a module's name while you
     * are deciding about it.
     *
     * **Where it answers from**, because *does asking this tell
     * somebody outside* is the question being answered at the moment
     * of choosing.
     *
     * **Whether it can answer at all**, for a module that is enabled
     * and missing the settings it cannot work without. That one is the
     * quietest failure the page has — the row looks healthy and the
     * error arrives on press — and `ModuleCredentials` is deliberately
     * silent wherever it cannot defend the claim.
     *
     * @param string $name
     * @param array|null $facts
     * @return array `label` and `tone` pairs
     */
    private function moduleTags($name, $facts)
    {
        $tags = array();
        $where = ModuleLocality::resolve($name);
        /*
         * **`unknown` gets no pill**, and that is the common case
         * rather than an edge: `ModuleLocality` names the local
         * modules and almost none of them are ones a *value* page has
         * a type for, so every row of the shipped default resolved
         * `unknown` and wore the same words. A badge that says the
         * same thing on every row is wallpaper — the reader stops
         * seeing it, including on the row where it differs.
         *
         * So the presumption is stated once, in the block's blurb —
         * asking a module tells somebody outside unless it says
         * otherwise — and the pill marks only the modules known to
         * answer from inside.
         */
        if ($where['locality'] === ModuleLocality::LOCAL) {
            $tags[] = array(
                'label' => __('stays local'),
                'tone' => 'plain',
                'title' => __('Nothing about the value leaves this instance'
                    . ' when this module is asked.'),
            );
        }
        if ($facts !== null && !empty($facts['unset_required'])) {
            $tags[] = array(
                'label' => __('needs settings'),
                'tone' => 'missing',
                'title' => sprintf(
                    __n(
                        'Enabled here, but %s is not set. It will fail'
                        . ' when run until an administrator fills it'
                        . ' in under Plugin settings.',
                        'Enabled here, but %s are not set. It will'
                        . ' fail when run until an administrator fills'
                        . ' them in under Plugin settings.',
                        count($facts['unset_required'])
                    ),
                    implode(', ', $facts['unset_required'])
                ),
            );
        }
        return $tags;
    }

    /**
     * Why a declared module would not answer here, or null when it
     * would.
     *
     * The order is `getEnabledModules()`'s own, so the sentence a
     * reader gets names the first thing that actually stopped the
     * module rather than the most interesting one — the same rule
     * `ValueEnrichmentTool::explain()` follows, because the two say
     * the same things in different places and must not disagree.
     *
     * @param array|null $facts
     * @param bool $reachable
     * @return string|null
     */
    private function moduleNote($facts, $reachable)
    {
        if (!$reachable) {
            return __(
                'Defined in the profile. The modules service is not'
                . ' answering, so it could not be checked.'
            );
        }
        if ($facts === null) {
            return __(
                'Defined in the profile, unknown on this instance —'
                . ' not in this modules build, or renamed.'
            );
        }
        if (empty($facts['enabled'])) {
            return __(
                'Defined in the profile, disabled on this instance.'
                . ' An administrator turns it on under Plugin'
                . ' settings.'
            );
        }
        if (!empty($facts['restricted'])) {
            return __(
                'Defined in the profile, reserved for another'
                . ' organisation on this instance.'
            );
        }
        return null;
    }

    /**
     * The types each module accepts, for the page to draw a row it
     * adds itself.
     *
     * **Only the modules the picker can offer.** The page reads this
     * when a row is added and never otherwise, and the picker offers
     * what a reader can use — so carrying the whole roster put 118
     * modules and their type lists into an attribute on every editor
     * load to answer at most one of them. §4's rule about not sending
     * 900 organisations to say something about four, in the block that
     * had quietly started doing it.
     *
     * @param array $catalogue
     * @return array name => list of types
     */
    private function acceptedTypes(array $catalogue)
    {
        $out = array();
        foreach ($catalogue as $name => $facts) {
            if (empty($facts['enabled']) || !empty($facts['restricted'])) {
                continue;
            }
            $out[$name] = $facts['accepts'];
        }
        return $out;
    }

    /**
     * The modules a reader could pick today: offered, enabled here,
     * and not reserved elsewhere.
     *
     * @param array $catalogue
     * @return array
     */
    private function usableModules(array $catalogue)
    {
        $out = array();
        foreach ($catalogue as $name => $facts) {
            if (!empty($facts['enabled']) && empty($facts['restricted'])) {
                $out[] = $name;
            }
        }
        return $out;
    }

    /**
     * The run states, each saying what it actually changes.
     *
     * Three words that look like three behaviours and are not.
     * `stateFor()` returns `ticked` for a module the declaration does
     * not name, so **the blank option and `ticked` resolve to the same
     * thing** — the select offered both and said nowhere that one of
     * them is a no-op you have chosen to write down. `never` is the
     * only state that takes anything away, and it is taken away at the
     * run endpoint rather than by unticking a box
     * (`ValueEnrichmentTool::refuses()`), which is worth saying
     * because it is the difference between a default and a refusal.
     * **`auto` is storable and not offered.** The schema carries
     * it and the run path does not, so an editor offering it
     * would be selling a behaviour nothing implements; a
     * document that already declares one still says so, because
     * `state_map` offers any state it finds stored.
     *
     * Short, because eight of these stack in one row and a label long
     * enough to explain itself is a label the box cuts off. The rest
     * goes under the table, which is `categoryLegend()`'s division
     * again: the option carries enough to choose by, the legend
     * carries what it does.
     *
     * @return array `value`/`label` pairs, blank first
     */
    private function stateOptions()
    {
        return array(
            array(
                'value' => '',
                'label' => __('Nothing'),
            ),
            array(
                'value' => ValueEnrichmentTool::STATE_TICKED,
                'label' => __('Pre-select, ready to run'),
            ),
            array(
                'value' => ValueEnrichmentTool::STATE_NEVER,
                'label' => __('Block, running is refused'),
            ),
            /*
             * Offered again since phase 11. D23 removed it because the
             * editor offers only what is implemented and `auto` did
             * nothing; the same rule puts it back now that it runs.
             * Whether it runs *here* is the instance's call, and the
             * tab says so per module when the answer is no.
             */
            array(
                'value' => ValueEnrichmentTool::STATE_AUTO,
                'label' => __('Auto, run it on its own'),
            ),
        );
    }

    /**
     * What the three run states do, under the table that offers them.
     *
     * Two of them are the same behaviour, which is not a thing four
     * words in a select can carry. The one worth reading twice is
     * `never`: every other state decides whether a box arrives
     * ticked, and `never` is checked again at the run endpoint,
     * because a disabled checkbox is not a guard (D17).
     *
     * **The labels name the effect, not the stored key.** They read
     * `ticked — the same, written down` and `not declared — offered
     * ticked` until 2026-09-12, which asked the reader to hold the
     * storage format in their head *and* was wrong: a module the
     * profile does not name is not offered ticked, it arrives
     * unticked. Both halves are fixed here, and the note under the
     * table says the thing the blank state is actually for — leaving a
     * module alone does not block it.
     *
     * @return array
     */
    private function stateLegend()
    {
        return array(
            'title' => __('What each choice does on the Enrichment tab'),
            'entries' => array(
                array(
                    'value' => '',
                    'label' => __('Nothing'),
                    'meaning' => __(
                        'The profile has no opinion about this module'
                        . ' for this type. It still appears on the tab'
                        . ' with its box empty, and you can tick it and'
                        . ' run it whenever you want.'
                    ),
                    'effect' => __('box empty, running it is up to you'),
                ),
                array(
                    'value' => ValueEnrichmentTool::STATE_TICKED,
                    'label' => __('Pre-select, ready to run'),
                    'meaning' => __(
                        'The box arrives already ticked, so running it'
                        . ' is one press instead of two. Ticking is not'
                        . ' running: nothing is sent anywhere until you'
                        . ' press Run.'
                    ),
                    'effect' => __('box ticked, still waits for your'
                        . ' press'),
                ),
                array(
                    'value' => ValueEnrichmentTool::STATE_NEVER,
                    'label' => __('Block, running is refused'),
                    'meaning' => __(
                        'The only choice that takes something away. The'
                        . ' box is empty and ticking it by hand will'
                        . ' not work either — the run is refused and'
                        . ' the tab says why.'
                    ),
                    'effect' => __('cannot be run at all for this type'),
                ),
                array(
                    'value' => ValueEnrichmentTool::STATE_AUTO,
                    'label' => __('Auto, run it on its own'),
                    'meaning' => __(
                        'The only choice that sends something without'
                        . ' you asking: opening a value of this type'
                        . ' queries the module and the answer is'
                        . ' waiting for you. An administrator has to'
                        . ' allow this for the instance first, and'
                        . ' until they do it behaves like'
                        . ' pre-selecting. An answer already fetched'
                        . ' recently is reused rather than asked for'
                        . ' again.'
                    ),
                    'effect' => __('runs by itself, if the instance'
                        . ' allows it'),
                ),
            ),
        );
    }

    /**
     * A setting whose fallback is another setting, drawn as an empty box
     * that says what it is following.
     *
     * Two things make this more than a placeholder. **The word is not a
     * value**: `ValueEscalationBase::shareThreshold()` reads anything
     * that is not a number as *follow the profile*, so `supermajority`
     * and an absent key have always meant the same thing — printing the
     * word into a box invites an analyst to edit a sentinel as though
     * it were a threshold. It is shown as empty instead, which is what
     * the engine already reads it as, and a save then writes it away.
     *
     * **And the number is the profile's, not the schema's.** The box
     * names the fallback and shows what it currently resolves to, read
     * with the engine's own function — a second copy of
     * `lean_supermajority`'s validity rule here would be a placeholder
     * that lies the day somebody stores `0.4`.
     *
     * One setting is followed and one resolver answers for it, so the
     * spec names the word rather than a path: a second `follows` field
     * would want a resolver named beside it, and inventing that slot
     * before there is a second one is a guess about what it needs.
     *
     * @param array $field
     * @param array $follows The `name` the fallback is written as
     * @param array $parameters
     * @return array
     */
    private function following(array $field, array $follows,
        array $parameters
    ) {
        if ($field['value'] !== null && !is_numeric($field['value'])) {
            $field['value'] = null;
        }
        $resolved = ValueLeanTool::supermajority(
            array('parameters' => $parameters));
        $field['placeholder'] = sprintf(
            '%s · %s',
            $follows['name'],
            $resolved
        );
        $field['resolved'] = $resolved;
        $field['follows'] = $follows['name'];
        return $field;
    }

    /**
     * A form for a schema the tool has never seen, which is what makes a
     * dropped-in signal configurable without hand-edited JSON.
     *
     * @param array $schema key => spec
     * @param array $stored The map as the profile carries it
     * @param array $prefix The path segments this map lives under
     * @param array $parameters The whole document, for a spec whose
     *                          fallback is another setting in it
     * @return array
     */
    private function generatedFields(array $schema, array $stored,
        array $prefix, array $parameters = array()
    ) {
        $fields = array();
        foreach ($schema as $key => $spec) {
            $field = array(
                'key' => $key,
                'label' => isset($spec['label']) ? $spec['label'] : $key,
                'type' => isset($spec['type']) ? $spec['type'] : 'int',
                'value' => array_key_exists($key, $stored)
                    ? $stored[$key]
                    : null,
                'default' => isset($spec['default'])
                    ? $spec['default']
                    : null,
                'path' => array_merge($prefix, array($key)),
                'generated' => true,
            );
            if (isset($spec['options'])) {
                $field['type'] = 'select';
                $field['options'] = $spec['options'];
            }
            if (isset($spec['help'])) {
                $field['help'] = $spec['help'];
            }
            if (isset($spec['unit'])) {
                $field['unit'] = $spec['unit'];
            }
            foreach (array('min', 'max') as $bound) {
                if (isset($spec[$bound])) {
                    $field[$bound] = $spec[$bound];
                }
            }
            if (isset($spec['follows'])) {
                $field = $this->following($field, $spec['follows'],
                    $parameters);
            }
            $fields[] = $field;
        }
        /*
         * A key the profile carries that the schema does not describe.
         * Not an error — a profile written against a later version of a
         * signal has to survive a downgrade (`ValueSignalBase`) — so it
         * is rendered as what it is: a value this version cannot label.
         */
        foreach ($stored as $key => $value) {
            if (isset($schema[$key]) || is_array($value)) {
                continue;
            }
            $fields[] = array(
                'key' => $key,
                'label' => $key,
                'type' => is_float($value) ? 'float'
                    : (is_int($value) ? 'int' : 'string'),
                'value' => $value,
                'default' => null,
                'path' => array_merge($prefix, array($key)),
                'generated' => true,
                'undeclared' => true,
            );
        }
        return $fields;
    }

    /**
     * The most this profile's enabled signals could contribute, and how
     * that number was arrived at.
     *
     * **The rule: the largest positive value in a signal's `points`
     * map, or the sum of its positive caps where that is larger.** A
     * signal paying two capped rows — `attribution.galaxy`'s occurrence
     * and event clusters (`cap`, `event_cap`), `enrichment.answer`'s
     * verdicts and agreement (`cap`, `agreeing_cap`) — can reach both
     * caps at once, and the largest term alone would under-report it.
     * A cap is a key named `cap` or ending in `_cap`.
     *
     * **What it is: an upper bound, and only for a signal whose points
     * bound it.** A custom signal paying `per_x` with no cap is not
     * bounded by its own points, and this would under-report it. That is
     * why `unbounded` is returned alongside the total rather than
     * folded into it — the caller refuses a band above the bound, and
     * a bound with an unbounded signal under it is a bound the caller
     * should not refuse on. Stated rather than papered over: a derived
     * number that quietly rejects a legitimate edit is worse than one
     * that says where it stops being reliable.
     *
     * A declared maximum on the signal class was the alternative and
     * was rejected for D14's reason in a new place: a number an author
     * maintains by hand duplicates their own arithmetic and drifts from
     * it silently, where a derived one cannot.
     *
     * @param array $parameters
     * @return array `bound`, `per_signal`, `unbounded`, `signals`
     */
    public function attainable(array $parameters)
    {
        $catalogue = ValueSignalLoader::catalogue();
        $perSignal = array();
        $unbounded = array();
        $bound = 0;
        $counted = 0;
        foreach ($this->entriesById($parameters, 'signals') as $id => $entry) {
            if (array_key_exists('enabled', $entry)
                && empty($entry['enabled'])
            ) {
                continue;
            }
            if (!isset($catalogue[$id])) {
                // Cannot run here, so it can contribute nothing.
                continue;
            }
            $counted++;
            $points = isset($entry['points']) && is_array($entry['points'])
                ? $entry['points']
                : array();
            $best = 0;
            $caps = 0;
            $positive = false;
            foreach ($points as $key => $value) {
                if (!is_int($value) && !is_float($value)) {
                    continue;
                }
                if ($value > $best) {
                    $best = $value;
                    $positive = true;
                }
                if ($value > 0 && ($key === 'cap'
                    || substr((string)$key, -4) === '_cap')
                ) {
                    $caps += $value;
                }
            }
            $best = max($best, $caps);
            $perSignal[$id] = (int)$best;
            $bound += (int)$best;
            /*
             * A signal with a positive term and no key at least as
             * large as its own product cannot be bounded from here. The
             * cheap and honest test is whether it declares a cap at
             * all: the shipped six do, under the key `cap`, and a
             * custom signal that pays per unit without one is the case
             * this cannot see.
             */
            if ($positive && !array_key_exists('cap', $points)
                && count($points) > 0
                && $this->looksPerUnit($points)
            ) {
                $unbounded[] = $id;
            }
        }
        return array(
            'bound' => $bound,
            'per_signal' => $perSignal,
            'unbounded' => $unbounded,
            'signals' => $counted,
            'reliable' => empty($unbounded),
        );
    }

    /**
     * Whether a points map reads as *paid per something* — a key named
     * `per…`, which is the convention every shipped signal that
     * multiplies by a count follows, and every one of those declares a
     * `cap` beside it.
     *
     * `scale` is deliberately not here, and the distinction is the whole
     * point of the test rather than a detail: `reporting.published_ratio`
     * pays `scale × published / events`, and the multiplicand is a ratio
     * at most 1 — so `scale` *is* its maximum and the signal is bounded
     * by its own points with no cap. Treating it as per-unit made
     * `reliable` false for the shipped default, which would have turned
     * §7a item 8's refusal into an advisory on every instance. Measured
     * against all eleven shipped signals: with `scale` excluded, six
     * declare a `per…` key and all six declare a `cap`, so the shipped
     * catalogue is fully bounded.
     *
     * @param array $points
     * @return bool
     */
    private function looksPerUnit(array $points)
    {
        foreach (array_keys($points) as $key) {
            if (strpos((string)$key, 'per') === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * The band boundaries drawn against the attainable range, so a band
     * above the one above it — or beyond anything the catalogue can
     * reach — is visibly wrong rather than silently saved.
     *
     * @param array $parameters
     * @return array
     */
    public function bandStrip(array $parameters)
    {
        $thresholds = $this->section($parameters, 'thresholds');
        $bands = isset($thresholds['signal_strength_bands'])
            && is_array($thresholds['signal_strength_bands'])
            ? $thresholds['signal_strength_bands']
            : array();
        $high = isset($bands['high']) ? (int)$bands['high'] : 60;
        $medium = isset($bands['medium']) ? (int)$bands['medium'] : 30;
        $attainable = $this->attainable($parameters);
        $bound = $attainable['bound'];
        $problems = array();
        if ($medium >= $high) {
            $problems[] = array(
                'band' => 'medium',
                'message' => sprintf(
                    __('Medium starts at %1$d, which is not below high'
                        . ' at %2$d. Nothing could ever be high.'),
                    $medium,
                    $high
                ),
            );
        }
        foreach (array('high' => $high, 'medium' => $medium) as $band => $at) {
            if ($at <= $bound) {
                continue;
            }
            $problems[] = array(
                'band' => $band,
                'message' => sprintf(
                    __('%1$s starts at %2$d, and the enabled signals'
                        . ' cannot sum past %3$d. Nothing could ever'
                        . ' reach %1$s.'),
                    $band,
                    $at,
                    $bound
                ),
                'advisory' => !$attainable['reliable'],
            );
        }
        return array(
            'bound' => $bound,
            'attainable' => $attainable,
            'bands' => array(
                array(
                    'id' => 'high',
                    'from' => $high,
                    'to' => max($high, $bound),
                ),
                array(
                    'id' => 'medium',
                    'from' => $medium,
                    'to' => $high,
                ),
                array(
                    'id' => 'low',
                    'from' => 0,
                    'to' => $medium,
                ),
            ),
            'problems' => $problems,
            'ok' => empty($problems),
        );
    }

    /**
     * Everything wrong with a document, as sentences.
     *
     * Phase 1 asked only whether `parameters` parses into an object and
     * left each section's contract to the phase that owns it. This is
     * where those contracts are finally checked together, because the
     * editor is the first caller that can refuse an edit before it is
     * stored.
     *
     * A **warning** is a statement about a document that is still
     * saveable — a signal this instance does not have, an organisation
     * key that is not a uuid — and it is returned separately, because
     * refusing to save a profile written for a different instance would
     * make export and import useless.
     *
     * @param array $parameters
     * @return array `errors` and `warnings`, both lists of strings
     */
    public function validate(array $parameters)
    {
        $errors = array();
        $warnings = array();

        foreach (array_keys($parameters) as $key) {
            if ($key === 'format'
                || in_array($key, self::SECTION_ORDER, true)
            ) {
                continue;
            }
            $warnings[] = sprintf(
                __('`%s` is not a section this version knows about. It'
                    . ' is kept and ignored.'),
                $key
            );
        }
        foreach (array('signals', 'escalations', 'exclusions') as $name) {
            if (isset($parameters[$name]) && !$this->isList($parameters[$name])) {
                $errors[] = sprintf(
                    __('`%s` must be a list of entries, each with an'
                        . ' `id`.'),
                    $name
                );
            }
        }
        $strip = $this->bandStrip($parameters);
        foreach ($strip['problems'] as $problem) {
            if (!empty($problem['advisory'])) {
                $warnings[] = $problem['message'] . ' ' . sprintf(
                    __('Not refused, because %s is paid per unit with'
                        . ' no cap and the bound cannot see it.'),
                    implode(', ', $strip['attainable']['unbounded'])
                );
                continue;
            }
            $errors[] = $problem['message'];
        }

        $thresholds = $this->section($parameters, 'thresholds');
        if (isset($thresholds['lean_supermajority'])) {
            $share = $thresholds['lean_supermajority'];
            if (!is_numeric($share) || $share <= 0.5 || $share > 1) {
                $errors[] = __(
                    'The lean supermajority must be above 0.5 and at'
                    . ' most 1. A share at or below half is not a'
                    . ' majority, and one above 1 can never be met.'
                );
            }
        }

        $clampSection = isset($thresholds['thin_record_clamp'])
            && is_array($thresholds['thin_record_clamp'])
            ? $thresholds['thin_record_clamp']
            : array();
        if (isset($clampSection['max_voices'])
            && (!is_numeric($clampSection['max_voices'])
                || $clampSection['max_voices'] < 0)
        ) {
            $errors[] = __('The thin-record clamp\'s source count must be'
                . ' a number of zero or more.');
        }
        foreach ($clampSection['max_band_by_grade'] ?? array()
            as $grade => $band
        ) {
            if (!in_array($grade, ValueTrustTool::GRADES, true)
                || !in_array($band, ValueVerdictTool::BANDS, true)
            ) {
                $errors[] = sprintf(
                    __('The clamp by grade names `%1$s` → `%2$s`; it'
                        . ' takes a grade A to G and a band.'),
                    (string)$grade,
                    is_scalar($band) ? (string)$band : gettype($band)
                );
            }
        }
        if (isset($thresholds['dispute_stale_factor'])) {
            $factor = $thresholds['dispute_stale_factor'];
            if (!is_numeric($factor) || $factor < 0 || $factor > 1) {
                $errors[] = __(
                    'The weight of an old dispute must be between 0'
                    . ' and 1: it is a share of one voice.'
                );
            }
        }

        $catalogue = ValueSignalLoader::catalogue();
        foreach ($this->entriesById($parameters, 'signals') as $id => $entry) {
            $signal = ValueSignalLoader::get($id);
            if ($signal === null) {
                $warnings[] = sprintf(
                    __('`%s` is not implemented on this instance. It'
                        . ' contributes nothing and is kept.'),
                    $id
                );
                continue;
            }
            foreach ($signal->validateEntry($entry) as $error) {
                $errors[] = $error;
            }
        }
        foreach ($this->entriesById($parameters, 'escalations')
            as $id => $entry
        ) {
            $rule = ValueSignalLoader::get($id,
                ValueSignalLoader::SUBJECT_ESCALATION);
            if ($rule === null) {
                $warnings[] = sprintf(
                    __('`%s` is not a conflict rule this instance has.'
                        . ' It cannot fire and is kept.'),
                    $id
                );
                continue;
            }
            foreach ($rule->validateEntry($entry) as $error) {
                $errors[] = $error;
            }
        }
        $exclusions = ValueExclusionTool::catalogue();
        foreach ($this->entriesById($parameters, 'exclusions')
            as $id => $entry
        ) {
            if (!isset($exclusions[$id])) {
                $warnings[] = sprintf(
                    __('`%s` is not an exclusion this version has. The'
                        . ' set is closed in code; the entry does'
                        . ' nothing.'),
                    $id
                );
                continue;
            }
            foreach ($exclusions[$id]['schema'] as $key => $spec) {
                if (!array_key_exists($key, $entry)) {
                    continue;
                }
                $error = $this->checkScalar($entry[$key], $spec,
                    $id . '.' . $key);
                if ($error !== null) {
                    $errors[] = $error;
                }
            }
        }

        foreach ($this->relevanceErrors($parameters) as $error) {
            $errors[] = $error;
        }
        foreach ($this->referenceErrors($parameters) as $error) {
            $errors[] = $error;
        }
        foreach ($this->enrichmentErrors($parameters) as $error) {
            $errors[] = $error;
        }
        foreach ($this->contextErrors($parameters) as $error) {
            $errors[] = $error;
        }
        foreach ($this->contextWarnings($parameters) as $warning) {
            $warnings[] = $warning;
        }
        return array('errors' => $errors, 'warnings' => $warnings);
    }

    /**
     * What a hand-written `context` or `galaxies` section can get wrong
     * badly enough to refuse.
     *
     * Only the shape, and deliberately: a tier naming a taxonomy this
     * instance does not have is a document written elsewhere, which is
     * what import exists for, and `planFor()` reads it without
     * complaint. What cannot be read at all is a tier that is not a
     * list of names.
     *
     * @param array $parameters
     * @return array
     */
    private function contextErrors(array $parameters)
    {
        $errors = array();
        $context = $this->section($parameters, 'context');
        foreach (array(ValueLabelPriority::TAXONOMIES,
            ValueLabelPriority::GALAXIES) as $scope
        ) {
            if (!isset($context[$scope])) {
                continue;
            }
            if (!is_array($context[$scope])) {
                $errors[] = sprintf(
                    __('`context.%s` must hold the three tiers.'),
                    $scope
                );
                continue;
            }
            foreach ($context[$scope] as $tier => $names) {
                if (!in_array($tier, ValueLabelPriority::TIERS, true)) {
                    continue;
                }
                if (!$this->isList($names)) {
                    $errors[] = sprintf(
                        __('`context.%1$s.%2$s` must be a list of'
                            . ' names.'),
                        $scope,
                        $tier
                    );
                }
            }
        }
        if (isset($context['markings']) && !$this->isList($context['markings'])) {
            $errors[] = __('`context.markings` must be a list of taxonomy'
                . ' namespaces.');
        }
        if (array_key_exists(ValueLabelPriority::SHOW_ASSESSMENT, $context)
            && !is_bool($context[ValueLabelPriority::SHOW_ASSESSMENT])
        ) {
            $errors[] = __('`context.show_assessment` must be true or'
                . ' false.');
        }
        $galaxies = $this->section($parameters, 'galaxies');
        if (isset($galaxies['attribution'])
            && !$this->isList($galaxies['attribution'])
        ) {
            $errors[] = __('`galaxies.attribution` must be a list of'
                . ' galaxy types.');
        }
        return $errors;
    }

    /**
     * What is saveable and worth saying out loud.
     *
     * A name in two tiers is the one an editor cannot produce and a
     * hand-written document can: `planFor()` resolves it to the first
     * tier in precedence order, and an analyst who wrote both should
     * hear which half is being ignored rather than discover it from a
     * card.
     *
     * @param array $parameters
     * @return array
     */
    private function contextWarnings(array $parameters)
    {
        $warnings = array();
        $context = $this->section($parameters, 'context');
        foreach (array(ValueLabelPriority::TAXONOMIES,
            ValueLabelPriority::GALAXIES) as $scope
        ) {
            if (empty($context[$scope]) || !is_array($context[$scope])) {
                continue;
            }
            $seen = array();
            foreach (ValueLabelPriority::TIERS as $tier) {
                if (empty($context[$scope][$tier])
                    || !is_array($context[$scope][$tier])
                ) {
                    continue;
                }
                foreach ($context[$scope][$tier] as $name) {
                    if (!is_string($name) && !is_numeric($name)) {
                        continue;
                    }
                    $name = mb_strtolower(trim((string)$name));
                    if ($name === '') {
                        continue;
                    }
                    if (isset($seen[$name])) {
                        $warnings[] = sprintf(
                            __('`%1$s` is in both `%2$s` and `%3$s`'
                                . ' under `context.%4$s`. It is read as'
                                . ' `%2$s`.'),
                            $name,
                            $seen[$name],
                            $tier,
                            $scope
                        );
                        continue;
                    }
                    $seen[$name] = $tier;
                }
            }
        }
        $plan = ValueLabelPriority::planFor($parameters);
        foreach (array(ValueLabelPriority::TAXONOMIES,
            ValueLabelPriority::GALAXIES) as $scope
        ) {
            $note = $this->pinNote($plan, $scope);
            if ($note !== null) {
                $warnings[] = $note;
            }
        }
        return $warnings;
    }

    /**
     * @param array $parameters
     * @return array
     */
    private function relevanceErrors(array $parameters)
    {
        $errors = array();
        $section = $this->section($parameters, 'relevance');
        if (isset($section['clock'])
            && !in_array($section['clock'], ValueRelevanceTool::CLOCKS,
                true)
        ) {
            $errors[] = sprintf(
                __('`relevance.clock`: `%s` is not a clock this version'
                    . ' reads.'),
                $section['clock']
            );
        }
        if (isset($section['type_rule'])
            && !in_array($section['type_rule'],
                ValueRelevanceTool::TYPE_RULES, true)
        ) {
            $errors[] = sprintf(
                __('`relevance.type_rule`: `%s` is not a rule this'
                    . ' version applies.'),
                $section['type_rule']
            );
        }
        if (isset($section['decay_speed'])) {
            $speed = $section['decay_speed'];
            if (!is_numeric($speed) || $speed <= 0) {
                $errors[] = __(
                    '`relevance.decay_speed` must be a number above'
                    . ' zero — it is the exponent the runway is raised'
                    . ' to, and zero has no curve.'
                );
            }
        }
        if (isset($section['aging_fraction'])) {
            $fraction = $section['aging_fraction'];
            if (!is_numeric($fraction) || $fraction <= 0 || $fraction >= 1) {
                $errors[] = __(
                    '`relevance.aging_fraction` must be above 0 and'
                    . ' below 1 — it is the share of the TTL still'
                    . ' left when a value stops reading as current.'
                );
            }
        }
        /*
         * Never validated under either name — `lag_uncertain_days` had
         * no rule here and neither did its replacement, so the form
         * accepted `-5` and a word alike. The engine clamps at zero, so
         * nothing broke; the field simply displayed a number that did
         * nothing, which is its own kind of wrong.
         */
        foreach (array('undated_assumed_days', 'lag_uncertain_days')
            as $key
        ) {
            if (!isset($section[$key])) {
                continue;
            }
            if (!is_int($section[$key]) || $section[$key] < 0) {
                $errors[] = sprintf(
                    __('`relevance.%s` must be a whole number of days,'
                        . ' zero or above — it is how much older than'
                        . ' its record an undated value is assumed to'
                        . ' be, and a value cannot be younger than its'
                        . ' own record. Zero assumes nothing.'),
                    $key
                );
            }
        }
        /*
         * D18. Both shapes are validated, because both are documents
         * an analyst can legitimately be holding: a fork nobody has
         * opened still carries the flat map, and the engine still
         * reads it.
         */
        foreach (array('ttl_buckets' => ValueRelevanceTool::BUCKETS,
            'ttl_overrides' => null) as $key => $allowed
        ) {
            if (!isset($section[$key]) || !is_array($section[$key])) {
                continue;
            }
            foreach ($section[$key] as $name => $days) {
                if ($allowed !== null
                    && !in_array($name, $allowed, true)
                ) {
                    $errors[] = sprintf(
                        __('`relevance.%1$s.%2$s` is not a bucket. One'
                            . ' of: %3$s.'),
                        $key,
                        $name,
                        implode(', ', $allowed)
                    );
                    continue;
                }
                if (!is_int($days) || $days <= 0) {
                    $errors[] = sprintf(
                        __('`relevance.%1$s.%2$s` must be a whole'
                            . ' number of days above zero.'),
                        $key,
                        $name
                    );
                }
            }
        }
        if (isset($section['ttl_types'])
            && is_array($section['ttl_types'])
        ) {
            foreach ($section['ttl_types'] as $type => $bucket) {
                if (in_array($bucket, ValueRelevanceTool::BUCKETS, true)) {
                    continue;
                }
                $errors[] = sprintf(
                    __('`relevance.ttl_types.%1$s`: `%2$s` is not a'
                        . ' bucket. One of: %3$s.'),
                    $type,
                    is_scalar($bucket) ? (string)$bucket : gettype($bucket),
                    implode(', ', ValueRelevanceTool::BUCKETS)
                );
            }
        }
        if (isset($section['ttl_default'])
            && (!is_int($section['ttl_default'])
                || $section['ttl_default'] <= 0)
        ) {
            $errors[] = __(
                '`relevance.ttl_default` must be a whole number of days'
                . ' above zero — it is the lifetime of every type'
                . ' nothing else names.'
            );
        }

        $ttl = isset($section['ttl_days']) && is_array($section['ttl_days'])
            ? $section['ttl_days']
            : array();
        foreach ($ttl as $type => $days) {
            if (!is_int($days) || $days <= 0) {
                $errors[] = sprintf(
                    __('`relevance.ttl_days.%s` must be a whole number'
                        . ' of days above zero.'),
                    $type
                );
            }
        }
        /*
         * A flat map still needs its own default, but only while it is
         * the shape in force: once the bucket keys are present the
         * engine ignores the flat map entirely, so demanding a default
         * inside an ignored block would refuse a document that works.
         */
        if (!empty($ttl) && !isset($ttl['default'])
            && !isset($section['ttl_default'])
        ) {
            $errors[] = __(
                '`relevance.ttl_days` needs a `default`, or every type'
                . ' it does not name has no time to live at all.'
            );
        }
        return $errors;
    }

    /**
     * @param array $parameters
     * @return array
     */
    private function referenceErrors(array $parameters)
    {
        $errors = array();
        $section = $this->section($parameters, 'reference');
        $grades = array_merge(ValueTrustTool::GRADES,
            array(ValueTrustTool::UNRATED));
        $trust = isset($section['org_trust'])
            && is_array($section['org_trust'])
            ? $section['org_trust']
            : array();
        foreach ($trust as $uuid => $grade) {
            if (!in_array(ValueTrustTool::normaliseGrade($grade), $grades,
                true)
            ) {
                $errors[] = sprintf(
                    __('`reference.org_trust.%1$s`: `%2$s` is not an'
                        . ' admiralty grade.'),
                    $uuid,
                    is_scalar($grade) ? $grade : gettype($grade)
                );
            }
        }
        $scale = isset($section['org_trust_scale'])
            && is_array($section['org_trust_scale'])
            ? $section['org_trust_scale']
            : array();
        foreach ($scale as $grade => $factor) {
            if (!is_numeric($factor) || $factor < 0) {
                $errors[] = sprintf(
                    __('`reference.org_trust_scale.%s` must be a number'
                        . ' at or above zero.'),
                    $grade
                );
            }
        }
        $categories = isset($section['warninglist_category'])
            && is_array($section['warninglist_category'])
            ? $section['warninglist_category']
            : array();
        $allowed = $this->categoryOptions();
        foreach ($categories as $name => $category) {
            if (!in_array($category, $allowed, true)) {
                $errors[] = sprintf(
                    __('`reference.warninglist_category.%1$s`: `%2$s` is'
                        . ' not a category.'),
                    $name,
                    is_scalar($category) ? $category : gettype($category)
                );
            }
        }
        return $errors;
    }

    /**
     * @param array $parameters
     * @return array
     */
    private function enrichmentErrors(array $parameters)
    {
        $errors = array();
        $section = $this->section($parameters, 'enrichment');
        /*
         * The retired posture keys are not validated and not an error.
         * A document that carries one is a document somebody wrote
         * against an older version — refusing it would refuse a
         * profile whose every other section still works, and nothing
         * reads the key any more. `legacyShapes()` says it is there
         * and saving takes it out.
         */
        if (isset($section['max_age_hours'])
            && (!is_int($section['max_age_hours'])
                || $section['max_age_hours'] <= 0)
        ) {
            $errors[] = __(
                '`enrichment.max_age_hours` must be a whole number of'
                . ' hours above zero.'
            );
        }
        $autoRun = isset($section['auto_run'])
            && is_array($section['auto_run'])
            ? $section['auto_run']
            : array();
        foreach ($autoRun as $type => $names) {
            if (!is_array($names) && !is_string($names)) {
                $errors[] = sprintf(
                    __('`enrichment.auto_run.%s` must be a list of'
                        . ' module names, or a map of names to run'
                        . ' states.'),
                    $type
                );
                continue;
            }
            if (!is_array($names)) {
                continue;
            }
            foreach ($names as $name => $state) {
                /*
                 * An integer key is a list entry, which means
                 * `ticked` and carries no state to check.
                 */
                if (is_int($name)) {
                    continue;
                }
                if (in_array($state, ValueEnrichmentTool::states(), true)) {
                    continue;
                }
                $errors[] = sprintf(
                    __('`enrichment.auto_run.%1$s.%2$s`: `%3$s` is not'
                        . ' a run state. One of: %4$s.'),
                    $type,
                    $name,
                    is_scalar($state) ? (string)$state : gettype($state),
                    implode(', ', ValueEnrichmentTool::states())
                );
            }
        }
        return $errors;
    }

    /**
     * @param mixed $given
     * @param array $spec
     * @param string $label
     * @return string|null
     */
    private function checkScalar($given, array $spec, $label)
    {
        $type = isset($spec['type']) ? $spec['type'] : 'int';
        if ($type === 'int' && !is_int($given)) {
            return sprintf(__('`%s` must be a whole number.'), $label);
        }
        if ($type === 'float' && !is_int($given) && !is_float($given)) {
            return sprintf(__('`%s` must be a number.'), $label);
        }
        if ($type === 'string' && !is_string($given)) {
            return sprintf(__('`%s` must be text.'), $label);
        }
        if (isset($spec['options'])
            && !in_array($given, $spec['options'], true)
        ) {
            return sprintf(
                __('`%1$s` must be one of: %2$s.'),
                $label,
                implode(', ', $spec['options'])
            );
        }
        /*
         * A bound the schema declares. The box already carries it as a
         * `min`/`max` the browser refuses at the keystroke, and a
         * document that arrived by import never met that box — so a
         * window of `-5` days would be stored, read as a window nothing
         * falls inside, and say nothing about why.
         */
        if (isset($spec['min']) && is_numeric($given)
            && (float)$given < (float)$spec['min']
        ) {
            return sprintf(
                __('`%1$s` must be at least %2$s.'),
                $label,
                $spec['min']
            );
        }
        if (isset($spec['max']) && is_numeric($given)
            && (float)$given > (float)$spec['max']
        ) {
            return sprintf(
                __('`%1$s` must be at most %2$s.'),
                $label,
                $spec['max']
            );
        }
        return null;
    }

    /**
     * A pasted document, with the parse error and its line where there
     * is one.
     *
     * `json_decode` reports an offset and not a line, so the line is
     * counted from the offset — because "syntax error" with no position
     * on a 300-line document is a message that sends the reader back to
     * a text editor to bisect it by hand.
     *
     * @param string $raw
     * @return array `ok`, and either `parameters` or `error` and `line`
     */
    public function parse($raw)
    {
        $raw = (string)$raw;
        if (trim($raw) === '') {
            return array(
                'ok' => false,
                'error' => __('The document is empty.'),
                'line' => 1,
            );
        }
        $decoded = json_decode($raw, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $offset = function_exists('json_last_error_msg')
                ? $this->firstStructuralFault($raw)
                : null;
            return array(
                'ok' => false,
                'error' => json_last_error_msg(),
                'line' => $offset === null
                    ? null
                    : substr_count(substr($raw, 0, $offset), "\n") + 1,
            );
        }
        if (!is_array($decoded) || $this->isList($decoded)) {
            return array(
                'ok' => false,
                'error' => __(
                    'A profile is a JSON object of named sections, not'
                    . ' a list or a bare value.'
                ),
                'line' => 1,
            );
        }
        return array('ok' => true, 'parameters' => $decoded);
    }

    /**
     * The byte at which the document first stops being possible.
     *
     * PHP reports *what* went wrong and never *where*, and "syntax
     * error" with no position on a three-hundred-line document sends the
     * reader back to a text editor to bisect it by hand. Bisecting on
     * *does this prefix parse* finds nothing, because a prefix of valid
     * JSON is almost never valid JSON — so this walks the brackets
     * instead, tracking what each closer is supposed to be closing.
     *
     * It catches the two faults a hand-edited profile actually has: a
     * closer with no opener, and a closer that does not match its
     * opener — `"signals": [}`, where the depth never goes negative and
     * a depth-only counter would have pointed at the end of the file.
     * Anything it cannot place — a bad escape, a bare word, a trailing
     * comma — points at the last byte, which is where an unterminated
     * document does in fact stop.
     *
     * @param string $raw
     * @return int|null
     */
    private function firstStructuralFault($raw)
    {
        $length = strlen($raw);
        if ($length === 0) {
            return null;
        }
        $stack = array();
        $inString = false;
        $escaped = false;
        for ($i = 0; $i < $length; $i++) {
            $char = $raw[$i];
            if ($inString) {
                if ($escaped) {
                    $escaped = false;
                } elseif ($char === '\\') {
                    $escaped = true;
                } elseif ($char === '"') {
                    $inString = false;
                }
                continue;
            }
            if ($char === '"') {
                $inString = true;
            } elseif ($char === '{' || $char === '[') {
                $stack[] = $char;
            } elseif ($char === '}' || $char === ']') {
                if (empty($stack)) {
                    return $i;
                }
                $opener = array_pop($stack);
                $wants = $char === '}' ? '{' : '[';
                if ($opener !== $wants) {
                    return $i;
                }
            }
        }
        return $length - 1;
    }

    /**
     * The parts of a stored document that are in a shape an older
     * version wrote, and what saving will do to them.
     *
     * Two sections are read through a shim — `relevance` since D18
     * gave TTLs four buckets, `enrichment` since the posture was
     * withdrawn — and a shim is a *read*: the stored document keeps
     * the old keys until something writes it. The editor is that
     * something. It renders the shimmed reading, so posting any
     * section back rewrites both sections into the current shape and
     * moves `revision`, on a save the analyst may believe changed
     * nothing.
     *
     * That is the right outcome and a bad surprise, so the page says
     * it first. Detected from the legacy keys themselves rather than
     * by merging a document to see what comes out: the keys are what
     * the shim reads, so they are what can be stated.
     *
     * @param array $parameters
     * @return array Sentences, one per section still in an old shape
     */
    public function legacyShapes(array $parameters)
    {
        $notes = array();
        if (isset($parameters['relevance']['ttl_days'])) {
            $notes[] = __(
                'This profile keeps lifetimes as one day count per'
                . ' attribute type, which is the shape before the four'
                . ' buckets. It is read exactly — every named type'
                . ' counts as its own override, so nothing has changed'
                . ' lifetime — and the pane below shows that reading.'
                . ' Saving any section writes the buckets and drops the'
                . ' old key.'
            );
        }
        $enrichment = isset($parameters['enrichment'])
            && is_array($parameters['enrichment'])
            ? $parameters['enrichment']
            : array();
        foreach (array('locality_posture', 'cost_posture') as $retired) {
            if (!isset($enrichment[$retired])) {
                continue;
            }
            $notes[] = sprintf(
                __('This profile carries `enrichment.%s`, the setting'
                    . ' that decided whether a module leaving the'
                    . ' instance could be offered. It has been'
                    . ' withdrawn — nothing was ever withheld that a'
                    . ' press could not reach, and locality is now a'
                    . ' label rather than a gate. The key is ignored'
                    . ' and saving any section drops it.'),
                $retired
            );
        }
        foreach ($this->followedWords($parameters) as $note) {
            $notes[] = $note;
        }
        return $notes;
    }

    /**
     * A `when` setting still written as the word for its fallback.
     *
     * The same shape as the two above and for the same reason: the word
     * is read as *follow the profile*, an absent key is read as exactly
     * that too, and the editor draws the reading rather than the
     * spelling — so a save takes the key out and moves `revision`
     * without changing a single answer. Said before it happens.
     *
     * Driven off the schemas rather than a list here, so a second rule
     * declaring `follows` is covered the day it is dropped in.
     *
     * @param array $parameters
     * @return array
     */
    private function followedWords(array $parameters)
    {
        $notes = array();
        $catalogue = ValueSignalLoader::catalogue(
            ValueSignalLoader::SUBJECT_ESCALATION
        );
        foreach ($this->entriesById($parameters, 'escalations')
            as $id => $entry
        ) {
            if (!isset($catalogue[$id]['when_schema'])
                || !isset($entry['when'])
                || !is_array($entry['when'])
            ) {
                continue;
            }
            foreach ($catalogue[$id]['when_schema'] as $key => $spec) {
                if (!isset($spec['follows']['name'])
                    || !isset($entry['when'][$key])
                    || $entry['when'][$key] !== $spec['follows']['name']
                ) {
                    continue;
                }
                $notes[] = sprintf(
                    __('`%1$s` writes `%2$s` as the word `%3$s`. That'
                        . ' means follow the profile, and so does'
                        . ' leaving the key out, which is how the box'
                        . ' below shows it. Saving any section drops'
                        . ' the word and changes no answer.'),
                    $id,
                    $key,
                    $spec['follows']['name']
                );
            }
        }
        return $notes;
    }

    /**
     * What a field is called in the POST.
     *
     * The naming convention is the class docblock's, and it lives here
     * rather than in a template because `merge()` is the reader: one
     * writer for the name and one for the read, and neither has to
     * remember what the other does with a dot or a pipe.
     *
     * @param array $path The field's `path`, from the view-model
     * @param array $extra Segments appended after it — `__present`,
     *                     `__remove`, a map key
     * @return string
     */
    public static function fieldName(array $path, array $extra = array())
    {
        $name = 'data[AnalystProfile][parameters]';
        foreach (array_merge($path, $extra) as $segment) {
            $name .= '[' . $segment . ']';
        }
        return $name;
    }

    /**
     * A DOM id for the same field, so a label can point at it.
     *
     * @param array $path
     * @param array $extra
     * @return string
     */
    public static function fieldId(array $path, array $extra = array())
    {
        return 'ap-' . preg_replace(
            '/[^a-zA-Z0-9_-]+/',
            '-',
            implode('-', array_merge($path, $extra))
        );
    }

    /**
     * A posted form applied to the stored document.
     *
     * **A section the form did not post is untouched.** The editor edits
     * one section at a time, and a merge that treated absence as
     * deletion would let a form wipe the six sections it did not draw.
     *
     * Within a posted section:
     *
     * - **`signals`, `escalations`, `exclusions` merge by id.** A stored
     *   entry the form did not mention survives — which is the rule that
     *   keeps an analyst's configuration for a signal this instance does
     *   not currently have (`03-signals.md` §4.4). An entry is removed
     *   only by an explicit `__remove`.
     * - **A map replaces wholesale**, because a removed row posts
     *   nothing and a merge could not tell that from a row the form
     *   never drew. So a map block posts `__present`, and a present
     *   marker with no rows means *empty*, not *unchanged*.
     * - **A scalar field with an empty string is a deletion**, so the
     *   key falls back to its schema default rather than being stored as
     *   `""` — which is how a numeric field gets cleared at all.
     *
     * @param array $stored The decoded stored `parameters`
     * @param array $posted The `parameters` sub-array of the request
     * @return array The document to save
     */
    public function merge(array $stored, array $posted)
    {
        $merged = $stored;
        foreach ($posted as $name => $value) {
            if (!in_array($name, self::SECTION_ORDER, true)) {
                continue;
            }
            if (in_array($name, array('signals', 'escalations',
                'exclusions'), true)
            ) {
                $merged[$name] = $this->mergeEntries(
                    isset($stored[$name]) && is_array($stored[$name])
                        ? $stored[$name]
                        : array(),
                    is_array($value) ? $value : array()
                );
                continue;
            }
            $merged[$name] = $this->mergeAssoc(
                isset($stored[$name]) && is_array($stored[$name])
                    ? $stored[$name]
                    : array(),
                is_array($value) ? $value : array()
            );
        }
        /*
         * D18: a fork upgraded from the flat per-type TTL map must not
         * keep the flat map beside its buckets. `ValueRelevanceTool`
         * ignores `ttl_days` once the current keys are present, so
         * leaving it would be dead weight that reads as a setting.
         */
        if (isset($merged['relevance']['ttl_days'])) {
            foreach (array('ttl_buckets', 'ttl_types', 'ttl_overrides',
                'ttl_default') as $key
            ) {
                if (isset($merged['relevance'][$key])) {
                    unset($merged['relevance']['ttl_days']);
                    break;
                }
            }
        }
        /*
         * The withdrawn posture, under either of the two names it
         * had. Nothing reads them, so leaving them in the document
         * would leave a setting that looks like one and is not — the
         * exact shape of the quiet lie `01-profile.md` §1.3 forbids.
         * A save on any section takes them out.
         */
        if (isset($merged['enrichment'])
            && is_array($merged['enrichment'])
        ) {
            unset(
                $merged['enrichment']['locality_posture'],
                $merged['enrichment']['cost_posture'],
                $merged['enrichment']['locality']
            );
        }
        // `max_voices` replaced `max_orgs`; a save drops the old key.
        if (isset($merged['thresholds']['thin_record_clamp']['max_voices'])) {
            unset($merged['thresholds']['thin_record_clamp']['max_orgs']);
        }
        // Shown is the default, so only a switched-off profile stores it.
        if (($merged['context'][ValueLabelPriority::SHOW_ASSESSMENT] ?? null)
            === true
        ) {
            unset($merged['context'][ValueLabelPriority::SHOW_ASSESSMENT]);
        }
        $merged = $this->transposeModules($merged, $posted);
        $merged = $this->transposeTiers($merged, $posted);
        $merged = $this->transposeMarkings($merged, $posted);
        $merged = $this->transposeAttribution($merged, $posted);
        $merged = $this->reindexShapes($merged);
        return $merged;
    }

    /**
     * The shape ranking, written back as a list rather than as
     * whatever the form's indices happened to be.
     *
     * The order block posts one input per row, named by its position,
     * and the page renumbers them on every move — but a row removed
     * without a renumber, or a browser that posts a sparse set for any
     * other reason, gives keys like `0, 2, 3`. PHP keeps those as an
     * associative array and `json_encode` writes `{"0":…}` where the
     * document says a list. Nothing downstream breaks — the reading is
     * tolerant — but the stored document would no longer be the shape
     * it claims, and a document is read by hand as often as by code.
     *
     * Sorting by key first is what makes this a re-index rather than a
     * reshuffle: the keys *are* the ranking.
     *
     * @param array $merged
     * @return array
     */
    private function reindexShapes(array $merged)
    {
        if (!isset($merged['enrichment']['shapes'])
            || !is_array($merged['enrichment']['shapes'])
        ) {
            return $merged;
        }
        $shapes = $merged['enrichment']['shapes'];
        ksort($shapes, SORT_NUMERIC);
        $out = array();
        foreach ($shapes as $shape) {
            if (!is_string($shape) && !is_numeric($shape)) {
                continue;
            }
            $shape = trim((string)$shape);
            if ($shape !== '' && !in_array($shape, $out, true)) {
                $out[] = $shape;
            }
        }
        /*
         * An empty ranking is taken out rather than stored as `[]`,
         * so that a profile which has never ranked anything and one
         * that ranked something and then cleared it are the same
         * document. The shipped default's neutrality is exactly this
         * rule applied to every other section.
         */
        if (empty($out)) {
            unset($merged['enrichment']['shapes']);
            return $merged;
        }
        $merged['enrichment']['shapes'] = $out;
        return $merged;
    }

    /**
     * The tier-per-name map the form posts, written back as the three
     * ordered lists the document stores.
     *
     * `transposeModules()`'s twin and for its reason: the editor asks
     * *what is this taxonomy to me* once per name, and every reader —
     * `ValueLabelPriority`, the shipped profiles, a document written by
     * hand — speaks three lists. The row order inside the map is the
     * order within a tier, which is how an analyst says
     * `threat-actor` before `malpedia`.
     *
     * A blank tier is *not ranked* and writes nothing, so a name every
     * row left blank leaves the lists entirely — the same rule the
     * module states follow, and the one that lets a profile go back to
     * having no opinion.
     *
     * Only on a post that carried the block, for the same reason: the
     * map's `__present` marker is what says it was on screen, and
     * without that check a save of some other section would read the
     * map's absence as *every ranking cleared*.
     *
     * @param array $merged The document so far
     * @param array $posted The `parameters` sub-array of the request
     * @return array
     */
    private function transposeTiers(array $merged, array $posted)
    {
        if (!isset($merged['context']) || !is_array($merged['context'])) {
            return $merged;
        }
        foreach (array(ValueLabelPriority::TAXONOMIES,
            ValueLabelPriority::GALAXIES) as $scope
        ) {
            $field = $scope . '_tier';
            if (!isset($posted['context'][$field])) {
                unset($merged['context'][$field]);
                continue;
            }
            $byName = isset($merged['context'][$field])
                && is_array($merged['context'][$field])
                ? $merged['context'][$field]
                : array();
            unset($merged['context'][$field]);
            $lists = array();
            foreach (ValueLabelPriority::TIERS as $tier) {
                $lists[$tier] = array();
            }
            foreach ($byName as $name => $tier) {
                if ($name === '__present' || $tier === ''
                    || $tier === null
                    || !isset($lists[$tier])
                ) {
                    continue;
                }
                $lists[$tier][] = (string)$name;
            }
            $merged['context'][$scope] = $lists;
        }
        if ($merged['context'] === array()) {
            unset($merged['context']);
        }
        return $merged;
    }

    /**
     * The markings map the form posts, written back as the list the
     * document stores — or not at all while it equals the default, so
     * a profile that never touched it keeps following the default.
     *
     * @param array $merged
     * @param array $posted
     * @return array
     */
    private function transposeMarkings(array $merged, array $posted)
    {
        if (!isset($merged['context']) || !is_array($merged['context'])) {
            return $merged;
        }
        if (!isset($posted['context']['markings_map'])) {
            unset($merged['context']['markings_map']);
            return $merged;
        }
        $map = is_array($merged['context']['markings_map'] ?? null)
            ? $merged['context']['markings_map']
            : array();
        unset($merged['context']['markings_map']);
        $namespaces = array();
        foreach ($map as $namespace => $state) {
            if ($namespace === '__present' || $state === ''
                || $state === null
            ) {
                continue;
            }
            $namespaces[] = mb_strtolower((string)$namespace);
        }
        if ($namespaces === ValueLabelPriority::DEFAULT_MARKINGS) {
            unset($merged['context']['markings']);
        } else {
            $merged['context']['markings'] = $namespaces;
        }
        if ($merged['context'] === array()) {
            unset($merged['context']);
        }
        return $merged;
    }

    /**
     * The attribution map the form posts, written back as the list the
     * document stores.
     *
     * The value column carries one option and exists so a row can be
     * removed by the control every other map uses; what is stored is
     * the keys. An empty map is a declared *no filter*, which is what
     * removing the last row means and what the signal read before the
     * list existed.
     *
     * @param array $merged
     * @param array $posted
     * @return array
     */
    private function transposeAttribution(array $merged, array $posted)
    {
        if (!isset($merged['galaxies']) || !is_array($merged['galaxies'])) {
            return $merged;
        }
        if (!isset($posted['galaxies']['attribution_map'])) {
            unset($merged['galaxies']['attribution_map']);
            return $merged;
        }
        $map = isset($merged['galaxies']['attribution_map'])
            && is_array($merged['galaxies']['attribution_map'])
            ? $merged['galaxies']['attribution_map']
            : array();
        unset($merged['galaxies']['attribution_map']);
        $types = array();
        foreach ($map as $type => $state) {
            if ($type === '__present' || $state === '' || $state === null) {
                continue;
            }
            $types[] = (string)$type;
        }
        $merged['galaxies']['attribution'] = $types;
        return $merged;
    }

    /**
     * The module-keyed map the form posts, written back as the
     * type-keyed one the document stores.
     *
     * **The editor's axis is not the document's**, and this is the one
     * place that knows it. `auto_run_modules` never reaches storage;
     * `auto_run` is what every reader — the engine, the tab, the
     * shipped default, every profile written by hand — has always
     * spoken, and changing the stored shape to match a form would have
     * been the form deciding the contract.
     *
     * A blank state is *not declared* and writes nothing, so a type
     * every row left blank disappears from `auto_run` entirely, which
     * is exactly right: a type no module names is a type the profile
     * does not narrow.
     *
     * Only on a post that carried the block. The map's `__present`
     * marker is what says it was on screen, and without that check a
     * save of some other section would read `auto_run_modules`'
     * absence as *every module cleared* and wipe the declaration.
     *
     * @param array $merged The document so far
     * @param array $posted The `parameters` sub-array of the request
     * @return array
     */
    private function transposeModules(array $merged, array $posted)
    {
        if (!isset($merged['enrichment'])
            || !is_array($merged['enrichment'])
        ) {
            return $merged;
        }
        if (!isset($posted['enrichment']['auto_run_modules'])) {
            unset($merged['enrichment']['auto_run_modules']);
            return $merged;
        }
        $byModule = isset($merged['enrichment']['auto_run_modules'])
            && is_array($merged['enrichment']['auto_run_modules'])
            ? $merged['enrichment']['auto_run_modules']
            : array();
        unset($merged['enrichment']['auto_run_modules']);
        $autoRun = array();
        foreach ($byModule as $name => $states) {
            if (!is_array($states)) {
                continue;
            }
            foreach ($states as $type => $state) {
                if ($type === '__present' || $state === ''
                    || $state === null
                ) {
                    continue;
                }
                $autoRun[(string)$type][(string)$name] = $state;
            }
        }
        $merged['enrichment']['auto_run'] = $autoRun;
        return $merged;
    }

    /**
     * @param array $stored A list of entries with `id`
     * @param array $posted id => fields
     * @return array A list of entries
     */
    private function mergeEntries(array $stored, array $posted)
    {
        $byId = array();
        $order = array();
        foreach ($stored as $entry) {
            if (!is_array($entry) || empty($entry['id'])) {
                continue;
            }
            $byId[$entry['id']] = $entry;
            $order[] = $entry['id'];
        }
        foreach ($posted as $id => $fields) {
            if (!is_array($fields)) {
                continue;
            }
            if (!empty($fields['__remove'])) {
                unset($byId[$id]);
                continue;
            }
            unset($fields['__remove']);
            $entry = isset($byId[$id])
                ? $byId[$id]
                : array('id' => $id);
            $byId[$id] = $this->mergeAssoc($entry, $fields);
            $byId[$id]['id'] = $id;
            if (!in_array($id, $order, true)) {
                $order[] = $id;
            }
        }
        $out = array();
        foreach ($order as $id) {
            if (isset($byId[$id])) {
                $out[] = $byId[$id];
            }
        }
        return $out;
    }

    /**
     * @param array $stored
     * @param array $posted
     * @return array
     */
    private function mergeAssoc(array $stored, array $posted)
    {
        $merged = $stored;
        $present = array();
        foreach ($posted as $key => $value) {
            if ($key === '__present') {
                continue;
            }
            $present[] = $key;
            if (is_array($value)) {
                if (!empty($value['__present'])
                    || $this->isList($value)
                ) {
                    $merged[$key] = $this->replaceMap($value);
                    continue;
                }
                $merged[$key] = $this->mergeAssoc(
                    isset($stored[$key]) && is_array($stored[$key])
                        ? $stored[$key]
                        : array(),
                    $value
                );
                continue;
            }
            if ($value === '' || $value === null) {
                unset($merged[$key]);
                continue;
            }
            $merged[$key] = $this->cast($value);
        }
        /*
         * A block that declared itself present replaces rather than
         * merges: the rows it did not post are rows the analyst removed.
         */
        if (!empty($posted['__present'])) {
            foreach (array_keys($merged) as $key) {
                if (!in_array($key, $present, true)) {
                    unset($merged[$key]);
                }
            }
        }
        return $merged;
    }

    /**
     * @param array $posted
     * @return array
     */
    private function replaceMap(array $posted)
    {
        unset($posted['__present']);
        $out = array();
        foreach ($posted as $key => $value) {
            if (is_array($value)) {
                $out[$key] = $this->replaceMap($value);
                continue;
            }
            if ($value === '' || $value === null) {
                continue;
            }
            $out[$key] = $this->cast($value);
        }
        return $out;
    }

    /**
     * A posted scalar back to the type the document wants.
     *
     * Everything arrives as a string from a form, and a document whose
     * `per_org` is `"7"` fails `ValueSignalBase::validatePoints()` —
     * correctly, because the exact-sum invariant is not negotiable and a
     * string is not an integer. So the cast happens here, once, rather
     * than in every validator.
     *
     * @param mixed $value
     * @return mixed
     */
    private function cast($value)
    {
        if (is_bool($value) || is_int($value) || is_float($value)) {
            return $value;
        }
        if (!is_string($value)) {
            return $value;
        }
        $trimmed = trim($value);
        if ($trimmed === '') {
            return '';
        }
        if (preg_match('/^-?\d+$/', $trimmed)) {
            return (int)$trimmed;
        }
        if (preg_match('/^-?\d*\.\d+$/', $trimmed)) {
            return (float)$trimmed;
        }
        if ($trimmed === 'true') {
            return true;
        }
        if ($trimmed === 'false') {
            return false;
        }
        return $trimmed;
    }

    /**
     * A section's entries keyed by id, from the list the document holds.
     *
     * @param array $parameters
     * @param string $name
     * @return array
     */
    private function entriesById(array $parameters, $name)
    {
        $entries = array();
        $section = isset($parameters[$name]) && is_array($parameters[$name])
            ? $parameters[$name]
            : array();
        foreach ($section as $entry) {
            if (!is_array($entry) || empty($entry['id'])) {
                continue;
            }
            $entries[(string)$entry['id']] = $entry;
        }
        return $entries;
    }

    /**
     * @param array $parameters
     * @param string $name
     * @return array
     */
    private function section(array $parameters, $name)
    {
        return isset($parameters[$name]) && is_array($parameters[$name])
            ? $parameters[$name]
            : array();
    }

    /**
     * `context` — which labels a surface draws first, and which it
     * draws when the value carries none of them.
     *
     * **Edited as one map per dimension rather than as three lists**,
     * because the question an analyst is answering is *what is
     * `attck4fraud` to me*, once, and three lists ask it three times
     * and let them answer twice. The document stores the three lists —
     * that is what every reader speaks — and `transposeTiers()` is the
     * one place that knows the editor's axis is not the document's, as
     * `transposeModules()` does for the enrichment mapping.
     *
     * The rows' order in the map is the order within a tier, so an
     * analyst who wants `threat-actor` ahead of `malpedia` puts it
     * ahead of it here.
     *
     * @param array $parameters
     * @param array $sources
     * @return array
     */
    private function sectionContext(array $parameters, array $sources)
    {
        $plan = ValueLabelPriority::planFor($parameters);
        $offered = array(
            ValueLabelPriority::TAXONOMIES => isset($sources['taxonomies'])
                ? $sources['taxonomies']
                : array(),
            ValueLabelPriority::GALAXIES => isset($sources['galaxies'])
                ? $sources['galaxies']
                : array(),
        );
        $blocks = array(
            array(
                'kind' => 'fields',
                'id' => ValueLabelPriority::SHOW_ASSESSMENT,
                'title' => __('Assessment'),
                'blurb' => __(
                    'Whether value pages, hover cards and the value'
                    . ' worklist show the lean, relevance and signal'
                    . ' strength. Switching it off hides them for'
                    . ' readers of this profile and skips computing'
                    . ' them; the evidence tabs and the REST API are'
                    . ' unchanged.'
                ),
                'fields' => array(
                    array(
                        'key' => ValueLabelPriority::SHOW_ASSESSMENT,
                        'label' => __('Show the assessment'),
                        'type' => 'bool',
                        'value' => ValueLabelPriority::showsAssessment(
                            $parameters
                        ),
                        'default' => true,
                        'path' => array('context',
                            ValueLabelPriority::SHOW_ASSESSMENT),
                    ),
                ),
            ),
        );
        foreach ($offered as $scope => $available) {
            $entries = array();
            $tiers = array();
            foreach (ValueLabelPriority::TIERS as $tier) {
                foreach ($plan[$scope][$tier] as $key) {
                    $tiers[$key] = $tier;
                    $entries[] = array(
                        'key' => $key,
                        'label' => isset($available[$key])
                            ? $available[$key]
                            : $key,
                        'sub_label' => isset($available[$key])
                            && $available[$key] !== $key
                            ? $key
                            : null,
                        /*
                         * A site admin who disables a taxonomy for a
                         * week must not silently erase every profile's
                         * pin on it (D41, D23): the row is kept and
                         * marked, the document keeps the entry, and
                         * re-enabling brings the pin back. What the
                         * floor does instead is refuse to *draw* the
                         * absence, which is the page's decision rather
                         * than the editor's.
                         */
                        'missing' => !empty($available)
                            && !isset($available[$key]),
                        'value' => $tier,
                        'type' => 'select',
                        'options' => $this->tierOptions(),
                        'path' => array('context', $scope . '_tier', $key),
                    );
                }
            }
            $blocks[] = array(
                'kind' => 'map',
                'id' => $scope . '_tier',
                'title' => $scope === ValueLabelPriority::TAXONOMIES
                    ? __('Taxonomies')
                    : __('Galaxies'),
                'blurb' => $scope === ValueLabelPriority::TAXONOMIES
                    ? __(
                        'Pinned taxonomies are drawn first, and a value'
                        . ' that carries none of one is shown as'
                        . ' missing it — so keep that list short: a'
                        . ' card listing eight absences teaches you to'
                        . ' skip that part of the page. Taxonomies you'
                        . ' do not rank keep the order they have today,'
                        . ' and nothing here can hide a label.'
                    )
                    : __(
                        'The same three tiers, for galaxies. A compact'
                        . ' surface such as the hover card has room for'
                        . ' one cluster and counts the rest; this'
                        . ' decides which one it names. Ranking a'
                        . ' galaxy here does not make it count as an'
                        . ' attribution — that is set under What counts'
                        . ' as an attribution.'
                    ),
                'key_label' => $scope === ValueLabelPriority::TAXONOMIES
                    ? __('Taxonomy')
                    : __('Galaxy'),
                'value_label' => __('Tier'),
                'empty_label' => __('Nothing ranked'),
                'empty_note' => __('Every label keeps the order it has'
                    . ' today.'),
                'value_type' => 'select',
                'value_options' => $this->tierOptions(),
                'path' => array('context', $scope . '_tier'),
                'entries' => $entries,
                'note' => $this->pinNote($plan, $scope),
                'add' => array(
                    'label' => $scope === ValueLabelPriority::TAXONOMIES
                        ? __('Rank a taxonomy')
                        : __('Rank a galaxy'),
                    'source' => $scope,
                    /*
                     * 182 taxonomies and 130 galaxies: the whole roster
                     * fits in the page and nobody reads to the bottom
                     * of it, which is the warninglists' case exactly.
                     */
                    'search' => true,
                    'placeholder' => $scope
                        === ValueLabelPriority::TAXONOMIES
                        ? __('filter taxonomies…')
                        : __('filter galaxies…'),
                    'options' => $this->unusedKeys(
                        array_keys($available),
                        $tiers
                    ),
                ),
            );
        }
        $blocks[] = $this->markingsBlock(
            $parameters,
            $offered[ValueLabelPriority::TAXONOMIES]
        );
        return array(
            'id' => 'context',
            'title' => __('What you look at first'),
            'blurb' => __(
                'Whether the assessment is shown, which taxonomies and'
                . ' galaxies are shown first on cards with room for only'
                . ' a few, and which taxonomies the event page draws as'
                . ' markings. Demoting a label only moves it down, it'
                . ' never hides it.'
            ),
            'blocks' => $blocks,
        );
    }

    /**
     * Which taxonomies the event page's marking block draws.
     *
     * Rows start from what is in force, defaults included, so the
     * editor shows what the page shows; the transpose writes nothing
     * back while the list still equals the default.
     *
     * @param array $parameters
     * @param array $available Taxonomy namespace => label
     * @return array
     */
    private function markingsBlock(array $parameters, array $available)
    {
        $entries = array();
        $used = array();
        foreach (ValueLabelPriority::markings($parameters) as $namespace) {
            $used[$namespace] = true;
            $entries[] = array(
                'key' => $namespace,
                'label' => isset($available[$namespace])
                    ? $available[$namespace]
                    : $namespace,
                'sub_label' => isset($available[$namespace])
                    && $available[$namespace] !== $namespace
                    ? $namespace
                    : null,
                'missing' => !empty($available)
                    && !isset($available[$namespace]),
                'value' => self::MARKING_SHOWN,
                'type' => 'select',
                'options' => $this->markingOptions(),
                'path' => array('context', 'markings_map', $namespace),
            );
        }
        return array(
            'kind' => 'map',
            'id' => 'markings_map',
            'title' => __('Markings'),
            'blurb' => __(
                'The taxonomies the event page draws in its marking'
                . ' block, beside the distribution, in this order.'
                . ' TLP and PAP unless you say otherwise; add your own'
                . ' classification scheme, such as NATO\'s, or remove'
                . ' every row to drop the block.'
            ),
            'key_label' => __('Taxonomy'),
            'value_label' => __('Shown as'),
            'empty_label' => __('No marking block'),
            'empty_note' => __('The event page draws no markings beside'
                . ' the distribution.'),
            'display' => 'chips',
            'value_type' => 'select',
            'value_options' => $this->markingOptions(),
            'path' => array('context', 'markings_map'),
            'entries' => $entries,
            'add' => array(
                'label' => __('Add a marking'),
                'source' => ValueLabelPriority::TAXONOMIES,
                'search' => true,
                'placeholder' => __('filter taxonomies…'),
                'options' => $this->unusedKeys(
                    array_keys($available),
                    $used
                ),
            ),
        );
    }

    /**
     * @return array `value`/`label` pairs
     */
    private function markingOptions()
    {
        return array(
            array(
                'value' => self::MARKING_SHOWN,
                'label' => __('a marking'),
            ),
        );
    }

    /**
     * `galaxies` — which galaxies count as an attribution.
     *
     * **Not the display priority, and separate on purpose.**
     * `attribution.galaxy` reads a value's clusters and consults no
     * category table, so every galaxy that is not ATT&CK-shaped counts
     * — sectors, countries and countermeasures included. This list is
     * the filter it never had, and it is not the display ranking because
     * the wrong answers differ: demoting `firearms` down a card must
     * not change anybody's score, and preferring a typology on a card
     * must not have it scored as an attribution.
     *
     * @param array $parameters
     * @param array $sources
     * @return array
     */
    private function sectionGalaxies(array $parameters, array $sources)
    {
        $declared = ValueLabelPriority::attribution($parameters);
        $available = isset($sources['galaxies'])
            ? $sources['galaxies']
            : array();
        $entries = array();
        $used = array();
        foreach ((array)$declared as $type) {
            $used[$type] = true;
            $entries[] = array(
                'key' => $type,
                'label' => isset($available[$type])
                    ? $available[$type]
                    : $type,
                'sub_label' => isset($available[$type])
                    && $available[$type] !== $type
                    ? $type
                    : null,
                'missing' => !empty($available) && !isset($available[$type]),
                'value' => self::ATTRIBUTION_COUNTS,
                'type' => 'select',
                'options' => $this->attributionOptions(),
                'path' => array('galaxies', 'attribution_map', $type),
            );
        }
        return array(
            'id' => 'galaxies',
            'title' => __('What counts as an attribution'),
            'blurb' => __(
                'Which galaxies name a threat — an actor, a campaign, a'
                . ' malware family, a tool — rather than classify one.'
                . ' The attribution signal only scores clusters from these'
                . ' galaxies, or every cluster when the list is empty.'
                . ' ATT&CK techniques are scored by a signal of their'
                . ' own.'
            ),
            'blocks' => array(
                array(
                    'kind' => 'map',
                    'id' => 'attribution_map',
                    'title' => __('Galaxies that count'),
                    'blurb' => __(
                        'Remove one to stop counting it. A sector, a'
                        . ' country, a countermeasure or a typology is'
                        . ' not an attribution — state-sponsored is a'
                        . ' type, not a name.'
                    ),
                    'display' => 'chips',
                    'key_label' => __('Galaxy'),
                    'value_label' => __('Counts as'),
                    'empty_label' => __('No filter'),
                    'empty_note' => __('Every cluster that is not an'
                        . ' attack pattern counts.'),
                    'value_type' => 'select',
                    'value_options' => $this->attributionOptions(),
                    'path' => array('galaxies', 'attribution_map'),
                    'entries' => $entries,
                    'add' => array(
                        'label' => __('Count a galaxy'),
                        'source' => 'galaxies',
                        'search' => true,
                        'placeholder' => __('filter galaxies…'),
                        'options' => $this->unusedKeys(
                            array_keys($available),
                            $used
                        ),
                        /*
                         * **Retyping a list you just wrote is how the
                         * two drift apart**, and they are meant to
                         * overlap. The action fills this list from the
                         * galaxies preferred for display, which is the
                         * starting point an analyst who has just ranked
                         * them actually wants.
                         */
                        'copy_from' => array(
                            'label' => __('Copy the galaxies preferred'
                                . ' for display'),
                            'keys' => ValueLabelPriority::keys(
                                $parameters,
                                ValueLabelPriority::GALAXIES,
                                ValueLabelPriority::PREFERRED
                            ),
                            'value' => self::ATTRIBUTION_COUNTS,
                        ),
                    ),
                ),
            ),
        );
    }

    /**
     * The three tiers, each saying what it does rather than what it is
     * called.
     *
     * @return array `value`/`label` pairs
     */
    private function tierOptions()
    {
        return array(
            array(
                'value' => ValueLabelPriority::PINNED,
                'label' => __('pinned — always shown, and shown as'
                    . ' missing when it is'),
            ),
            array(
                'value' => ValueLabelPriority::PREFERRED,
                'label' => __('preferred — shown before anything'
                    . ' unranked'),
            ),
            array(
                'value' => ValueLabelPriority::DEMOTED,
                'label' => __('demoted — shown after anything unranked,'
                    . ' never hidden'),
            ),
        );
    }

    /**
     * @return array `value`/`label` pairs
     */
    private function attributionOptions()
    {
        return array(
            array(
                'value' => self::ATTRIBUTION_COUNTS,
                'label' => __('an attribution'),
            ),
        );
    }

    /**
     * The warning that keeps the pinned tier worth having.
     *
     * A pin buys attention by being rare: the tier renders absence, and
     * a reader shown eight absences learns to skip the region. So the
     * editor says so at five rather than refusing at five — an analyst
     * with a reason to pin six is not wrong, they are spending
     * something, and the editor's job is to say what.
     *
     * @param array $plan
     * @param string $scope
     * @return string|null
     */
    private function pinNote(array $plan, $scope)
    {
        $pinned = count($plan[$scope][ValueLabelPriority::PINNED]);
        if ($pinned <= ValueLabelPriority::PIN_WARN_AT) {
            return null;
        }
        return sprintf(
            __('%d pinned. Each one draws a row on every value that'
                . ' carries none of it, and a card listing that many'
                . ' absences is a card readers learn to skip.'),
            $pinned
        );
    }

    /**
     * Candidate keys a map does not already carry, so an "add one"
     * picker offers what is missing rather than everything.
     *
     * @param array $candidates
     * @param array $used
     * @return array
     */
    private function unusedKeys(array $candidates, array $used)
    {
        $out = array();
        foreach ($candidates as $candidate) {
            if (!array_key_exists($candidate, $used)) {
                $out[] = $candidate;
            }
        }
        return $out;
    }

    /**
     * @param mixed $value
     * @return bool
     */
    private function isList($value)
    {
        if (!is_array($value)) {
            return false;
        }
        if ($value === array()) {
            return true;
        }
        return array_keys($value) === range(0, count($value) - 1);
    }
}
