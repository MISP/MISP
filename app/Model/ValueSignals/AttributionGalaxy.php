<?php

/**
 * What this value has been attributed to.
 *
 * A galaxy cluster on an occurrence is a person's judgement that this
 * indicator belongs to a named actor, family or campaign — the
 * strongest editorial statement MISP's data model carries — so it is
 * worth more than another count of the same rows.
 *
 * **Absence fires here, and this is the case absence keys exist for.**
 * *"No galaxy and no technique on any occurrence"* scores toward
 * benign: nine occurrences, four organisations, and nobody willing to
 * attribute it to anything is evidence rather than a gap. It fires
 * only where the profile carries an `absent` key and only on genuine
 * absence — a cluster set an exclusion emptied leaves the row silent.
 *
 * **An absence says where it looked.** *Occurrence* is the whole of
 * the distinction this signal rests on, and a row that leans on the
 * word silently reads as a contradiction of the context card: the
 * Overview heads a *Threat Actor* group with *APT29*, this says nobody
 * attributed the value, and a reader is left to reconcile two true
 * sentences. So where the carrying events name a threat the count is
 * put in the row and the reason under it. **Nothing about the score
 * changes** — the event labels are not an attribution of the value and
 * are not paid for, which is the point the wording makes out loud
 * rather than by omission.
 *
 * **One point per cluster, not per occurrence.** The same actor tag on
 * a hundred occurrences is one attribution repeated; on *"QakBot, on
 * 107 occurrences"* a per-occurrence weight would pay 107 times for
 * one judgement. The occurrence count belongs in the prose,
 * where it is context rather than arithmetic.
 *
 * **Not every cluster is an attribution, and the profile says which
 * are.** The context splits a value's galaxy tags into techniques and
 * clusters on *is this ATT&CK-shaped*, so `clusters` is every galaxy
 * that is not — sectors, countries, countermeasures and typologies
 * included. Unfiltered, a value tagged `sector:banking`, `country:lu`
 * and a `preventive-measure` would be paid three times over and called
 * attribution. `galaxies.attribution` is the eligibility filter; a
 * profile declaring none counts every cluster, which is what a profile
 * written before the section existed needs.
 *
 * **The event's attribution reaches a flagged occurrence, at a
 * discount.** Nearly every reporter attributes on the event
 * rather than on each attribute, so the clusters on an event in which
 * the reporter flagged this value `to_ids = 1` pay on a second row at
 * `per_event_cluster`, capped by `event_cap`. Flagged is what keeps
 * the caution above: it says this value is an indicator of the
 * report's threat, which the resolver an APT29 sample touched is not.
 * A cluster already on an occurrence is paid there and not again.
 */
class AttributionGalaxy extends ValueSignalBase
{
    public $id = 'attribution.galaxy';
    public $group = 'Attribution';
    public $evidence_class = self::EVIDENCE_ROW;
    public $reads = array('galaxies');
    public $absence_key = 'absent';
    public $tab = 'general';

    public function __construct()
    {
        $this->description = __(
            'Adds points when the value is tied to a threat actor, malware'
            . ' family or campaign by a galaxy cluster; fewer when only the'
            . ' event flagging it is.'
        );
        $this->help = array(
            'name' => __('Attributed to a threat'),
            'what' => __(
                'Galaxy clusters on the value itself: somebody\'s judgement'
                . ' that it belongs to a named actor, family or campaign.'
                . ' A cluster counts once however many occurrences carry'
                . ' it. Clusters on an event that flags the value for'
                . ' detection count too, for less. Which galaxies count is'
                . ' set under What counts as an attribution.'
            ),
            'how' => __(
                'Each cluster on the value is worth {per_cluster} points,'
                . ' up to {cap}. Each cluster only on a flagging event is'
                . ' worth {per_event_cluster}, up to {event_cap}. Nothing'
                . ' attributed at all: {absent}.'
            ),
            'settings' => array(
                'per_cluster' => __(
                    'What one cluster on the value is worth.'
                ),
                'cap' => __('The most clusters on the value can add.'),
                'per_event_cluster' => __(
                    'What one cluster on a flagging event is worth. Raise'
                    . ' it if your reporters attribute events rather than'
                    . ' each attribute.'
                ),
                'event_cap' => __(
                    'The most the events\' clusters can add.'
                ),
                'absent' => __(
                    'Points when nobody attributed the value. Lower it to'
                    . ' push unattributed values down.'
                ),
            ),
            'recipes' => array(
                array(
                    'want' => __('An event\'s attribution should count as'
                        . ' much as the value\'s own'),
                    'do' => __('Set per_event_cluster and event_cap to'
                        . ' per_cluster and cap, e.g. 7 and 21.'),
                ),
                array(
                    'want' => __('Unattributed values should rank'
                        . ' clearly lower'),
                    'do' => __('Lower absent, e.g. to -5.'),
                ),
                array(
                    'want' => __('Another galaxy, e.g. sectors, should'
                        . ' count as attribution'),
                    'do' => __('Add it under What counts as an'
                        . ' attribution → Attribution galaxies.'),
                ),
            ),
        );
        $this->points_schema = array(
            'per_cluster' => array(
                'type' => 'int',
                'default' => 7,
                'label' => __('Points per distinct cluster'),
            ),
            'cap' => array(
                'type' => 'int',
                'default' => 21,
                'label' => __('Most this signal may contribute'),
            ),
            'per_event_cluster' => array(
                'type' => 'int',
                'default' => 3,
                'label' => __('Points per cluster on an event that'
                    . ' flags it for detection'),
            ),
            'event_cap' => array(
                'type' => 'int',
                'default' => 9,
                'label' => __('Most the events\' clusters may'
                    . ' contribute'),
            ),
            'absent' => array(
                'type' => 'int',
                'default' => -1,
                'label' => __('Points when nobody has attributed it'),
            ),
        );
        $this->unit = array(
            'points' => 'per_cluster',
            'cap' => 'cap',
            'one' => __('A galaxy cluster on any occurrence'),
            'many' => __('%d galaxy clusters across the occurrences'),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $galaxies = isset($context['galaxies'])
            ? $context['galaxies']
            : array();
        $carried = isset($galaxies['clusters'])
            ? $galaxies['clusters']
            : array();
        $clusters = $this->eligible($galaxies, $carried);
        $onFlagged = array_diff_key(
            $this->eligible(
                $galaxies,
                $this->listIn($galaxies, 'on_flagged_events'),
                $this->listIn($galaxies, 'event_types')
            ),
            $clusters
        );
        if (empty($clusters) && empty($onFlagged)) {
            if (!$this->absenceFires($config, $context, 'galaxies')) {
                return null;
            }
            /*
             * Three absences, and they are not the same finding.
             * Nobody labelled this at all, somebody labelled it with
             * galaxies that name no threat, or the labels naming one
             * are on the events rather than on this value — and a
             * signal that said *no galaxy on any occurrence* over a
             * value carrying `sector:banking` would be contradicted by
             * the context card two panels away.
             *
             * **The third is the same objection at event scope**, and
             * it is the one a reader actually meets: the context card
             * heads a *Threat Actor* group with *APT29*, this row says
             * nobody attributed it, and both are true. The word doing
             * the work is *occurrence*, and it was doing it silently.
             * So the count is said out loud and the evidence line says
             * why it is not an attribution, which is the distinction
             * `ValueIntelligence::verdictEventGalaxies` exists to keep
             * rather than to soften.
             *
             * `eligible()` runs over the event set too, so the two
             * halves of the sentence count the same kind of thing: a
             * value whose events carry only `producer` and a typology
             * says *no galaxy* with nothing in brackets, rather than
             * sending its reader to look for an attribution that is
             * not there.
             */
            $ruled = count($carried);
            $evidence = __('Nobody has attributed this value to an'
                . ' actor, family or campaign');
            if ($ruled === 0) {
                $onEvents = $this->eligible(
                    $galaxies,
                    $this->listIn($galaxies, 'on_events'),
                    $this->listIn($galaxies, 'event_types')
                );
                if (empty($onEvents)) {
                    $signal = __('No galaxy on any occurrence');
                } else {
                    $signal = sprintf(
                        __('No galaxy on any occurrence (%d on the'
                            . ' events it appears in)'),
                        count($onEvents)
                    );
                    $evidence = __('Its events are attributed to a'
                        . ' threat; the value is not, and is not'
                        . ' flagged for detection in them');
                }
            } elseif ($ruled === 1) {
                $signal = __('One galaxy on the occurrences, and it'
                    . ' names no threat');
            } else {
                $signal = sprintf(
                    __('%d galaxies on the occurrences, none of them'
                        . ' naming a threat'),
                    $ruled
                );
            }
            return $this->row(
                $this->points($config, 'absent'),
                $signal,
                $evidence,
                $context
            );
        }
        $rows = array();
        if (!empty($clusters)) {
            $rows[] = $this->occurrenceRow($clusters, $config, $context);
        }
        if (!empty($onFlagged)) {
            $rows[] = $this->eventRow($onFlagged, $config, $context);
        }
        return count($rows) === 1 ? $rows[0] : array('rows' => $rows);
    }

    /**
     * The clusters on the value's own occurrences.
     *
     * @param array $clusters Eligible cluster name => occurrences
     * @param array $config
     * @param array $context
     * @return array
     */
    private function occurrenceRow(array $clusters, array $config,
        array $context
    ) {
        arsort($clusters);
        $points = $this->capped(
            $this->points($config, 'per_cluster') * count($clusters),
            $this->points($config, 'cap')
        );
        $names = array_keys($clusters);
        $lead = $names[0];
        $occurrences = (int)$clusters[$lead];
        $signal = count($names) === 1
            ? sprintf(
                __('Linked to galaxy: %1$s (%2$d %3$s)'),
                $lead,
                $occurrences,
                $occurrences === 1
                    ? __('occurrence')
                    : __('occurrences')
            )
            : sprintf(
                __('Linked to %1$d galaxy clusters, led by %2$s'),
                count($names),
                $lead
            );
        return $this->row(
            $points,
            $signal,
            implode(', ', array_slice($names, 0, 4)),
            $context
        );
    }

    /**
     * The clusters on events that flag the value for detection.
     *
     * `unit` is false because `$unit` describes a cluster on an
     * occurrence: the falsifier's arithmetic reads the occurrence row
     * against `cap`, and this row has a cap of its own.
     *
     * @param array $clusters Eligible cluster name => flagged events
     * @param array $config
     * @param array $context
     * @return array
     */
    private function eventRow(array $clusters, array $config,
        array $context
    ) {
        arsort($clusters);
        $points = $this->capped(
            $this->points($config, 'per_event_cluster') * count($clusters),
            $this->points($config, 'event_cap')
        );
        $names = array_keys($clusters);
        $lead = $names[0];
        $events = (int)$clusters[$lead];
        $signal = count($names) === 1
            ? sprintf(
                __('Flagged for detection in %1$s attributed to %2$s'),
                $events === 1
                    ? __('an event')
                    : sprintf(__('%d events'), $events),
                $lead
            )
            : sprintf(
                __('Flagged for detection in events attributed to %1$d'
                    . ' clusters, led by %2$s'),
                count($names),
                $lead
            );
        $row = $this->row(
            $points,
            $signal,
            implode(', ', array_slice($names, 0, 4)) . ' — '
                . __('the reporter\'s attribution of the event, which'
                    . ' counts for less than one of the value'),
            $context
        );
        $row['unit'] = false;
        return $row;
    }

    /**
     * One map out of the context's galaxy half, or an empty one.
     *
     * @param array $galaxies
     * @param string $key
     * @return array
     */
    private function listIn(array $galaxies, $key)
    {
        return isset($galaxies[$key]) && is_array($galaxies[$key])
            ? $galaxies[$key]
            : array();
    }

    /**
     * The clusters this profile counts as an attribution.
     *
     * The filter is off unless the profile declares a list, so an
     * instance whose profile predates the section scores exactly as it
     * did. A cluster whose galaxy the context could not record is kept
     * for the same reason: dropping it would silently lower a score on
     * a data shape this signal cannot see, and the wrong answer there
     * is the one that removes evidence rather than the one that keeps
     * it.
     *
     * A cluster name folds two galaxies into one entry where both name
     * it — *Lazarus Group* is a `threat-actor` and an
     * `mitre-intrusion-set` — so one eligible galaxy is enough.
     *
     * The types map is a parameter rather than a lookup because the
     * absence wording asks the same question of a second set — the
     * clusters on the carrying events — and one rule applied to both
     * is what keeps the ledger from calling a galaxy an attribution in
     * brackets and not in the row above.
     *
     * @param array $galaxies The context's galaxy half
     * @param array $clusters Cluster name => occurrences
     * @param array|null $types Cluster name => galaxy types; the
     *                          occurrence set's own map when omitted
     * @return array The subset that attributes
     */
    private function eligible(array $galaxies, array $clusters,
        ?array $types = null
    ) {
        if (empty($galaxies['attribution'])
            || !is_array($galaxies['attribution'])
            || empty($clusters)
        ) {
            return $clusters;
        }
        $allowed = array_flip($galaxies['attribution']);
        if ($types === null) {
            $types = isset($galaxies['types'])
                && is_array($galaxies['types'])
                ? $galaxies['types']
                : array();
        }
        $kept = array();
        foreach ($clusters as $name => $occurrences) {
            if (!isset($types[$name]) || !is_array($types[$name])) {
                $kept[$name] = $occurrences;
                continue;
            }
            foreach ($types[$name] as $type) {
                if (isset($allowed[$type])) {
                    $kept[$name] = $occurrences;
                    break;
                }
            }
        }
        return $kept;
    }
}
