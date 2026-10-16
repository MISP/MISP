<?php
App::uses('ValueIntelligenceBuckets', 'Tools/ValueIntelligence');
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');

/**
 * The cross-cutting aggregates the Value Intelligence page's panels share:
 * facet counts, organisation and type rollups, and the seen-density
 * histogram behind the occurrence rail's sparkline.
 *
 * Pure and static, the shape `ValueIntelligenceBuckets` also takes. **No
 * method here accepts a
 * `$user`**, and none of them queries anything: the owning model
 * pre-scopes and hands over a set that is already filtered, so this
 * class cannot leak data the viewer may not see. That is checkable by
 * reading the signatures rather than by tracing the callers.
 */
class ValueStatsTool
{
    /** MISP's "inherit from the parent" distribution level. */
    const INHERIT = 5;

    /**
     * Restrictiveness, tightest first — the order this class resolves a
     * distribution chain by, and the only place it is decided.
     *
     * `0` is one organisation and is strictly tightest. `4` is a named
     * list of organisations, so it sits next: bounded and explicit,
     * where `1`–`3` widen by community. **`4` is not truly comparable
     * with `1`–`3`** — a sharing group can carry an `all_orgs` server
     * entry and so be wider than "this community only" — which is why a
     * chain mixing the two is reported as an intersection rather than
     * silently flattened. See `effectiveDistribution()`.
     */
    private static $restrictiveness = array(0 => 0, 4 => 1, 1 => 2,
        2 => 3, 3 => 4);

    /**
     * Who can actually see one occurrence, as a single level.
     *
     * An attribute carries a distribution, so does the object holding it
     * and so does the event holding that, and MISP's own visibility rule
     * is the conjunction of all three — `MispAttribute::buildConditions`
     * requires the event to allow the viewer *and* the attribute *and*
     * the object, with level 5 passing through. Reporting the attribute's
     * own column instead says `Inherited` for almost every row on a real
     * instance and tells the reader nothing.
     *
     * Two steps. **Inheritance is resolved**: a link at level 5 states
     * nothing of its own and defers outward, and an event can never be 5,
     * so at least one link always states a level. **Then the tightest
     * stated level wins**, by `$restrictiveness`.
     *
     * `intersects` is the honest part. When a sharing group is one of
     * several stated constraints, the real audience is an intersection —
     * that group's members *and* whatever the other constraint allows —
     * and no single level says that. It is true only where the ambiguity
     * is real: a level 0 anywhere dominates every other constraint, and
     * the same sharing group stated twice is one constraint, so neither
     * of those sets it.
     *
     * A row with no object must not be read as an object at level 0. The
     * `Object` key is always present after a `contain`, holding nulls
     * where the LEFT JOIN found nothing, so the object link counts only
     * when it has an id.
     *
     * @param array $row fetchAttributes-shaped, with Event contained
     * @param array $sharingGroupNames id => name, for the groups this
     *                                 viewer may see
     * @return array level, sharing_group_id, sharing_group_name, source,
     *               stated, intersects, inherited
     */
    public static function effectiveDistribution(array $row,
        array $sharingGroupNames = array()
    ) {
        $links = array(
            self::link('attribute', __('Attribute'), $row['Attribute']),
        );
        if (!empty($row['Object']['id'])) {
            $links[] = self::link('object', __('Object'), $row['Object']);
        }
        $links[] = self::link('event', __('Event'), $row['Event']);
        return self::resolveChain($links, $sharingGroupNames);
    }

    /**
     * One link of a distribution chain, from the record holding it.
     *
     * `sharing_group_id` is read off records that may not have been
     * fetched with the column — a chain built from a `fields` list that
     * omits it is a chain of levels, and a level that is not 4 has no
     * group to name anyway.
     *
     * @param string $scope
     * @param string $label
     * @param array $from The record's own row
     * @return array
     */
    private static function link($scope, $label, array $from)
    {
        return array(
            'scope' => $scope,
            'label' => $label,
            'level' => (int)$from['distribution'],
            'sharing_group_id' => isset($from['sharing_group_id'])
                ? (int)$from['sharing_group_id']
                : null,
        );
    }

    /**
     * The same two steps over any chain of records that inherit
     * outward, so the rule lives in one place rather than once per
     * chain shape.
     *
     * An occurrence's chain is attribute → object → event. **An event
     * report's is report → event**, and MISP enforces the same
     * conjunction there: `EventReport::buildACLConditions` requires the
     * event to allow the viewer *and* the report, with level 5 passing
     * through — so a report deferring to its event is read exactly as
     * an attribute deferring to its own.
     *
     * The chain is ordered innermost first, and the outermost link must
     * state a level: an event can never be 5, which is what makes
     * `stated` non-empty for every chain MISP can hold.
     *
     * @param array $links scope, label, level, sharing_group_id — the
     *                     innermost record first
     * @param array $sharingGroupNames id => name, for the groups this
     *                                 viewer may see
     * @return array level, rank, sharing_group_id, sharing_group_name,
     *               source, stated, intersects, inherited
     */
    public static function resolveChain(array $links,
        array $sharingGroupNames = array()
    ) {
        $innermost = empty($links) ? null : $links[0]['scope'];
        $stated = array();
        foreach ($links as $link) {
            $level = (int)$link['level'];
            if ($level === self::INHERIT) {
                continue;
            }
            $stated[] = array(
                'scope' => $link['scope'],
                'label' => $link['label'],
                'level' => $level,
                'sharing_group_id' => $level === 4
                    ? $link['sharing_group_id']
                    : null,
            );
        }

        if (empty($stated)) {
            // Only reachable if an event were itself at level 5, which
            // MISP does not allow. Reported rather than guessed at.
            return array(
                'level' => null,
                'rank' => PHP_INT_MAX,
                'sharing_group_id' => null,
                'sharing_group_name' => null,
                'source' => null,
                'stated' => array(),
                'intersects' => false,
                'inherited' => true,
            );
        }

        $winner = $stated[0];
        foreach ($stated as $candidate) {
            if (self::restrictionRank($candidate['level'])
                < self::restrictionRank($winner['level'])
            ) {
                $winner = $candidate;
            }
        }

        return array(
            'level' => $winner['level'],
            // Position in `$restrictiveness`, so a caller ordering rows
            // by audience does not have to know the order — the one
            // place it is decided stays the one place.
            'rank' => self::restrictionRank($winner['level']),
            'sharing_group_id' => $winner['sharing_group_id'],
            'sharing_group_name' => $winner['sharing_group_id'] !== null
                    && isset($sharingGroupNames[$winner['sharing_group_id']])
                ? $sharingGroupNames[$winner['sharing_group_id']]
                : null,
            'source' => $winner['scope'],
            'stated' => $stated,
            'intersects' => self::intersects($stated, $winner),
            // The innermost record deferred, so this level is somebody
            // else's decision — worth saying, because it is not
            // editable where the reader is looking.
            'inherited' => $winner['scope'] !== $innermost,
        );
    }

    /**
     * A distribution level as the words the rest of the product uses.
     *
     * MISP's own `DistributionLevel` helper holds these, and a helper
     * is reachable from a template and not from a model — so a lane
     * composing a sentence about an audience had no way to name one.
     * Rather than a third spelling of the same five strings beside it,
     * the one place the levels are already reasoned about names them.
     *
     * `null` is *the chain did not resolve* and 5 is *inherit*: two
     * different things that print the same way, because in both cases
     * what the record states is nothing.
     *
     * @param int|null $level
     * @param string|null $sharingGroupName Where the level is 4 and the
     *                                      group resolved for this
     *                                      viewer
     * @return string
     */
    public static function levelLabel($level, $sharingGroupName = null)
    {
        if ($level === null) {
            return __('Inherit event');
        }
        $level = (int)$level;
        if ($level === 4) {
            return $sharingGroupName === null
                ? __('Sharing group')
                : $sharingGroupName;
        }
        $levels = array(
            0 => __('Your organisation only'),
            1 => __('This community only'),
            2 => __('Connected communities'),
            3 => __('All communities'),
        );
        return isset($levels[$level])
            ? $levels[$level]
            : __('Inherit event');
    }

    /**
     * Where a level sits in `$restrictiveness`.
     *
     * Public because `effectiveDistribution` is not the only caller
     * that has to order audiences: the co-occurrence fold
     * builds one for a label out of its event's level, and the ordering
     * has to stay decided in this one place rather than be re-derived
     * beside the second caller.
     *
     * @param int $level
     * @return int
     */
    public static function restrictionRank($level)
    {
        return isset(self::$restrictiveness[$level])
            ? self::$restrictiveness[$level]
            : PHP_INT_MAX;
    }

    /**
     * Whether the stated constraints narrow each other in a way one
     * level cannot express. See `effectiveDistribution()`.
     *
     * @param array $stated
     * @param array $winner
     * @return bool
     */
    private static function intersects(array $stated, array $winner)
    {
        if ($winner['level'] === 0) {
            return false;
        }
        $groups = array();
        $others = 0;
        foreach ($stated as $constraint) {
            if ($constraint['level'] === 4) {
                $groups[$constraint['sharing_group_id']] = true;
            } elseif ($constraint['level'] !== 0) {
                $others++;
            }
        }
        if (empty($groups)) {
            return false;
        }
        return count($groups) > 1 || $others > 0;
    }

    /**
     * The token a facet checkbox carries and a row is matched on.
     *
     * One rule with two callers, which is why it is here rather than in
     * either of them. The rail counts by it and
     * `value_occurrence_table.ctp` stamps it on each row; a slug written
     * down by hand in one place and derived by a regex in the other
     * would drift apart with nothing to notice. A MISP type can hold
     * characters
     * an attribute value should not — `domain|ip` — so everything is
     * slugged rather than only the values that look like they need it.
     *
     * @param string $text
     * @return string
     */
    public static function facetToken($text)
    {
        return trim(
            preg_replace('/[^a-z0-9]+/', '-', strtolower((string)$text)),
            '-'
        );
    }

    /**
     * The numbers in the occurrence table's panel header.
     *
     * `$total` is the viewer's own count of the value's occurrences and
     * arrives from the model; everything else is counted from the rows
     * the panel was actually given, so a capped fetch cannot claim to
     * describe events and organisations it never loaded.
     *
     * @param array $rows fetchAttributes-shaped occurrence rows
     * @param int $total The viewer's occurrence count for the value
     * @return array
     */
    public static function occurrenceStats(array $rows, $total)
    {
        $events = array();
        $orgs = array();
        $deleted = 0;
        foreach ($rows as $row) {
            $events[$row['Event']['id']] = true;
            if (isset($row['Event']['Orgc']['id'])) {
                $orgs[$row['Event']['Orgc']['id']] = true;
            }
            if (!empty($row['Attribute']['deleted'])) {
                $deleted++;
            }
        }
        return array(
            'total' => (int)$total,
            'shown' => count($rows),
            'events' => count($events),
            'orgs' => count($orgs),
            'deleted' => $deleted,
        );
    }

    /**
     * The counted rail beside the occurrence table.
     *
     * Order, heading and glyph are not here: `value_occurrence_facets`
     * owns those because they are the same for every value. What this
     * returns is only what varies — counts, and the domain values behind
     * them.
     *
     * All ten groups are always present, empty where the rows offer
     * nothing. The rail iterates a fixed list of keys and dereferences
     * two of them directly, so a missing key is a warning rather than an
     * absent group; `value_facet_group` is what decides that a group of
     * zeroes renders nothing at all.
     *
     * **The two label groups are ordered by the reader's profile, and
     * ordered here rather than in the rail**: `value_facet_group` shows
     * ten rows and folds the rest, so this is the one label surface
     * where priority decides what is visible rather than what is read
     * first. Ordering after the fold would rank the ten the counts
     * chose.
     *
     * A null plan — every caller that has no profile to hand — leaves
     * both groups exactly as the counts ranked them.
     *
     * @param array $rows fetchAttributes-shaped occurrence rows,
     *                    already carrying Event.Orgc, SharingGroup,
     *                    AttributeTag.Tag and proposal_count
     * @param int $total The viewer's occurrence count for the value
     * @param array|null $plan `ValueLabelPriority::planFor()`
     * @return array
     */
    public static function occurrenceFacets(array $rows, $total,
        $plan = null
    ) {
        $groups = array(
            'organisation' => array(),
            'type' => array(),
            'object' => array(),
            'category' => array(),
            'ids' => array(),
            'distribution' => array(),
            'sharing_group' => array(),
            // One group over both scopes, matching the Tags column:
            // `value_occurrence_table`'s token builder has the reason.
            'tag' => array(),
            /*
             * The clusters the row is attributed to, from
             * `ValueIntelligence::attachClusters` — already ruled on,
             * already deduplicated across the two scopes, already
             * named. A galaxy tag that did not come back as a cluster
             * is not here, so the rail cannot offer a filter on
             * something the table will not draw.
             */
            'galaxy' => array(),
            'state' => array(),
        );
        $deleted = 0;
        $proposals = 0;

        foreach ($rows as $row) {
            $attribute = $row['Attribute'];

            if (isset($row['Event']['Orgc']['id'])) {
                self::bump(
                    $groups['organisation'],
                    (string)$row['Event']['Orgc']['id'],
                    $row['Event']['Orgc']['name']
                );
            }
            self::bump(
                $groups['type'],
                self::facetToken($attribute['type']),
                $attribute['type']
            );
            /*
             * The object template the occurrence sits in — `domain-ip`,
             * `network-socket` — which is a different question from its
             * type and one the type facet cannot answer: the same
             * `ip-dst` turns up standalone, inside a `domain-ip` and
             * inside a `network-socket`, and those are three different
             * things to have found.
             *
             * The template's name and not the object's id: a value's
             * occurrences are almost never in the *same* object, so
             * per-instance counts would all be one.
             *
             * Standalone rows get a value of their own rather than no
             * token, so the group partitions the rows and the reader can
             * ask for the complement, which a group counting only the
             * rows inside objects could not offer. `standalone` cannot
             * collide with a slugged
             * template name unless somebody ships an object template
             * called "standalone".
             */
            if (empty($row['Object']['name'])) {
                self::bump(
                    $groups['object'],
                    'standalone',
                    __('Standalone attribute')
                );
            } else {
                self::bump(
                    $groups['object'],
                    self::facetToken($row['Object']['name']),
                    $row['Object']['name']
                );
            }
            self::bump(
                $groups['category'],
                self::facetToken($attribute['category']),
                $attribute['category']
            );
            self::bump(
                $groups['ids'],
                empty($attribute['to_ids']) ? 'unset' : 'set',
                empty($attribute['to_ids'])
                    ? __('to_ids unset')
                    : __('to_ids set')
            );
            /*
             * The **effective** level, not `Attribute.distribution`.
             * Almost every attribute on a real instance is at level 5,
             * so a rail counting the column says `Inherited: 100` and
             * answers nobody's question; the resolved chain says who can
             * actually see each row. `effectiveDistribution()` has the
             * rule, and the model stamps it on the row so the rail and
             * the table cannot resolve it differently.
             */
            $effective = isset($row['effective_distribution'])
                ? $row['effective_distribution']
                : null;
            $level = $effective === null ? null : $effective['level'];
            if ($level !== null) {
                self::bump(
                    $groups['distribution'],
                    (string)$level,
                    null,
                    array('level' => $level)
                );
                // Named by whichever link in the chain won, so a row
                // distributed through its event's sharing group is
                // counted under that group rather than not at all.
                if ($level === 4
                    && !empty($effective['sharing_group_id'])
                ) {
                    self::bump(
                        $groups['sharing_group'],
                        (string)$effective['sharing_group_id'],
                        $effective['sharing_group_name'] !== null
                            ? $effective['sharing_group_name']
                            : sprintf(
                                __('Sharing group #%s'),
                                $effective['sharing_group_id']
                            )
                    );
                }
            }
            /*
             * **Both scopes into one group, and once per row.** The
             * Tags column draws the attribute's labels and its event's
             * as one list, so the rail that narrows it counts them the
             * same way — and a row whose attribute and whose event both
             * carry `tlp:white` is *one* row matching that filter, so
             * the second sighting must not bump the count again.
             */
            $rowTags = array();
            foreach ($row['AttributeTag'] as $attributeTag) {
                if (!empty($attributeTag['Tag'])) {
                    $rowTags[] = $attributeTag['Tag'];
                }
            }
            foreach ($row['EventTag'] ?? array() as $eventTag) {
                if (!empty($eventTag['Tag'])) {
                    $rowTags[] = $eventTag['Tag'];
                }
            }
            $countedTags = array();
            foreach ($rowTags as $tag) {
                // The Tags column does not draw galaxy tags either, and
                // a filter on something invisible is not a filter.
                if (!empty($tag['is_galaxy'])) {
                    continue;
                }
                $token = self::facetToken($tag['name']);
                if (isset($countedTags[$token])) {
                    continue;
                }
                $countedTags[$token] = true;
                self::bump(
                    $groups['tag'],
                    $token,
                    $tag['name'],
                    array(
                        'tag' => $tag,
                        'local' => !empty($tag['local']) ? 1 : 0,
                        // What a profile lists a taxonomy by, and the
                        // full name its handling order is read from.
                        'key' => ValueLabelPriority::namespaceOf(
                            $tag['name']
                        ),
                        'name' => $tag['name'],
                    )
                );
            }
            foreach ($row['Cluster'] ?? array() as $cluster) {
                self::bump(
                    $groups['galaxy'],
                    self::facetToken($cluster['tag_name']),
                    $cluster['name'],
                    array(
                        'cluster' => $cluster['name'],
                        'galaxy' => $cluster['galaxy'],
                        // The galaxy `type`, which is what a profile
                        // lists; `galaxy` beside it is the display
                        // name and is not a key.
                        'key' => isset($cluster['type'])
                            ? $cluster['type']
                            : null,
                    )
                );
            }
            if (!empty($row['proposal_count'])) {
                $proposals++;
            }
            if (!empty($attribute['deleted'])) {
                $deleted++;
            }
        }

        /*
         * A tag attached locally on one occurrence and globally on
         * another is one facet, because the row token is the tag's name
         * and carries no local/global distinction. `local` therefore
         * survives only when every attachment was local, so the chip
         * never marks a globally-attached tag as local.
         */
        foreach ($groups['tag'] as $token => $facet) {
            $groups['tag'][$token]['local'] =
                empty($facet['local_all']) ? 0 : 1;
            unset($groups['tag'][$token]['local_all']);
        }

        if ($proposals > 0) {
            self::bump(
                $groups['state'],
                'proposal',
                __('With a pending proposal'),
                array(),
                $proposals
            );
        }

        foreach ($groups as $key => $facets) {
            $groups[$key] = self::rank($facets);
        }
        /*
         * After the count rank and before the rail's fold, so a
         * preferred taxonomy reaches the visible ten and the counts
         * still decide the order inside each tier.
         */
        $groups['tag'] = ValueLabelPriority::labels(
            $groups['tag'],
            $plan,
            ValueLabelPriority::TAXONOMIES
        );
        $groups['galaxy'] = ValueLabelPriority::labels(
            $groups['galaxy'],
            $plan,
            ValueLabelPriority::GALAXIES
        );

        return array_merge(
            array(
                // What the rail's own counts cover, which is the rows it
                // was given rather than the value's total.
                'visible' => count($rows),
                'total' => (int)$total,
                'groups' => $groups,
                'deleted' => $deleted,
            ),
            self::seenDensity($rows),
            self::timeSpans($rows)
        );
    }

    /**
     * Add one to a facet, creating it on first sight.
     *
     * @param array $group
     * @param string $token
     * @param string|null $label
     * @param array $extra Keys the rail renders a component from
     * @param int $by
     * @return void
     */
    private static function bump(array &$group, $token, $label,
        array $extra = array(), $by = 1
    ) {
        if (!isset($group[$token])) {
            $group[$token] = array_merge(
                array('value' => $token, 'count' => 0),
                $label === null ? array() : array('label' => $label),
                $extra
            );
            if (isset($extra['local'])) {
                $group[$token]['local_all'] = true;
            }
        }
        $group[$token]['count'] += $by;
        if (array_key_exists('local_all', $group[$token])
            && empty($extra['local'])
        ) {
            $group[$token]['local_all'] = false;
        }
    }

    /**
     * Count descending, then label, so redrawing the same rows cannot
     * reorder the rail.
     *
     * @param array $group
     * @return array
     */
    private static function rank(array $group)
    {
        $facets = array_values($group);
        usort($facets, function ($a, $b) {
            if ($a['count'] !== $b['count']) {
                return $b['count'] - $a['count'];
            }
            return strcmp(
                isset($a['label']) ? $a['label'] : $a['value'],
                isset($b['label']) ? $b['label'] : $b['value']
            );
        });
        return $facets;
    }

    /**
     * The three dates the rail can cut on, and what they span.
     *
     * `timestamp` is when the attribute was last modified and every
     * attribute has one. `published` is when its event was last
     * published, and an unpublished event has none — so those rows are
     * counted rather than quietly dropped, because a date cut over a
     * column that is sometimes absent has to say how much it removes
     * (the same rule `seen_unset` follows). `event` is when the event
     * itself was last modified, which moves when any attribute on it
     * does and so answers *when was this report last touched* rather
     * than *when was this occurrence*.
     *
     * The spans bound the date inputs. The inputs themselves start empty:
     * a control pre-filled with the full span looks like a filter that is
     * already applied, and "no bound" and "the widest bound" should not
     * render identically.
     *
     * @param array $rows
     * @return array `time_spans`, `time_buckets`, `published_unset`
     */
    private static function timeSpans(array $rows)
    {
        $keys = array('timestamp', 'published', 'event');
        $spans = array_fill_keys($keys, null);
        $days = array_fill_keys($keys, array());
        $unpublished = 0;
        foreach ($rows as $row) {
            $stamps = array(
                'timestamp' => $row['Attribute']['timestamp'] ?? null,
                'published' => empty($row['Event']['publish_timestamp'])
                    ? null
                    : $row['Event']['publish_timestamp'],
                'event' => $row['Event']['timestamp'] ?? null,
            );
            if ($stamps['published'] === null) {
                $unpublished++;
            }
            foreach ($stamps as $key => $stamp) {
                if (empty($stamp)) {
                    continue;
                }
                $day = date('Y-m-d', (int)$stamp);
                if (!isset($days[$key][$day])) {
                    $days[$key][$day] = 0;
                }
                $days[$key][$day]++;
                if ($spans[$key] === null) {
                    $spans[$key] = array('from' => $day, 'to' => $day);
                    continue;
                }
                $spans[$key]['from'] = min($spans[$key]['from'], $day);
                $spans[$key]['to'] = max($spans[$key]['to'], $day);
            }
        }
        $buckets = array();
        foreach ($spans as $key => $span) {
            $buckets[$key] = $span === null
                ? null
                : self::timeHistogram($span, $days[$key]);
        }
        return array(
            'time_spans' => $spans,
            'time_buckets' => $buckets,
            'published_unset' => $unpublished,
        );
    }

    /**
     * How many occurrences fall in each calendar bucket of a span, so
     * the rail can draw the shape of a date before the reader picks a
     * range out of it.
     *
     * A `timestamp` is an instant, so this is a `Y-m-d` count map
     * tallied into calendar buckets. `seenDensity()` shares the buckets
     * and counts intervals into them instead.
     *
     * The unit follows the span by a rule this caller owns, per the
     * tool's own contract. The default rule stops at weeks, which draws
     * a two-year span as a hundred-odd bars — legible in a full-width
     * chart and not in a `col-lg-3` rail, so months are added past a
     * year. Bars still thin out on a span of many years; the caption
     * states the grain so a thin bar is readable as a month rather than
     * as a gap.
     *
     * @param array $span `from` and `to`, `Y-m-d`
     * @param array $days `Y-m-d` => count
     * @return array `unit`, `max`, and `bars` of from/to/label/count
     */
    public static function timeHistogram(array $span, array $days)
    {
        $unit = self::railUnit($span);
        $series = self::railSeries($span);
        $index = ValueIntelligenceBuckets::locate($series);
        $counts = array_fill(0, count($series), 0);
        foreach ($days as $day => $count) {
            if (isset($index[$day])) {
                $counts[$index[$day]] += $count;
            }
        }
        $bars = array();
        foreach ($series as $position => $bucket) {
            $bars[] = array(
                'from' => $bucket['from'],
                'to' => $bucket['to'],
                'label' => $bucket['title'],
                'count' => $counts[$position],
            );
        }
        return array(
            'unit' => $unit,
            'max' => empty($counts) ? 0 : max($counts),
            'bars' => $bars,
        );
    }

    /**
     * @param array $span `from` and `to`, `Y-m-d`
     * @return string The rail's bucket unit for that span
     */
    private static function railUnit(array $span)
    {
        $spanDays = 1 + (int)round(
            (strtotime($span['to']) - strtotime($span['from'])) / 86400
        );
        return ValueIntelligenceBuckets::unitForSpan($spanDays, array(
            array('days' => 45, 'unit' => ValueIntelligenceBuckets::DAY),
            array('days' => 370, 'unit' => ValueIntelligenceBuckets::WEEK),
            array('days' => null, 'unit' => ValueIntelligenceBuckets::MONTH),
        ));
    }

    /**
     * @param array $span `from` and `to`, `Y-m-d`
     * @return array From `ValueIntelligenceBuckets::series()`
     */
    private static function railSeries(array $span)
    {
        return ValueIntelligenceBuckets::series(
            $span['from'],
            $span['to'],
            self::railUnit($span)
        );
    }

    /**
     * The date axis under a `timeHistogram()` strip: bar index => label,
     * or null for a tick without one.
     *
     * Ticks mark the next unit up from the grain (years over monthly bars,
     * months otherwise), never on the opening bucket, and labels are
     * thinned to about six and kept out of the last 8% of the bars so a
     * left-aligned one does not hang off the edge.
     *
     * @param array $histogram From `timeHistogram()`
     * @return array
     */
    public static function timeScale(array $histogram)
    {
        $bars = $histogram['bars'];
        $annual = $histogram['unit'] === ValueIntelligenceBuckets::MONTH;
        $marks = array();
        $seen = null;
        foreach ($bars as $index => $bar) {
            $period = substr($bar['from'], 0, $annual ? 4 : 7);
            $opened = $period !== $seen;
            $seen = $period;
            if (!$opened || $index === 0) {
                continue;
            }
            $marks[$index] = $annual
                ? $period
                : date('M', strtotime($bar['from']));
        }
        $step = max(1, (int)ceil(count($marks) / 6));
        $tail = count($bars)
            - max(1, (int)ceil(count($bars) * 0.08));
        $nth = 0;
        $scale = array();
        foreach ($marks as $index => $label) {
            $scale[$index] = ($nth % $step === 0 && $index < $tail)
                ? $label
                : null;
            $nth++;
        }
        return $scale;
    }

    /**
     * The strip under the rail's `First / last seen` heading.
     *
     * The same calendar buckets as the three time panes, each counting
     * the occurrences whose seen interval overlaps it — an occurrence
     * seen for three months is present in all three.
     *
     * `first_seen` and `last_seen` are optional, and either may be set
     * without the other — a row with only one of them is a point, and
     * covers the single bucket it falls in. A row with neither is
     * counted by `seen_unset` and placed nowhere, because a date filter
     * over a frequently-empty column has to say how much it would
     * silently drop.
     *
     * @param array $rows
     * @return array `seen_span`, `seen_buckets`, `seen_unset`
     */
    private static function seenDensity(array $rows)
    {
        $spans = array();
        $unset = 0;
        foreach ($rows as $row) {
            $first = self::stamp($row['Attribute']['first_seen'] ?? null);
            $last = self::stamp($row['Attribute']['last_seen'] ?? null);
            if ($first === null && $last === null) {
                $unset++;
                continue;
            }
            $from = $first === null ? $last : $first;
            $to = $last === null ? $first : $last;
            $spans[] = array(
                date('Y-m-d', min($from, $to)),
                date('Y-m-d', max($from, $to)),
            );
        }
        if (empty($spans)) {
            return array(
                'seen_span' => null,
                'seen_buckets' => null,
                'seen_unset' => $unset,
            );
        }

        $span = array(
            'from' => min(array_column($spans, 0)),
            'to' => max(array_column($spans, 1)),
        );
        $bars = array();
        $max = 0;
        foreach (self::railSeries($span) as $bucket) {
            $count = 0;
            foreach ($spans as $seen) {
                if ($seen[0] <= $bucket['to'] && $seen[1] >= $bucket['from']) {
                    $count++;
                }
            }
            $max = max($max, $count);
            $bars[] = array(
                'from' => $bucket['from'],
                'to' => $bucket['to'],
                'label' => $bucket['title'],
                'count' => $count,
            );
        }
        return array(
            'seen_span' => $span,
            'seen_buckets' => array(
                'unit' => self::railUnit($span),
                'max' => $max,
                'bars' => $bars,
            ),
            'seen_unset' => $unset,
        );
    }


    /**
     * The Overview card's sparkline: 90 days in 40 columns, all three
     * kinds of report, support above the line and contradiction below
     * it.
     *
     * Off the same rows the Sightings tab charts, which is the point of
     * it living here rather than being a fifth query of its own. The two
     * panels sit on the same page and a reader can see both at once, so
     * they must not be able to disagree about how busy the last 90 days
     * were.
     *
     * **It draws all three kinds, not type 0 alone.** *A false positive
     * is not a quiet week, and drawing it as one would put a
     * contradiction into the same bar as the support* — the argument is
     * right, and drawing only type 0 does not follow from it: the strip
     * would silently drop the contradicting reports under two tiles
     * counting exactly those, so they would not merely be uncoloured —
     * they would be absent, and nothing on the card would say so.
     *
     * The tab's own chart answers this: `sightingSeries`
     * hangs the contradicting types **below the axis**, where they can
     * never share a bar with the support and can never be mistaken for
     * it. This returns the same shape at sparkline scale, so the
     * geometry a reader learns on one surface reads the same on the
     * other.
     *
     * `up` and `down` are separately peaked by the caller, and the two
     * halves are sized in proportion so that one unit is one height on
     * both sides — a chart where four false positives out-drew forty
     * sightings would be a worse lie than the omission.
     *
     * The columns are folded from a dense per-day tally rather than
     * bucketed straight off the rows, so the day arithmetic is
     * `ValueIntelligenceBuckets`' and not a third copy of it.
     *
     * @param array $rows Rows as `Sighting::listSightings` returns
     * @param string $today `Y-m-d`
     * @return array 40 columns, oldest first, each `sighting`, `fp`,
     *               `expiration`, `from` and `to`
     */
    public static function sightingSpark(array $rows, $today)
    {
        $columns = 40;
        $days = 90;
        $start = strtotime($today) - ($days - 1) * 86400;
        $from = date('Y-m-d', $start);
        $kinds = array(1 => 'fp', 2 => 'expiration');
        $perDay = array('sighting' => array(), 'fp' => array(),
            'expiration' => array());
        foreach ($rows as $row) {
            $kind = $kinds[(int)$row['Sighting']['type']] ?? 'sighting';
            $day = date(
                'Y-m-d',
                (int)$row['Sighting']['date_sighting']
            );
            $perDay[$kind][$day] = ($perDay[$kind][$day] ?? 0) + 1;
        }

        $spark = array();
        for ($i = 0; $i < $columns; $i++) {
            $spark[$i] = array('sighting' => 0, 'fp' => 0,
                'expiration' => 0, 'from' => null, 'to' => null);
        }
        /*
         * One `tally` per kind rather than one over a triple: it sums
         * into an int accumulator, so an array value would be a type
         * error rather than three tallies. Three passes over ninety
         * days is not a cost worth reshaping a shared helper for.
         */
        foreach ($perDay as $kind => $days_) {
            foreach (ValueIntelligenceBuckets::tally($from, $today, $days_)
                     as $offset => $count
            ) {
                $column = min(
                    (int)floor(($offset * $columns) / $days),
                    $columns - 1
                );
                $spark[$column][$kind] += (int)$count;
            }
        }
        /*
         * The days each column stands for, so its tooltip can name a
         * range rather than leave the reader to divide 90 by 40.
         */
        for ($offset = 0; $offset < $days; $offset++) {
            $column = min(
                (int)floor(($offset * $columns) / $days),
                $columns - 1
            );
            $day = date('Y-m-d', $start + $offset * 86400);
            if ($spark[$column]['from'] === null) {
                $spark[$column]['from'] = $day;
            }
            $spark[$column]['to'] = $day;
        }
        return $spark;
    }

    /**
     * The three numbers the tab's headers count, plus who filed them.
     *
     * Every count here is the viewer's by construction: the rows arrive
     * from `Sighting::listSightings`, which has already applied
     * `Plugin.Sightings_policy` and `Plugin.Sightings_anonymise`. This
     * class never sees a row the reader may not see, which is what
     * taking no `$user` buys.
     *
     * An anonymised sighting comes back with an empty organisation name
     * and `org_id` 0, and is filed under one *Others* key rather than
     * one key per hidden organisation — otherwise the org stack would
     * leak the number of foreign reporters it is hiding.
     *
     * **A reporter's `count` is every report it filed, of any type**,
     * and that is deliberate: a contradiction is participation, and
     * hiding a false positive here would make the most sceptical
     * organisation look like the quietest. What it also has to do is
     * *say so*, which is why each reporter carries the same breakdown
     * the card's three tiles carry. Drawn as one bar it would assert
     * the opposite of the rule: ORG-A's bar would read 5 in the
     * sighting colour where three of its five reports corroborate the
     * value and two contradict or retire it.
     *
     * @param array $rows Rows as `Sighting::listSightings` returns
     * @return array
     */
    public static function sightingTotals(array $rows)
    {
        $counts = array('total' => 0, 'sighting' => 0, 'fp' => 0,
            'expiration' => 0);
        $blank = array('sighting' => 0, 'fp' => 0, 'expiration' => 0);
        $orgs = array();
        $orgKinds = array();
        $last = null;
        $lastFp = null;
        foreach ($rows as $row) {
            $type = (int)$row['Sighting']['type'];
            $kind = $type === 1
                ? 'fp'
                : ($type === 2 ? 'expiration' : 'sighting');
            $counts['total']++;
            $counts[$kind]++;
            $org = self::sightingOrg($row);
            $orgs[$org] = ($orgs[$org] ?? 0) + 1;
            if (!isset($orgKinds[$org])) {
                $orgKinds[$org] = $blank;
            }
            $orgKinds[$org][$kind]++;
            $at = (int)$row['Sighting']['date_sighting'];
            if ($last === null || $at > $last) {
                $last = $at;
            }
            if ($type === 1 && ($lastFp === null || $at > $lastFp)) {
                $lastFp = $at;
            }
        }
        arsort($orgs);
        $reporters = array();
        foreach ($orgs as $name => $count) {
            $reporters[] = array('org' => $name, 'count' => $count)
                + $orgKinds[$name];
        }
        return array(
            'total' => $counts['total'],
            'sighting' => $counts['sighting'],
            'fp' => $counts['fp'],
            'expiration' => $counts['expiration'],
            'reporters' => $reporters,
            'org_counts' => $orgs,
            'last_stamp' => $last,
            'last_fp_stamp' => $lastFp,
        );
    }

    /**
     * The same rows tallied by **organisation id** rather than by name,
     * which is what trust weighting needs.
     *
     * `sightingTotals` keys its stack by name, because that is what the
     * reporters card prints and because two organisations may not share
     * one. Nothing can be *graded* by name, though: the profile keys
     * grades by `organisations.uuid` and the join lands on the local id
     * (`ValueTrustTool`), so the weighted counts have to be read off
     * the id column.
     *
     * **An organisation this viewer cannot name is filed as
     * ungradeable, not as its id.** Anonymisation already zeroes
     * `org_id`, so the case that remains is a row carrying an id with
     * no disclosed name — and weighting *that* would move the number
     * for a reason the reader cannot see anywhere on the page, which a
     * weighting must never do. `sightingHasOrg()` is the same
     * both-or-neither test the rest of this class uses, so the two
     * tallies always agree about which rows are attributable.
     *
     * `names` comes back keyed by the same ids, so a caller that needs
     * to *print* the organisations it just weighted does not have to
     * pair two independently-built lists by position — which is how
     * a grade ends up printed against the wrong organisation.
     *
     * @param array $rows Rows as `Sighting::listSightings` returns
     * @return array `by_org` and `by_org_fp` (orgId => count),
     *               `by_org_last` (orgId => newest report),
     *               `by_org_fp_last` (orgId => newest false positive),
     *               `names` (orgId => name), plus `anonymous`,
     *               `anonymous_fp` and `anonymous_fp_last` for the rest
     */
    public static function sightingsByOrg(array $rows)
    {
        $byOrg = array();
        $byOrgFp = array();
        $names = array();
        $last = array();
        $fpLast = array();
        $anonymous = 0;
        $anonymousFp = 0;
        $anonymousFpLast = null;
        foreach ($rows as $row) {
            $isFp = ((int)$row['Sighting']['type'] === 1);
            $stamp = (int)$row['Sighting']['date_sighting'];
            if (!self::sightingHasOrg($row)) {
                $anonymous++;
                if ($isFp) {
                    $anonymousFp++;
                    $anonymousFpLast = max((int)$anonymousFpLast, $stamp);
                }
                continue;
            }
            $id = (int)$row['Sighting']['org_id'];
            $byOrg[$id] = ($byOrg[$id] ?? 0) + 1;
            $last[$id] = max($last[$id] ?? 0, $stamp);
            $names[$id] = $row['Organisation']['name'];
            if ($isFp) {
                $byOrgFp[$id] = ($byOrgFp[$id] ?? 0) + 1;
                $fpLast[$id] = max($fpLast[$id] ?? 0, $stamp);
            }
        }
        return array(
            'by_org' => $byOrg,
            'by_org_fp' => $byOrgFp,
            'by_org_last' => $last,
            'by_org_fp_last' => $fpLast,
            'names' => $names,
            'anonymous' => $anonymous,
            'anonymous_fp' => $anonymousFp,
            'anonymous_fp_last' => $anonymousFpLast,
        );
    }

    /**
     * The same rows narrowed to type-0 sightings, which are the only
     * reports that say the value was seen.
     *
     * The tallies above count every type, because the cards that print
     * them show the three types side by side. A score cannot: a false
     * positive argues the other way and an expiration says the value
     * is over, so counting either as volume, spread or recency lifts a
     * value on the very report that disputes it.
     *
     * @param array $rows Rows as `Sighting::listSightings` returns
     * @param int $now
     * @param int $recentDays What the row calls recent
     * @return array `total`, `orgs`, `last_stamp`, `recent`, `by_org`
     *               (orgId => count), `by_org_last` (orgId => stamp)
     *               and `anonymous`
     */
    public static function seenFacts(array $rows, $now, $recentDays)
    {
        $seen = array();
        foreach ($rows as $row) {
            if ((int)$row['Sighting']['type'] === 0) {
                $seen[] = $row;
            }
        }
        $totals = self::sightingTotals($seen);
        $signals = self::sightingSignals($seen, $now, $recentDays);
        $attributed = self::sightingsByOrg($seen);
        return array(
            'total' => $totals['total'],
            'orgs' => $signals['orgs'],
            'last_stamp' => $totals['last_stamp'],
            'recent' => $signals['recent'],
            'by_org' => $attributed['by_org'],
            'by_org_last' => $attributed['by_org_last'],
            'anonymous' => $attributed['anonymous'],
        );
    }

    /**
     * The individual-sightings table, oldest first.
     *
     * Oldest first because `value_sighting_list` reverses what it is
     * given: the brush indexes rows by date and the chart's series runs
     * forward, so one direction is chosen here and the panel's display
     * order is the panel's business.
     *
     * `against` is the occurrence the report was filed on, which is the
     * column a value-scoped list cannot do without — forty-seven
     * reports with no occurrence column silently merge ten occurrences
     * into one thing that was seen forty-seven times. It comes from the
     * id set rather than from a second lookup, so the table and the
     * chart cannot disagree about which occurrence a report belongs to.
     *
     * `org_id` and `against.attribute` are what the table links on, and
     * they are null exactly when there is nowhere to send the reader:
     * an anonymised report names no organisation, and an occurrence the
     * id set does not hold is one this reader may not open.
     *
     * @param array $rows Rows as `Sighting::listSightings` returns
     * @param array $occurrences As
     *              `Value::sightedOccurrenceIdsFor` returns
     * @return array
     */
    public static function sightingList(array $rows, array $occurrences)
    {
        $list = array();
        foreach ($rows as $row) {
            $id = (int)$row['Sighting']['attribute_id'];
            $source = $row['Sighting']['source'];
            $known = isset($occurrences[$id]);
            $list[] = array(
                'org' => self::sightingOrg($row),
                'org_id' => self::sightingHasOrg($row)
                    ? (int)$row['Sighting']['org_id']
                    : null,
                'source' => ($source === null || $source === '')
                    ? null
                    : $source,
                'date' => date(
                    'Y-m-d H:i',
                    (int)$row['Sighting']['date_sighting']
                ),
                'stamp' => (int)$row['Sighting']['date_sighting'],
                'type' => (int)$row['Sighting']['type'],
                'against' => array(
                    'attribute' => $known ? $id : null,
                    'event' => $known
                        ? $occurrences[$id]['event_id']
                        : (int)$row['Sighting']['event_id'],
                    'type' => $known
                        ? $occurrences[$id]['type']
                        : __('unknown type'),
                ),
            );
        }
        usort($list, function ($a, $b) {
            return $a['stamp'] - $b['stamp'];
        });
        return $list;
    }

    /**
     * The span the chart draws, and whether it was clipped.
     *
     * From the value's oldest evidence — the earliest occurrence date or
     * the earliest report, whichever is older, since a report can
     * predate the attribute row that now carries the value — to today.
     * Bounded by `ValueRelevanceTool::SPAN_CAP_DAYS`, and `clipped` says
     * so when it was, because a cap is not a permission.
     *
     * The oldest occurrence date arrives as one number from
     * `Value::occurrenceSummaryFor` rather than being scanned out of a
     * row set. It has to be the oldest of *every* occurrence — the
     * chart's span is a claim about the value, not about whichever
     * occurrences the overlay happens to read.
     *
     * @param array $summary From `Value::occurrenceSummaryFor`
     * @param array $rows Rows as `Sighting::listSightings` returns
     * @param string $today `Y-m-d`
     * @return array|null `from`, `to`, `first`, `clipped`
     */
    public static function sightingSpan(array $summary, array $rows,
        $today
    ) {
        $oldest = empty($summary['oldest'])
            ? null
            : date('Y-m-d', $summary['oldest']);
        foreach ($rows as $row) {
            $day = date('Y-m-d', (int)$row['Sighting']['date_sighting']);
            if ($oldest === null || $day < $oldest) {
                $oldest = $day;
            }
        }
        if ($oldest === null) {
            return null;
        }
        if ($oldest > $today) {
            // An occurrence whose timestamp is in the future of the
            // clock this page is drawn against. One day of span rather
            // than a negative one.
            $oldest = $today;
        }
        $floor = date(
            'Y-m-d',
            strtotime($today) - (ValueRelevanceTool::SPAN_CAP_DAYS - 1) * 86400
        );
        return array(
            'from' => max($oldest, $floor),
            'to' => $today,
            'first' => $oldest,
            'clipped' => $oldest < $floor,
        );
    }

    /**
     * The chart's payload: the reports as daily tallies per series, the
     * grain plan the browser zooms through, and the presets.
     *
     * The shape is parallel sparse day tallies plus a `plan` of grains,
     * so a zoom step and a preset switch are the same arithmetic in the
     * browser rather than a re-fetch — and the whole span as daily
     * counts weighs less than three precomputed ranges would.
     *
     * Every series is positional, aligned with `orgs`, because Chart.js
     * wants one dataset per organisation and a stack order that does
     * not change between buckets.
     *
     * @param array $rows Rows as `Sighting::listSightings` returns
     * @param array $span From sightingSpan
     * @param array $totals From sightingTotals
     * @param array $curves The overlay series: `model`, `threshold`,
     *                      `points` — one entry, the TTL runway
     * @return array
     */
    public static function sightingSeries(array $rows, array $span,
        array $totals, array $curves
    ) {
        /*
         * One organisation list for all three kinds of report, ordered
         * as the Reporters card orders it: by every report the
         * organisation filed, of any type.
         *
         * Using the type-0 list, with false positives and expirations
         * pooled into two series of their own, would make a sighting
         * `ORG-A saw this` and a false positive nobody's. The rail
         * beside the chart counts a contradiction as participation
         * ("hiding a false positive here would make the most sceptical
         * organisation look like the quietest"), and the chart says the
         * same thing: three series per organisation, and an
         * organisation that has only ever contradicted the value has a
         * slot like any other.
         */
        $orgKeys = array_keys($totals['org_counts']);
        $at = array_flip($orgKeys);
        $slots = count($orgKeys);
        $perDay = array(
            'sighting' => array_fill(0, $slots, array()),
            'fp' => array_fill(0, $slots, array()),
            'expiration' => array_fill(0, $slots, array()),
        );
        foreach ($rows as $row) {
            $day = date('Y-m-d', (int)$row['Sighting']['date_sighting']);
            $type = (int)$row['Sighting']['type'];
            $kind = $type === 1
                ? 'fp'
                : ($type === 2 ? 'expiration' : 'sighting');
            $i = $at[self::sightingOrg($row)];
            $perDay[$kind][$i][$day] =
                ($perDay[$kind][$i][$day] ?? 0) + 1;
        }

        $plan = ValueIntelligenceBuckets::plan(
            $span['from'],
            $span['to'],
            ValueIntelligenceBuckets::$spanRule,
            ValueIntelligenceBuckets::END
        );
        /*
         * The last bucket of every grain is today, whichever grain is
         * drawn. A bucket that is not the last one keeps its own date,
         * which makes this a relabelling of the end rather than of now.
         *
         * One word rather than a write into every grain's label array,
         * because the day grain has none — its labels are derived in
         * the browser (`ValueIntelligenceBuckets::plan`), and a translated
         * string is the one thing that cannot be. So the substitution
         * moves to the side that holds the labels.
         */
        $plan['last_label'] = __('today');

        /*
         * Sparse rather than dense: these are three series per
         * organisation over a span that can be three years, and each is
         * nearly all zero — two of the three usually entirely so.
         * `ValueIntelligenceBuckets::sparse` documents the measurement
         * behind the choice, and it is what keeps three series per
         * organisation from costing three times two.
         */
        $daily = array(
            'sighting' => array(),
            'fp' => array(),
            'expiration' => array(),
        );
        foreach ($perDay as $kind => $series) {
            foreach ($series as $i => $byDay) {
                $daily[$kind][$i] = ValueIntelligenceBuckets::sparse(
                    $span['from'],
                    $span['to'],
                    $byDay
                );
            }
        }

        return array(
            'today' => $span['to'],
            // Where the chart starts, and where the value does. They
            // differ exactly when the span cap bit, which is the only
            // thing that makes the clip notice sayable.
            'from' => $span['from'],
            'first' => $span['first'],
            'clipped' => $span['clipped'],
            'orgs' => $orgKeys,
            // Name => every report it filed, of any type. The same map
            // the Reporters card ranks, and the same order the stack
            // is drawn in.
            'org_counts' => $totals['org_counts'],
            'totals' => array(
                'total' => $totals['total'],
                'sighting' => $totals['sighting'],
                'fp' => $totals['fp'],
                'expiration' => $totals['expiration'],
            ),
            'plan' => $plan,
            'daily' => $daily,
            'curves' => $curves,
            'spans' => self::sightingSpans($span, $daily, $rows),
            'default_span' => self::defaultSpan($span, $rows),
        );
    }

    /**
     * The presets, derived rather than listed.
     *
     * 90 always; 365 only for a span wider than it, because a control
     * that draws the same chart as the one beside it behind a different
     * label is worse than one that is absent; all time always.
     *
     * @param array $span From sightingSpan
     * @param array $daily From sightingSeries
     * @param array $rows Rows as `Sighting::listSightings` returns
     * @return array
     */
    private static function sightingSpans(array $span, array $daily,
        array $rows
    ) {
        $days = 1 + (int)round(
            (strtotime($span['to']) - strtotime($span['from'])) / 86400
        );
        $windows = array(90);
        if ($days > 365) {
            $windows[] = 365;
        }
        $windows[] = null;
        $spans = array();
        foreach ($windows as $window) {
            $from = $window === null
                ? $span['from']
                : date(
                    'Y-m-d',
                    strtotime($span['to']) - ($window - 1) * 86400
                );
            if ($from < $span['from']) {
                $from = $span['from'];
            }
            $spans[] = array(
                'key' => $window === null ? 'all' : (string)$window,
                'label' => $window === null
                    ? ($span['clipped']
                        ? sprintf(
                            __('All charted · from %s'),
                            $span['from']
                        )
                        : sprintf(__('All time · from %s'), $span['from']))
                    : sprintf(__('Last %s days'), $window),
                'days' => $window,
                'from' => $from,
                'to' => $span['to'],
            );
        }
        return $spans;
    }

    /**
     * The narrowest preset that holds every report.
     *
     * A sparse value opening on 90 days is a nearly empty chart, and the
     * reader would have to discover the control to learn that it is not
     * the whole truth.
     *
     * @param array $span From sightingSpan
     * @param array $rows Rows as `Sighting::listSightings` returns
     * @return string
     */
    private static function defaultSpan(array $span, array $rows)
    {
        $oldest = null;
        foreach ($rows as $row) {
            $day = date('Y-m-d', (int)$row['Sighting']['date_sighting']);
            if ($oldest === null || $day < $oldest) {
                $oldest = $day;
            }
        }
        if ($oldest === null) {
            return 'all';
        }
        $days = 1 + (int)round(
            (strtotime($span['to']) - strtotime($span['from'])) / 86400
        );
        foreach (array(90, 365) as $window) {
            if ($window === 365 && $days <= 365) {
                continue;
            }
            $from = date(
                'Y-m-d',
                strtotime($span['to']) - ($window - 1) * 86400
            );
            if ($oldest >= $from) {
                return (string)$window;
            }
        }
        return 'all';
    }

    /**
     * The two sentences the tab must not omit, derived per value.
     *
     * The first is the whole argument for the overlay: a contradiction
     * is drawn on the axis and moves no line. It names the value's own
     * last false positive, so a reader can find the bar it is talking
     * about.
     *
     * @param array $totals From sightingTotals
     * @return array
     */
    public static function sightingNotes(array $totals)
    {
        if ($totals['fp'] > 0) {
            $fp = sprintf(
                __n(
                    'The false positive on %1$s leaves the runway flat.'
                        . ' The relevance clock counts type-0 reports'
                        . ' only, so a contradiction is visible on the'
                        . ' axis and extends nothing.',
                    'The %2$s false positives, the last of them on %1$s,'
                        . ' leave the runway flat. The relevance clock'
                        . ' counts type-0 reports only, so a'
                        . ' contradiction is visible on the axis and'
                        . ' extends nothing.',
                    $totals['fp']
                ),
                date('Y-m-d', $totals['last_fp_stamp']),
                $totals['fp']
            );
        } else {
            $fp = __(
                'Nobody has contradicted this value. A false positive'
                . ' would be drawn on this axis and would extend'
                . ' nothing — the relevance clock counts type-0 reports'
                . ' only.'
            );
        }
        return array(
            'fp_moves_nothing' => $fp,
            /*
             * Count-neutral, because two panels print it and only one
             * of them shows a count: *this count is yours* on the
             * relevance card would sit beside no count at all.
             */
            'policy' => __(
                'Sightings you can see. This instance hides sightings'
                . ' that other organisations reported on events your'
                . ' organisation does not own.'
            ),
        );
    }

    /**
     * How long ago, in the words the panel sub-line uses.
     *
     * @param int|null $stamp
     * @param int $now
     * @return string
     */
    public static function agoPhrase($stamp, $now)
    {
        if ($stamp === null) {
            return __('never');
        }
        $days = (int)floor(
            (strtotime(date('Y-m-d', $now)) - strtotime(date('Y-m-d', $stamp)))
            / 86400
        );
        if ($days <= 0) {
            return __('today');
        }
        if ($days === 1) {
            return __('yesterday');
        }
        if ($days < 31) {
            return sprintf(__('%s days ago'), $days);
        }
        return date('Y-m-d', $stamp);
    }

    /**
     * The organisation a report is filed under.
     *
     * `Sighting::listSightings` blanks the name and zeroes `org_id` for
     * a foreign report when `Plugin.Sightings_anonymise` is on. All of
     * them collapse to one key, because one key per hidden organisation
     * would put the number of them in the legend.
     *
     * @param array $row One `Sighting::listSightings` row
     * @return string
     */
    private static function sightingOrg(array $row)
    {
        return self::sightingHasOrg($row)
            ? $row['Organisation']['name']
            : __('Others');
    }

    /**
     * Whether the row names an organisation at all.
     *
     * One predicate rather than the same two-part guard written twice,
     * because the label and the link have to agree: a report pooled
     * under `Others` must not carry a link to whichever organisation
     * `Sighting.org_id` still happens to hold.
     *
     * @param array $row One `Sighting::listSightings` row
     * @return bool
     */
    private static function sightingHasOrg(array $row)
    {
        return ($row['Organisation']['name'] ?? '') !== ''
            && !empty($row['Sighting']['org_id']);
    }

    /**
     * `MispAttribute::afterFind` hands these back as ISO strings, and a
     * value that predates the seen columns hands back nothing.
     *
     * @param string|null $value
     * @return int|null Unix timestamp
     */
    private static function stamp($value)
    {
        if (empty($value)) {
            return null;
        }
        $stamp = strtotime($value);
        return $stamp === false ? null : $stamp;
    }

    /**
     * The sighting facts a ledger row quotes, beside the ones
     * `sightingTotals` already counts.
     *
     * Organisation spread, recency and who filed the false positives —
     * the three things `sightings.volume_recency` and
     * `sightings.false_positive` say in prose and that the totals do
     * not carry. Folded here rather than in the signals, so that two
     * implementations reading the same rows cannot disagree about what
     * *recent* meant.
     *
     * **Anonymised reports count and are not named.** `listSightings`
     * has already applied the instance's sighting policy, so a row with
     * no organisation is one this reader may count but not attribute;
     * it joins the spread under one *Others* key — one key rather than
     * one per hidden org, for the reason `sightingTotals` gives — and
     * never reaches an evidence line.
     *
     * @param array $rows Rows as `Sighting::listSightings` returns
     * @param int $now
     * @param int $recentDays What the row calls recent
     * @return array
     */
    public static function sightingSignals(array $rows, $now,
        $recentDays
    ) {
        $cut = (int)$now - (int)$recentDays * 86400;
        $orgs = array();
        $fpOrgs = array();
        $recent = 0;
        $first = null;
        foreach ($rows as $row) {
            $at = (int)$row['Sighting']['date_sighting'];
            $named = self::sightingHasOrg($row);
            $name = $named ? $row['Organisation']['name'] : null;
            $orgs[$named ? $name : '_others'] = true;
            if ($at >= $cut) {
                $recent++;
            }
            if ($first === null || $at < $first) {
                $first = $at;
            }
            if ((int)$row['Sighting']['type'] === 1) {
                $fpOrgs[$named ? $name : '_others'] = $named;
            }
        }
        $fpNames = array();
        foreach ($fpOrgs as $name => $named) {
            if ($named) {
                $fpNames[] = $name;
            }
        }
        return array(
            'orgs' => count($orgs),
            'fp_orgs' => count($fpOrgs),
            'fp_org_names' => $fpNames,
            'recent' => $recent,
            'recent_days' => (int)$recentDays,
            'first_stamp' => $first,
        );
    }

    /**
     * The composition card's segments, from the ledger the accumulator
     * just built.
     *
     * The rule: group the fired rows by kind, sum the **positives** into
     * a segment per group, and collect every **negative** across all
     * groups into one final segment. So `Reporting 37, Sightings 24,
     * Attribution 19, Lifecycle 18, Signals against -14` sums to 84 —
     * the ledger's own total, by a second route that cannot disagree
     * with it.
     *
     * **One collected negative rather than a hatched deduction per
     * group**: the segment is the downward signals, collected, and
     * explicitly not the contradictions, since labelling the line after
     * those would send a reader tracing -14 to the wrong rows.
     *
     * @param array $ledger Grouped rows, as `ValueVerdictTool` emits
     * @return array Segments of `label`, `points`, `colour`
     */
    public static function verdictComposition(array $ledger)
    {
        $segments = array();
        $against = 0;
        foreach ($ledger as $group) {
            $earned = 0;
            foreach ($group['signals'] as $signal) {
                $points = (int)$signal['contribution'];
                if ($points < 0) {
                    $against += $points;
                } else {
                    $earned += $points;
                }
            }
            if ($earned > 0) {
                $segments[] = array(
                    'label' => $group['kind'],
                    'points' => $earned,
                    'colour' => self::compositionColour($group['kind']),
                );
            }
        }
        if ($against < 0) {
            $segments[] = array(
                'label' => __('Signals against'),
                'points' => $against,
                'colour' => 'var(--bs-danger)',
            );
        }
        return $segments;
    }

    /**
     * The colour token a ledger group is drawn in — the page's own
     * per-domain variables, so a segment matches the tab its evidence
     * came from rather than a palette invented for this card.
     *
     * @param string $kind
     * @return string A CSS variable reference, never a raw hex
     */
    private static function compositionColour($kind)
    {
        switch ($kind) {
            case 'Reporting':
                return 'var(--event)';
            case 'Sightings':
                return 'var(--sighting)';
            case 'Attribution':
                return 'var(--galaxy)';
            case 'Lifecycle':
                return 'var(--correlation)';
        }
        return 'var(--vp-unknown)';
    }
}
