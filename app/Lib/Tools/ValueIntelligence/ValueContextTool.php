<?php
App::uses('GalaxyCategory', 'Tools');

/**
 * What the community has labelled this value, folded for the Overview.
 *
 * The one Overview panel whose shape is produced nowhere else on the
 * page, and the reason it is not a flat tag list is that a taxonomy is
 * the unit that can disagree with itself: two events putting
 * `tlp:amber` and `tlp:green` on one value is a fact about the value,
 * and a flat list hides it.
 *
 * **Three rulings are MISP's and not this tool's**, which is the whole
 * design:
 *
 * - **What counts as a conflict** is `Taxonomy::getTagConflicts` —
 *   an exclusive taxonomy carrying two predicates, or an exclusive
 *   predicate carrying two entries. It also knows that `tlp:white` and
 *   `tlp:clear` are one colour under two spellings rather than a
 *   contradiction, which is exactly the special case a rule invented
 *   here would have got wrong.
 * - **Where a tag sits on a scale** is the taxonomy's own
 *   `numerical_value`, read from the entries rather than assumed from
 *   the order they were imported in.
 * - **Whether a galaxy cluster may be named** is
 *   `GalaxyCluster::fetchGalaxyClusters`. A galaxy tag on a row this
 *   viewer may read is not permission to name the cluster behind it.
 *
 * **What reaches it is already capped.** `Value::topTagsFor` returns
 * the most-carried labels and no more, because a value like `443` can
 * carry thousands of distinct tags; the `capped` flag is how this tool
 * knows not to read a position off a list that stops.
 *
 * **No `$user`**: everything reaching this has been scoped already,
 * and a folding tool that could re-scope is one that can get the scope
 * wrong somewhere the ACL is not being reviewed.
 */
class ValueContextTool
{
    /**
     * The group every tag that is not a machine tag falls into.
     *
     * Not a namespace, and deliberately not empty string: it is a key
     * no namespace can collide with, and the card heads the group with
     * words rather than with it.
     */
    const FREETEXT = "\0freetext";

    /**
     * The taxonomy groups, in the shape `value_context` reads.
     *
     * Ordered by occurrence count, most-carried taxonomy first, so the
     * label an analyst is most likely to care about is not below the
     * fold of a card that does not scroll.
     *
     * @param array $tags `ValueIntelligence::mergeTagScopes`' output —
     *     `tag`, a `count` to sort by, and the per-scope
     *     `occurrences`/`events` behind it; galaxies included
     * @param array $taxonomies `namespace` => the fold below
     * @param array $conflicted Tag names MISP reports as conflicting
     * @param bool $capped Whether more labels exist than were read
     * @return array
     */
    public static function taxonomies(array $tags, array $taxonomies,
        array $conflicted, $capped = false
    ) {
        $groups = array();
        foreach ($tags as $name => $row) {
            if (!empty($row['tag']['is_galaxy'])) {
                continue;
            }
            $parts = self::split($name);
            /*
             * **Freetext tags share one group rather than each becoming
             * a taxonomy of one.** A value carrying `asyncrat`, `c2`,
             * `Gh0stRAT`, `historicalandnew` and
             * `mightcontainvariantsofasyncrat` has five tags in no
             * namespace at all, which as five headed groups would push
             * the real taxonomies off the card and imply a structure
             * none of them has.
             *
             * **And a namespace is matched case-insensitively**, which
             * is not a nicety: a tag may read `PAP:RED` while the
             * taxonomy is stored as `pap`, MISP's columns
             * collate `utf8mb3_bin`, and `Taxonomy::getTaxonomyForTag`
             * accordingly compares `LOWER()` on both sides. Keyed by
             * the raw spelling, `PAP:RED` and `pap:amber` would head
             * two groups and neither would find its taxonomy.
             */
            $namespace = $parts === null
                ? self::FREETEXT
                : mb_strtolower($parts['namespace']);
            if (!isset($groups[$namespace])) {
                $groups[$namespace] = array(
                    'taxonomy' => $namespace === self::FREETEXT
                        ? __('Not in a taxonomy')
                        : $namespace,
                    'conflict' => false,
                    'tags' => array(),
                    'total' => 0,
                );
                /*
                 * What a profile's priority lists name this group by
                 * (`ValueLabelPriority`), and it is deliberately
                 * absent on the freetext group: *not in a taxonomy* is
                 * not a dimension anybody can pin, prefer or demote,
                 * and a group with no key is unlisted by definition.
                 */
                if ($namespace !== self::FREETEXT) {
                    $groups[$namespace]['key'] = $namespace;
                }
            }
            $groups[$namespace]['tags'][] = array(
                'id' => $row['tag']['id'],
                'name' => $name,
                'colour' => $row['tag']['colour'],
                'count' => $row['count'],
                /*
                 * The two scopes' own counts, carried rather than
                 * summed. `count` above is a sort weight and nothing
                 * else: a tag on 2 occurrences and 8 events is not on
                 * 10 of anything, so the card prints these two facts
                 * where each can name its own unit and prints no
                 * number beside the chip.
                 */
                'occurrences' => isset($row['occurrences'])
                    ? $row['occurrences']
                    : null,
                'events' => isset($row['events'])
                    ? $row['events']
                    : null,
                'local' => !empty($row['tag']['local']),
            );
            $groups[$namespace]['total'] += $row['count'];
            if (isset($conflicted[$name])) {
                $groups[$namespace]['conflict'] = true;
            }
        }

        foreach ($groups as $namespace => $group) {
            usort($group['tags'], function ($a, $b) {
                if ($a['count'] === $b['count']) {
                    return strcmp($a['name'], $b['name']);
                }
                return $b['count'] - $a['count'];
            });
            $group['tags'] = array_values($group['tags']);
            /*
             * **No scale once the cap has bitten.** A position is only
             * a position because exactly one tag of that dimension is
             * present, and a truncated list cannot tell *one* from
             * *one that was read*. Drawing a bar there would state a
             * reading the record may contradict two rows below the cut.
             */
            $scale = $capped ? null : self::scaleFor(
                $group['tags'],
                isset($taxonomies[$namespace])
                    ? $taxonomies[$namespace]
                    : null
            );
            if ($scale !== null) {
                $group['scale'] = $scale;
            }
            unset($group['total']);
            $groups[$namespace] = $group;
        }

        uasort($groups, function ($a, $b) {
            return count($b['tags']) - count($a['tags']);
        });
        return array_values($groups);
    }

    /**
     * Where this group's tag sits on its taxonomy's own scale, if it has
     * one and if exactly one tag of it is present.
     *
     * **Exactly one**, because a position is a reading of a single
     * value. Two tags from one ordinal dimension is not a position
     * further along the scale, it is a contradiction — and the group is
     * already marked `conflict` for it, which is the honest rendering.
     *
     * Two levels, because a machine tag can put its reading in either
     * component: `admiralty-scale:source-reliability="b"` is an entry
     * under a predicate, and `tlp:amber` is a predicate under a
     * namespace. Both tables carry `numerical_value`, so the same fold
     * works on each — what changes is which list supplies the
     * denominator.
     *
     * @param array $tags This group's tags
     * @param array|null $taxonomy The namespace's predicates and entries
     * @return array|null
     */
    private static function scaleFor(array $tags, $taxonomy)
    {
        if ($taxonomy === null || count($tags) !== 1) {
            return null;
        }
        $parts = self::split($tags[0]['name']);
        if ($parts === null) {
            return null;
        }
        // Lowercased on both sides, as `getTaxonomyForTag` does it: the
        // fold is keyed that way and a tag carries whatever case the
        // analyst typed.
        $predicateKey = mb_strtolower($parts['predicate']);
        $predicate = isset($taxonomy['predicates'][$predicateKey])
            ? $taxonomy['predicates'][$predicateKey]
            : null;
        if (isset($parts['value'])) {
            if ($predicate === null || empty($predicate['entries'])) {
                return null;
            }
            return self::position(
                $predicate['entries'],
                mb_strtolower($parts['value']),
                empty($predicate['expanded'])
                    ? $parts['predicate']
                    : $predicate['expanded']
            );
        }
        if (empty($taxonomy['predicates'])) {
            return null;
        }
        return self::position(
            $taxonomy['predicates'],
            $predicateKey,
            mb_strtolower($parts['namespace'])
        );
    }

    /**
     * One tag's place in an ordered list of the values it could take.
     *
     * Returns nothing where the list carries no numbers — an ordinal
     * rendering of an unordered set invents a ranking, and `type:OSINT`
     * is not `1 of 14`. The test is that *every* member has a
     * `numerical_value`: a partly-numbered taxonomy sorts the rest to
     * one end, and a position read off that is meaningless in a way the
     * bar would hide.
     *
     * @param array $members value => `expanded`, `numerical`
     * @param string $value The value in play
     * @param string $label What to call the dimension
     * @return array|null
     */
    private static function position(array $members, $value, $label)
    {
        if (!isset($members[$value])) {
            return null;
        }
        $ordered = array();
        foreach ($members as $key => $member) {
            if ($member['numerical'] === null) {
                return null;
            }
            $ordered[$key] = $member;
        }
        /*
         * **Descending, so position 1 is the top of the scale.** The
         * taxonomy's numbers run the other way — `admiralty-scale`
         * gives *Confirmed by other sources* 100 and *Improbable* 0 —
         * and a bar filling up as a source gets less reliable reads as
         * the opposite of what it says. Two entries may tie (`c` and
         * `f` are both 50, `e` and `g` both 0), and PHP 8's sort is
         * stable, so a tie keeps the taxonomy's own order.
         *
         * The denominator is what the taxonomy actually holds rather
         * than what a reader assumes: `source-reliability` has **seven**
         * grades, which is the count the profile's trust map in
         * `ValueTrustTool` uses for the same reason.
         */
        uasort($ordered, function ($a, $b) {
            return $b['numerical'] - $a['numerical'];
        });
        /*
         * **Compared as strings, because PHP's array keys are not.**
         * `admiralty-scale:information-credibility` is keyed `1` to
         * `6`, and PHP casts a numeric-string key to an integer on the
         * way in — so `array_search('2', [5,4,3,6,2,1], true)` is
         * `false`, `false + 1` is `1`, and every numerically-keyed
         * taxonomy would render as *position 1* however it was tagged —
         * *2 — Probably true* drawn as *1 of 6*.
         */
        $keys = array_map('strval', array_keys($ordered));
        $at = array_search((string)$value, $keys, true);
        if ($at === false) {
            return null;
        }
        $position = $at + 1;
        $expanded = $members[$value]['expanded'];
        return array(
            'label' => $label,
            'position' => $position,
            'of' => count($ordered),
            'reading' => $expanded === null || $expanded === ''
                ? $value
                : sprintf('%s — %s', $value, $expanded),
        );
    }

    /**
     * The galaxy clusters, named only where the viewer may know them,
     * **grouped under the galaxy they belong to**.
     *
     * A galaxy tag reaches this with `is_galaxy` set and nothing else:
     * `Value::ownTagsFor` says in its own docblock that the tag is
     * worthless until `fetchGalaxyClusters` rules on it and that the
     * ruling belongs to the caller. So a tag with no cluster row is
     * **absent**, with nothing drawn in its place and no count of how
     * many were withheld — the page does not tell a reader that records
     * exist which it will not show them.
     *
     * **Grouped, because a cluster's galaxy is the thing it is a
     * member of.** Flat, the card would put *Cobalt Strike* (a tool),
     * *APT29* (a threat actor) and four ATT&CK techniques in one run,
     * each chip repeating its own kind in small print — a list sorted
     * by a number with the structure spelled out chip by chip. The
     * galaxy is what the clusters have in common, so it heads them, and
     * the kind is said once per group rather than once per cluster.
     *
     * The group is keyed on the galaxy's own `name` —
     * `fetchGalaxyClusters` contains `Galaxy` and then `arrangeData`
     * moves it *inside* the `GalaxyCluster` array, which is where this
     * reads it from. A cluster whose galaxy row did not come back falls
     * back to the cluster's own `type` — the same fallback the kind
     * uses, and for the same reason: the raw type is what the
     * cluster actually belongs to, only not spelled the way the
     * instance spells it.
     *
     * @param array $tags `ValueIntelligence::mergeTagScopes`' output
     * @param array $clusters Tag name => a `fetchGalaxyClusters` row
     * @return array One entry per galaxy: `galaxy`, `sub_category`,
     *     `clusters`
     */
    public static function galaxies(array $tags, array $clusters)
    {
        $galaxies = array();
        foreach ($tags as $name => $row) {
            if (empty($row['tag']['is_galaxy'])) {
                continue;
            }
            if (!isset($clusters[$name])) {
                continue;
            }
            $cluster = $clusters[$name]['GalaxyCluster'];
            $galaxy = empty($cluster['Galaxy']['name'])
                ? $cluster['type']
                : $cluster['Galaxy']['name'];
            if (!isset($galaxies[$galaxy])) {
                $galaxies[$galaxy] = array(
                    'galaxy' => $galaxy,
                    /*
                     * The galaxy's `type` rather than its name, because
                     * that is the string a profile's priority lists
                     * hold and the one inside every tag — the name is
                     * how this instance spells it.
                     */
                    'key' => $cluster['type'],
                    /*
                     * `subCategoryOf` answers null for an unclassified
                     * galaxy; the raw galaxy type is then better than a
                     * blank heading.
                     */
                    'sub_category' => GalaxyCategory::subCategoryOf(
                        $cluster['type']
                    ) ?? $cluster['type'],
                    'clusters' => array(),
                );
            }
            $galaxies[$galaxy]['clusters'][] = array(
                'id' => isset($cluster['id']) ? (int)$cluster['id'] : null,
                'name' => empty($cluster['value'])
                    ? $name
                    : $cluster['value'],
                'count' => $row['count'],
                'occurrences' => isset($row['occurrences'])
                    ? $row['occurrences']
                    : null,
                'events' => isset($row['events'])
                    ? $row['events']
                    : null,
            );
        }
        $byCount = function ($a, $b) {
            if ($a['count'] === $b['count']) {
                return strcmp($a['name'], $b['name']);
            }
            return $b['count'] - $a['count'];
        };
        foreach ($galaxies as $galaxy => $group) {
            usort($group['clusters'], $byCount);
            $galaxies[$galaxy]['clusters'] = $group['clusters'];
        }
        /*
         * Galaxies by their most-carried cluster, so the one whose
         * clusters are attributed most widely heads the card — the
         * order a flat list would have, only taken a level up.
         */
        uasort($galaxies, function ($a, $b) {
            $left = $a['clusters'][0]['count'];
            $right = $b['clusters'][0]['count'];
            if ($left === $right) {
                return strcmp($a['galaxy'], $b['galaxy']);
            }
            return $right - $left;
        });
        return array_values($galaxies);
    }

    /**
     * `Taxonomy::splitTagToComponents` without the model.
     *
     * The regex is copied rather than reached for because this tool
     * takes no models at all and one that took `Taxonomy` only to split
     * a string would be a model dependency for a `preg_match`. The
     * pattern is the seam: if MISP's machine-tag grammar changes, both
     * change, and the page's own tests are what catch it.
     *
     * @param string $tag
     * @return array|null Null when the tag is not a machine tag
     */
    private static function split($tag)
    {
        if (!preg_match('/^([^:="]+):([^:="]+)(="([^"]+)")?$/i', $tag, $m)) {
            return null;
        }
        $parts = array('namespace' => $m[1], 'predicate' => $m[2]);
        if (isset($m[4])) {
            $parts['value'] = $m[4];
        }
        return $parts;
    }
}
