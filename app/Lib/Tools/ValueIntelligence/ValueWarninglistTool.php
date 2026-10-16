<?php

/**
 * Which of a set of values MISP already knows to be benign.
 *
 * The page's **one** warninglist read. The frame's *Warninglist hit*
 * chip and the verdict card's band belong on this rather than on a
 * second regime, which would let the frame and a panel disagree about
 * the same value.
 *
 * **It is the event view's check, not a re-implementation.**
 * `Warninglist::attachWarninglistToAttributes` is the batched,
 * Redis-backed path core already uses on every event page: one `mget`
 * over `misp:wlc:<md5(type:value)>` keys for the whole set, the misses
 * computed and written back. The cache is keyed on the pair alone, so
 * an event view that has already checked `1.1.1.1` warms this lookup
 * and this lookup warms the next event view.
 *
 * **`to_ids` is deliberately not consulted.** Core gates that check on
 * `to_ids || MISP.warning_for_all`, because there it is asking *should
 * this attribute have been exported*. Here the question is *is this
 * value known-benign infrastructure*, which is a property of the value
 * and not of one occurrence's export flag — and a co-occurrence row
 * folds many occurrences that need not agree on it. The probes below
 * are therefore throwaway lookup keys carrying `to_ids`, not records:
 * nothing stored is being described, and nothing is written back.
 *
 * Model-injected and takes no `$user`. None is needed and none would
 * mean anything: which lists are enabled is instance state, identical
 * for every viewer, and the caller has already scoped the values it
 * asks about.
 *
 * The fixed cost — `getEnabled` plus building the entry sets, most of
 * it the CIDR lists — is what dominates, and the marginal cost of one
 * more value is small. That is what makes checking the whole fold
 * rather than only the displayed page affordable, and it is why the
 * facet counts below can be exact.
 */
class ValueWarninglistTool
{
    /**
     * Every list each value is on, keyed by value.
     *
     * A value is reported under **any** type it appeared as, which is
     * the rule the type facet already uses — `ValueRelationTool`'s row
     * builder gives a value one badge, its `dominant()` type, but
     * counts it under each. Classifying from the dominant type alone
     * would let a `sha1` seen once as `md5` escape the empty-file list
     * it is on.
     *
     * **One SQL query, and only where something matched and the caller
     * wants the comments.** The check itself is Redis; `assignComments`
     * is the query. Only the relation panels draw a comment, so the
     * banner and the assessment skip it.
     *
     * @param Warninglist $warninglist
     * @param array $pairs `value` and `type`, duplicates welcome
     * @param bool $withComments Fetch each matched entry's comment
     * @return array value => list of id, name, category, matched,
     *               comment (null when not fetched)
     */
    public static function hitsFor($warninglist, array $pairs,
        $withComments = true
    ) {
        $probes = array();
        $seen = array();
        foreach ($pairs as $pair) {
            $value = isset($pair['value']) ? (string)$pair['value'] : '';
            $type = isset($pair['type']) ? (string)$pair['type'] : '';
            if ($value === '' || $type === '') {
                continue;
            }
            $key = $type . ':' . $value;
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $probes[] = array(
                'value' => $value,
                'type' => $type,
                'to_ids' => 1,
            );
        }
        if (empty($probes)) {
            return array();
        }

        $warninglist->attachWarninglistToAttributes($probes, $withComments);

        /*
         * **Two fields core does not hand back.** A match carries the
         * list's id, name and category and nothing else, but the band
         * on the verdict tab names the version it matched against and
         * says *how* it matched — `cidr`, `substring`, `regex` — and
         * both are columns on the row the matcher already had in hand.
         * Read back from the enabled roster rather than by id, because
         * the roster is the set the match came out of and the read is
         * the same one `enabledCount()` makes.
         */
        $roster = self::rosterFrom($warninglist);

        $hits = array();
        foreach ($probes as $probe) {
            if (empty($probe['warnings'])) {
                continue;
            }
            $value = $probe['value'];
            if (!isset($hits[$value])) {
                $hits[$value] = array();
            }
            foreach ($probe['warnings'] as $warning) {
                $id = (int)$warning['warninglist_id'];
                if (isset($hits[$value][$id])) {
                    continue;
                }
                $hits[$value][$id] = array(
                    'id' => $id,
                    'name' => $warning['warninglist_name'],
                    'category' => $warning['warninglist_category'],
                    /*
                     * The list entry that matched, which is not the
                     * value: `10.0.5.23` matches `10.0.0.0/8`, and a
                     * tooltip naming only the list leaves the reader
                     * to guess why.
                     */
                    'matched' => $warning['match'],
                    // The entry's own note, where the list's curator left one.
                    'comment' => isset($warning['comment'])
                        ? $warning['comment']
                        : null,
                    'type' => isset($roster[$id]['type'])
                        ? $roster[$id]['type']
                        : null,
                    // Filled below; the roster cannot answer it.
                    'version' => null,
                );
            }
        }
        $versions = self::versionsFor($warninglist, $hits);
        foreach ($hits as $value => $lists) {
            usort($lists, function ($a, $b) {
                return strcasecmp($a['name'], $b['name']);
            });
            foreach ($lists as $i => $hit) {
                $lists[$i]['version'] = isset($versions[$hit['id']])
                    ? $versions[$hit['id']]
                    : null;
            }
            $hits[$value] = $lists;
        }
        return $hits;
    }

    /**
     * How many lists a miss was checked against.
     *
     * A miss is only informative beside this number — it is why the
     * fact strip prints *"84 lists checked"* under *"No warninglist
     * hit"*.
     *
     * @param Warninglist $warninglist
     * @return int
     */
    public static function enabledCount($warninglist)
    {
        return count($warninglist->getEnabled());
    }

    /**
     * The enabled lists, keyed by id, with the two fields a match does
     * not carry.
     *
     * `getEnabled()` is MISP's own cached read and `enabledCount()`
     * above already makes it a second time, so this adds a lookup
     * rather than a query. The shape it returns is
     * `[['Warninglist' => [...], 'types' => [...]], …]`, which
     * `Warninglist::attachWarninglistToAttributes` reads the same way.
     *
     * @param object $warninglist The Warninglist model
     * @return array id => `type`, `name`
     */
    public static function rosterFrom($warninglist)
    {
        $roster = array();
        foreach ($warninglist->getEnabled() as $row) {
            if (empty($row['Warninglist']['id'])) {
                continue;
            }
            $list = $row['Warninglist'];
            $roster[(int)$list['id']] = array(
                /*
                 * How the list matches, in MISP's own vocabulary. Not
                 * the attribute type and not the category — the column
                 * is `warninglists.type` and it holds `cidr`, `string`,
                 * `substring` or `regex`.
                 */
                'type' => isset($list['type']) ? $list['type'] : null,
                'name' => isset($list['name']) ? $list['name'] : null,
            );
        }
        return $roster;
    }

    /**
     * The matched lists' versions, which the enabled roster does not
     * carry.
     *
     * **One query, and only where something matched.**
     * `getEnabledAndCacheWarninglist()` selects `id, name, type,
     * category` and serialises that into redis, so `version` is not in
     * the cached shape and widening core's field list to serve one band
     * would change what every caller of `getEnabled()` deserialises. A
     * keyed read on the matched ids is the smaller change: most values
     * hit no list at all and pay nothing, and a value that hit one is
     * already paying for `assignComments`.
     *
     * The version is worth the read because it is what the match was
     * made against — *v20250802* dates the claim, and a band naming a
     * list with no version invites the reader to assume it is current.
     *
     * @param object $warninglist The Warninglist model
     * @param array $hits value => list of hits, each with an `id`
     * @return array id => version
     */
    private static function versionsFor($warninglist, array $hits)
    {
        $ids = array();
        foreach ($hits as $lists) {
            foreach ($lists as $hit) {
                $ids[(int)$hit['id']] = true;
            }
        }
        if (empty($ids)) {
            return array();
        }
        $rows = $warninglist->find('all', array(
            'recursive' => -1,
            'fields' => array('Warninglist.id', 'Warninglist.version'),
            'conditions' => array('Warninglist.id' => array_keys($ids)),
        ));
        $versions = array();
        foreach ($rows as $row) {
            $versions[(int)$row['Warninglist']['id']] =
                $row['Warninglist']['version'];
        }
        return $versions;
    }
}
