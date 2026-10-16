<?php

/**
 * Which labels a surface draws first, and which it draws even when the
 * value does not carry them.
 *
 * MISP ships 182 taxonomies and 130 galaxies, and to any consumer they
 * are one undifferentiated set in which `threat-actor` sits beside
 * `ukhsa-culture-collections`, `firearms` and `cancer`. Nothing in the
 * data says which of them this reader cares about, because that is not
 * a property of the data — it is a property of the job, and the profile
 * is where this page keeps those.
 *
 * So a profile declares three ordered lists per dimension and
 * everything unlisted keeps the order the surface already gave it:
 *
 *   pinned     always drawn, ahead of everything else, and the only
 *              tier whose *absence* is rendered
 *   preferred  sorted above anything unlisted
 *   demoted    sorted below anything unlisted
 *
 * **Sparse, not exhaustive.** No profile can rank 182 taxonomies and
 * one that tried would be wrong the next time misp-taxonomies ships a
 * release. A typical profile's three lists total about a dozen entries,
 * and `default-v1` declares none at all — which is why a profile that
 * declares nothing must return the groups untouched rather than
 * re-sorting them into the same order by a longer route.
 *
 * **There is no `hidden` tier, deliberately.** Hiding already exists
 * twice at instance level — `taxonomies.enabled = 0` and
 * `tags.hide_tag` — and a third mechanism at profile scope would mean
 * two people can make a label invisible and neither can see that the
 * other did. `demoted` pushes a taxonomy down; it never removes it. A
 * configuration that can make a `tlp:red` tag invisible to a reader
 * who has access to it is a way to mislead somebody about the value in
 * front of them.
 *
 * **Pure and static, and it takes no `$user`**: the caller has already
 * applied the ACL, as `GalaxyCategory` does today. It resolves nothing
 * and queries nothing — including the instance-enablement floor of
 * `absent()`, whose permitted set is read by the caller and passed in.
 */
class ValueLabelPriority
{
    /** Always drawn, and the only tier whose absence is rendered. */
    const PINNED = 'pinned';

    /** Sorted above anything unlisted. */
    const PREFERRED = 'preferred';

    /** Sorted below anything unlisted. */
    const DEMOTED = 'demoted';

    /**
     * The tiers in precedence order, which is also the order a key
     * listed twice is resolved in: a profile naming `tlp` as both
     * pinned and demoted meant the first of the two, and the editor
     * cannot stop a hand-written document saying it.
     */
    const TIERS = array(self::PINNED, self::PREFERRED, self::DEMOTED);

    /** The dimension keyed by taxonomy namespace. */
    const TAXONOMIES = 'taxonomies';

    /** The dimension keyed by galaxy `type`. */
    const GALAXIES = 'galaxies';

    /**
     * Where the editor starts warning about the pinned list's length.
     *
     * The tier is worth more than "first in the order" only because a
     * reader notices an absence drawn in a short list. A card listing
     * eight absences has taught them to skip that region of the page,
     * which costs exactly the attention the tier was created to buy.
     */
    const PIN_WARN_AT = 4;

    /**
     * The handling taxonomies, most restrictive first.
     *
     * These two are the taxonomies whose labels carry an order of
     * severity the page can know, and they are the reason a pinned
     * group is not simply rendered in count order. A value's context
     * tags come from every occurrence's event as well as from the
     * attributes, so a shared value with forty occurrences almost
     * always carries more than one `tlp` — and a reader who sees
     * `tlp:clear` in the pinned slot and misses `tlp:red` two chips
     * away has been misled in exactly the way the tier exists to
     * prevent.
     *
     * `clear` and `white` share a rank because they are one colour
     * under two spellings, which is the special case
     * `Taxonomy::getTagConflicts` already knows and a rule invented
     * here would have got wrong. A predicate absent from the table —
     * `tlp:unclear`, or whatever a later release adds — ranks last and
     * is counted with the rest rather than being allowed to win the
     * slot on a severity nobody has stated.
     *
     * Namespaces are keyed lowercase because that is how the groups
     * are keyed: MISP's columns collate `utf8mb3_bin` and the PAP
     * taxonomy ships its namespace and its predicates in capitals.
     */
    const HANDLING = array(
        'tlp' => array(
            'red' => 0,
            'amber+strict' => 1,
            'amber' => 2,
            'green' => 3,
            'clear' => 4,
            'white' => 4,
        ),
        'pap' => array(
            'red' => 0,
            'amber' => 1,
            'green' => 2,
            'clear' => 3,
            'white' => 3,
        ),
    );

    /** What the event marking block draws when a profile names nothing. */
    const DEFAULT_MARKINGS = array('tlp', 'pap');

    /**
     * The `context` section, whichever shape the profile arrived in.
     *
     * `ValueTrustTool::section()`'s twin, duplicated for the reason it
     * gives: this class is pure and a caller may hand over the
     * parameters alone.
     *
     * @param array|null $profile An `AnalystProfile` row, unwrapped, or
     *                            its `parameters`
     * @return array
     */
    public static function section($profile)
    {
        if (!is_array($profile)) {
            return array();
        }
        if (isset($profile['parameters']['context'])
            && is_array($profile['parameters']['context'])
        ) {
            return $profile['parameters']['context'];
        }
        if (isset($profile['context'])
            && is_array($profile['context'])
        ) {
            return $profile['context'];
        }
        return array();
    }

    /**
     * The three lists per dimension, normalised.
     *
     * Keys are lowercased and trimmed, empties dropped, each list
     * deduplicated, and a key claimed by two tiers kept by the first
     * of them in `TIERS` order. The declared order within a tier is
     * the order it is drawn in, so nothing is sorted here.
     *
     * A document written against a later vocabulary survives being
     * read by an older instance: an unrecognised dimension or tier is
     * dropped rather than refused, which is the rule for a whole
     * missing signal applied to one of its entries.
     *
     * @param array|null $profile A profile, its parameters, or a plan
     *                            this method already returned
     * @return array Dimension => tier => keys, in declared order
     */
    public static function planFor($profile)
    {
        if (self::isPlan($profile)) {
            return $profile;
        }
        $section = self::section($profile);
        $plan = array();
        foreach (array(self::TAXONOMIES, self::GALAXIES) as $scope) {
            $declared = isset($section[$scope])
                && is_array($section[$scope])
                ? $section[$scope]
                : array();
            $taken = array();
            foreach (self::TIERS as $tier) {
                $plan[$scope][$tier] = array();
                if (empty($declared[$tier])
                    || !is_array($declared[$tier])
                ) {
                    continue;
                }
                foreach ($declared[$tier] as $key) {
                    if (!is_string($key) && !is_numeric($key)) {
                        continue;
                    }
                    $key = mb_strtolower(trim((string)$key));
                    if ($key === '' || isset($taken[$key])) {
                        continue;
                    }
                    $taken[$key] = true;
                    $plan[$scope][$tier][] = $key;
                }
            }
        }
        return $plan;
    }

    /**
     * Whether this dimension has an opinion at all.
     *
     * The load-bearing question, and the reason it is asked before
     * anything is sorted: `default-v1` declares nothing, so on a stock
     * instance every surface must render exactly the order it was
     * given — not the same order arrived at by a comparator.
     *
     * @param array $plan
     * @param string|null $scope Null asks about either dimension
     * @return bool
     */
    public static function declares(array $plan, $scope = null)
    {
        $scopes = $scope === null
            ? array(self::TAXONOMIES, self::GALAXIES)
            : array($scope);
        foreach ($scopes as $one) {
            foreach (self::TIERS as $tier) {
                if (!empty($plan[$one][$tier])) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * The groups a surface assembled, in the order the profile asks
     * for, with each group marked by the tier that placed it.
     *
     * Every group must carry a `key` naming the dimension it belongs
     * to — the lowercased namespace for a taxonomy, the galaxy `type`
     * for a galaxy — because that is what a profile lists. A group
     * with no `key` is unlisted by definition and keeps its place,
     * which is what a surface that has not been taught to carry one
     * gets: its own order, not a wrong one.
     *
     * Ties keep the incoming order rather than relying on the sort
     * being stable, so the count order a surface arrived with survives
     * inside each tier.
     *
     * A pinned group from a handling taxonomy gains `lead`, which is
     * the most restrictive label present and a count of the others.
     * Nothing else is added to a group.
     *
     * @param array $groups Assembled groups, each carrying `key`
     * @param array|null $plan A plan, a profile, or its parameters
     * @param string $scope `taxonomies` or `galaxies`
     * @return array The same groups, ordered and marked
     */
    public static function order(array $groups, $plan, $scope)
    {
        $plan = self::planFor($plan);
        if (empty($groups) || !self::declares($plan, $scope)) {
            return $groups;
        }
        $places = self::places($plan, $scope);
        $ranked = array();
        foreach ($groups as $at => $group) {
            $key = self::keyOf($group);
            $place = $key !== null && isset($places[$key])
                ? $places[$key]
                : array('rank' => 2, 'within' => 0, 'tier' => null);
            $group['priority'] = $place['tier'];
            if ($place['tier'] === self::PINNED) {
                $lead = self::lead($group);
                if ($lead !== null) {
                    $group['lead'] = $lead;
                }
            }
            $ranked[] = array(
                'rank' => $place['rank'],
                'within' => $place['within'],
                'at' => $at,
                'group' => $group,
            );
        }
        usort($ranked, function ($a, $b) {
            if ($a['rank'] !== $b['rank']) {
                return $a['rank'] - $b['rank'];
            }
            if ($a['within'] !== $b['within']) {
                return $a['within'] - $b['within'];
            }
            return $a['at'] - $b['at'];
        });
        $out = array();
        foreach ($ranked as $row) {
            $out[] = $row['group'];
        }
        return $out;
    }

    /**
     * The same tiers, over a list of individual labels.
     *
     * `order()`'s twin for the surfaces that hand out a chip or a row
     * per label rather than a group per dimension — a facet rail, a
     * chip run, a table column. One table of tiers, three entry
     * points: the precedence, the lowercasing and the *declares
     * nothing changes nothing* rule are `order()`'s and are not
     * restated here.
     *
     * This one is for a list that is all of one dimension; `across()`
     * takes a list holding both.
     *
     * **It differs in exactly one thing**, and the difference is the
     * handling rule at a granularity it was not written for. A
     * pinned `tlp` *group* renders the most restrictive label with a
     * count of the others, because the group is one slot and something
     * has to fill it. A list of `tlp` *items* has no slot to win: the
     * reader sees `tlp:clear`, `tlp:red` and `tlp:amber` as three
     * chips, and what matters is that the most restrictive is the
     * first of them. Ranking them equal — which is what `order()`
     * does, since they share a key and therefore a rank — leaves the
     * incoming order deciding, and the incoming order is a count.
     *
     * So within a handling namespace the profile has **listed**,
     * items are ordered by `HANDLING` severity, from the table `lead()`
     * reads, so the page cannot rank `tlp` two ways.
     *
     * **A namespace nobody listed keeps arrival order, `tlp`
     * included.** Re-sorting a handling taxonomy no profile mentioned
     * would change every page on every instance in the name of a
     * profile that declared nothing, which is the one thing
     * `declares()` exists to prevent.
     *
     * Each item carries `key` — as a group does — and `name`, the full
     * tag string severity is read from. An item with no `name` ranks
     * last inside its tier rather than first, which is `severity()`'s
     * answer for a predicate the table does not know.
     *
     * @param array $labels Individual labels, each carrying `key`
     * @param array|null $plan A plan, a profile, or its parameters
     * @param string $scope `taxonomies` or `galaxies`
     * @return array The same labels, ordered and marked
     */
    public static function labels(array $labels, $plan, $scope)
    {
        $plan = self::planFor($plan);
        if (empty($labels) || !self::declares($plan, $scope)) {
            return $labels;
        }
        return self::ranked(
            $labels,
            array($scope => self::places($plan, $scope)),
            $scope
        );
    }

    /**
     * The same tiers again, over a list that holds both dimensions at
     * once.
     *
     * `labels()` ranks a list that is all taxonomy tags or all galaxy
     * clusters, and most surfaces are one or the other. The
     * neighbourhood label table is neither: it is a
     * single list ranked by shared events in which a cluster row sits
     * beside a tag row, with a cut partway down it, and both dimensions
     * have to compete for the rows above the cut. Ranking the tags and
     * ranking the clusters separately produces two ordered lists and no
     * answer about how to interleave them.
     *
     * So each item names its own dimension in `scope`, and one pass
     * ranks the lot. Everything else is `labels()`: the tiers, the
     * lowercasing, the handling severity inside a listed namespace, and
     * the rule that ties keep arrival order — which here is the
     * incoming rank, so a neighbourhood the profile has no opinion
     * about still reads by shared events.
     *
     * **An item whose `scope` names neither dimension is unlisted**,
     * like an item with no `key`, and keeps its place. A caller that
     * has not been taught to say which dimension a row belongs to
     * therefore gets its own order rather than a wrong one.
     *
     * A profile declaring one dimension and not the other is the
     * ordinary case rather than a special one: the undeclared
     * dimension's items are unlisted, tie with each other, and keep
     * the order they arrived in among themselves.
     *
     * @param array $labels Items, each carrying `key` and `scope`
     * @param array|null $plan A plan, a profile, or its parameters
     * @return array The same items, ordered and marked
     */
    public static function across(array $labels, $plan)
    {
        $plan = self::planFor($plan);
        if (empty($labels) || !self::declares($plan)) {
            return $labels;
        }
        $places = array();
        foreach (array(self::TAXONOMIES, self::GALAXIES) as $one) {
            $places[$one] = self::places($plan, $one);
        }
        return self::ranked($labels, $places, null);
    }

    /**
     * One ranking pass, for both per-item entry points.
     *
     * @param array $labels
     * @param array $places Dimension => `places()`
     * @param string|null $scope The one dimension every item is in, or
     *     null to read each item's own `scope`
     * @return array
     */
    private static function ranked(array $labels, array $places, $scope)
    {
        $ranked = array();
        $first = array();
        foreach ($labels as $at => $label) {
            $dimension = $scope === null
                ? self::scopeOf($label)
                : $scope;
            $key = self::keyOf($label);
            $place = $dimension !== null && $key !== null
                && isset($places[$dimension][$key])
                ? $places[$dimension][$key]
                : array('rank' => 2, 'within' => 0, 'tier' => null);
            $label['priority'] = $place['tier'];
            /*
             * Constant for everything the profile did not list, so
             * those items tie and `at` keeps them where they were.
             *
             * Severity is a taxonomy's, and the dimension is tested
             * rather than the key alone: `HANDLING` is keyed by
             * namespace, and a galaxy whose `type` happened to spell
             * one of them would otherwise be ranked by a table written
             * about handling markings.
             */
            $severity = 0;
            if ($place['tier'] !== null
                && $dimension === self::TAXONOMIES
                && isset(self::HANDLING[$key])
            ) {
                $severity = self::severity(
                    $label,
                    $key,
                    self::HANDLING[$key]
                );
            }
            /*
             * Where this key's first item arrived, which decides the
             * order of two **listed** keys the profile ranked equally.
             *
             * Within one dimension that cannot happen — a tier's keys
             * hold distinct positions, so `within` has already
             * separated them — and the group is inert. Across two
             * dimensions it happens constantly: a profile's taxonomy
             * list and its galaxy list are independent, so the first
             * pinned taxonomy and the first pinned galaxy both sit at
             * position zero and the profile has said nothing about
             * which of the two leads.
             *
             * Arrival order answers that, and grouping by key rather
             * than interleaving by it is what keeps `severity`
             * meaningful: severity is an order *inside* a handling
             * namespace, and comparing a cluster's zero against
             * `tlp:clear`'s four is comparing two different scales.
             *
             * Zero for everything unlisted, whose severity is zero
             * too, so `at` alone decides among them and their arrival
             * order survives.
             */
            $group = 0;
            if ($place['tier'] !== null && $key !== null) {
                $id = $dimension . '|' . $key;
                if (!isset($first[$id])) {
                    $first[$id] = $at;
                }
                $group = $first[$id];
            }
            $ranked[] = array(
                'rank' => $place['rank'],
                'within' => $place['within'],
                'group' => $group,
                'severity' => $severity,
                'at' => $at,
                'label' => $label,
            );
        }
        usort($ranked, function ($a, $b) {
            if ($a['rank'] !== $b['rank']) {
                return $a['rank'] - $b['rank'];
            }
            if ($a['within'] !== $b['within']) {
                return $a['within'] - $b['within'];
            }
            if ($a['group'] !== $b['group']) {
                return $a['group'] - $b['group'];
            }
            if ($a['severity'] !== $b['severity']) {
                return $a['severity'] < $b['severity'] ? -1 : 1;
            }
            return $a['at'] - $b['at'];
        });
        $out = array();
        foreach ($ranked as $row) {
            $out[] = $row['label'];
        }
        return $out;
    }

    /**
     * The dimension an item says it belongs to.
     *
     * @param array $label
     * @return string|null Null for an item naming neither dimension,
     *     which is unlisted by definition
     */
    private static function scopeOf(array $label)
    {
        if (!isset($label['scope'])) {
            return null;
        }
        $scope = mb_strtolower(trim((string)$label['scope']));
        return $scope === self::TAXONOMIES || $scope === self::GALAXIES
            ? $scope
            : null;
    }

    /**
     * The namespace a tag name belongs to, which is what a profile
     * lists taxonomies by.
     *
     * Everything before the first colon, lowercased; null where there
     * is no colon, which is a tag in no taxonomy at all.
     *
     * **Looser than `Taxonomy::splitTagToComponents` on purpose.** The
     * strict grammar is already copied once, in
     * `ValueContextTool::split()`, which needs the predicate and the
     * value as well; a third copy to answer *what is in front of the
     * colon* would be a regex maintained in three places to decide one
     * substring. The only input the two disagree about is a string no
     * machine-tag grammar accepts — `foo"bar:baz` — and there they
     * disagree harmlessly: the loose answer is a key no profile can
     * have listed, so the label is unlisted and keeps its place, which
     * is the same place a strict null would have left it.
     *
     * A galaxy tag answers `misp-galaxy`, and no profile lists that: a
     * profile's galaxy list is keyed by the galaxy `type`, which is the
     * other dimension and is ordered where the clusters are drawn. So a
     * galaxy tag that survives into a tag list keeps its place rather
     * than being ranked under the wrong dimension.
     *
     * @param string|null $name A tag name
     * @return string|null
     */
    public static function namespaceOf($name)
    {
        if (!is_string($name) && !is_numeric($name)) {
            return null;
        }
        $name = trim((string)$name);
        $at = strpos($name, ':');
        if ($at === false || $at === 0) {
            return null;
        }
        return mb_strtolower(substr($name, 0, $at));
    }

    /**
     * The pinned dimensions this value carries nothing of.
     *
     * The only tier that renders absence, and the reason it exists:
     * an unlabelled value is not an unrestricted one, and a reader who
     * does not notice the label is missing will assume they saw it.
     *
     * **It says nothing about what the reader cannot see.** A pinned
     * absence says no tag of this dimension is on this value *within
     * what this reader may read*, which is the page's standing rule,
     * and it carries no count of anything withheld.
     *
     * **The instance's enablement is a floor this cannot lift.**
     * `enabled = 0` and `hide_tag` say *this does not exist here*; a
     * pin says *when it is used, it matters*. The first wins, because
     * it is a statement about what the instance holds and the second
     * is a statement about attention — so a pin on a disabled taxonomy
     * draws nothing rather than an empty row inviting somebody to fill
     * a dimension nobody on this instance can fill. The permitted set
     * is read by the caller, which is the only half of this that needs
     * a query; null means no floor was read and every pin stands.
     *
     * @param array $groups The groups the surface assembled
     * @param array|null $plan A plan, a profile, or its parameters
     * @param string $scope `taxonomies` or `galaxies`
     * @param array|null $permitted Keys the instance permits, or null
     * @return array One entry per absent pin, in the declared order
     */
    public static function absent(array $groups, $plan, $scope,
        $permitted = null
    ) {
        $plan = self::planFor($plan);
        if (empty($plan[$scope][self::PINNED])) {
            return array();
        }
        $present = array();
        foreach ($groups as $group) {
            $key = self::keyOf($group);
            if ($key !== null) {
                $present[$key] = true;
            }
        }
        $floor = null;
        if (is_array($permitted)) {
            $floor = array();
            foreach ($permitted as $key) {
                $floor[mb_strtolower(trim((string)$key))] = true;
            }
        }
        $absent = array();
        foreach ($plan[$scope][self::PINNED] as $key) {
            if (isset($present[$key])) {
                continue;
            }
            if ($floor !== null && !isset($floor[$key])) {
                continue;
            }
            $absent[] = array('key' => $key);
        }
        return $absent;
    }

    /**
     * Every key this plan names, for a caller that has to ask the
     * instance which of them it permits before absence is drawn.
     *
     * @param array|null $plan
     * @param string $scope
     * @param string|null $tier One tier, or null for all three
     * @return array Keys, deduplicated
     */
    public static function keys($plan, $scope, $tier = null)
    {
        $plan = self::planFor($plan);
        $tiers = $tier === null ? self::TIERS : array($tier);
        $keys = array();
        foreach ($tiers as $one) {
            if (empty($plan[$scope][$one])) {
                continue;
            }
            foreach ($plan[$scope][$one] as $key) {
                $keys[$key] = true;
            }
        }
        return array_keys($keys);
    }

    /**
     * The scoring eligibility list, which is **not** the display
     * priority.
     *
     * `attribution.galaxy` reads a value's non-ATT&CK-shaped clusters
     * and consults no category table at all, so unfiltered, on a value
     * tagged `sector:banking`, `country:lu` and a `preventive-measure`
     * it would pay per cluster and call that attribution — under a
     * signal whose own absence row reads *"Nobody has attributed this
     * value to an actor, family or campaign"*. This is its filter.
     *
     * **Display priority and scoring eligibility answer different
     * questions and the wrong answers are different.** A CERT demoting
     * `firearms` down the card must not change anybody's score; a desk
     * that prefers a typology on the card must not thereby have it
     * counted as attribution. One list gets one of those two wrong on
     * every instance.
     *
     * Null when the profile declares none, which keeps the filter off
     * and scores every cluster — the answer a document without this
     * section needs.
     *
     * @param array|null $profile A profile or its parameters
     * @return array|null Galaxy types, lowercased, or null
     */
    public static function attribution($profile)
    {
        if (!is_array($profile)) {
            return null;
        }
        $section = null;
        if (isset($profile['parameters'][self::GALAXIES])
            && is_array($profile['parameters'][self::GALAXIES])
        ) {
            $section = $profile['parameters'][self::GALAXIES];
        } elseif (isset($profile[self::GALAXIES])
            && is_array($profile[self::GALAXIES])
        ) {
            $section = $profile[self::GALAXIES];
        }
        if ($section === null
            || empty($section['attribution'])
            || !is_array($section['attribution'])
        ) {
            return null;
        }
        $types = array();
        foreach ($section['attribution'] as $type) {
            if (!is_string($type) && !is_numeric($type)) {
                continue;
            }
            $type = mb_strtolower(trim((string)$type));
            if ($type !== '') {
                $types[$type] = true;
            }
        }
        return empty($types) ? null : array_keys($types);
    }

    /**
     * The taxonomies an event's marking block draws, in declared order.
     *
     * A profile that says nothing gets `DEFAULT_MARKINGS`; one that
     * declares an empty list has asked for no marking block at all.
     *
     * @param array|null $profile A profile or its parameters
     * @return array Taxonomy namespaces, lowercased
     */
    public static function markings($profile)
    {
        $section = self::section($profile);
        if (!array_key_exists('markings', $section)
            || !is_array($section['markings'])
        ) {
            return self::DEFAULT_MARKINGS;
        }
        $namespaces = array();
        foreach ($section['markings'] as $namespace) {
            if (!is_string($namespace) && !is_numeric($namespace)) {
                continue;
            }
            $namespace = mb_strtolower(trim((string)$namespace));
            if ($namespace !== '' && !in_array($namespace, $namespaces, true)) {
                $namespaces[] = $namespace;
            }
        }
        return $namespaces;
    }

    /**
     * Whether this namespace's labels carry an order of severity.
     *
     * @param string $namespace
     * @return bool
     */
    public static function isHandling($namespace)
    {
        return isset(self::HANDLING[mb_strtolower((string)$namespace)]);
    }

    /**
     * The most restrictive label in a handling group, and how many
     * others sit behind it.
     *
     * Null for every other group, which is what makes the rest of the
     * card keep rendering its labels in count order: only the handling
     * taxonomies carry an order the page can know, and imposing one
     * anywhere else would be the invented ranking
     * `ValueContextTool::position` already refuses to draw.
     *
     * @param array $group A taxonomy group carrying `key` and `tags`
     * @return array|null `tag` and `others`
     */
    public static function lead(array $group)
    {
        $key = self::keyOf($group);
        if ($key === null
            || !isset(self::HANDLING[$key])
            || empty($group['tags'])
            || count($group['tags']) < 2
        ) {
            return null;
        }
        $order = self::HANDLING[$key];
        $best = null;
        $bestRank = null;
        foreach ($group['tags'] as $tag) {
            $rank = self::severity($tag, $key, $order);
            if ($bestRank === null || $rank < $bestRank) {
                $best = $tag;
                $bestRank = $rank;
            }
        }
        if ($best === null) {
            return null;
        }
        return array(
            'tag' => $best,
            'others' => count($group['tags']) - 1,
        );
    }

    /**
     * One tag's place in its handling taxonomy's order of severity.
     *
     * @param array $tag A group's tag row
     * @param string $namespace The group's key
     * @param array $order Predicate => rank
     * @return int PHP_INT_MAX for a predicate the table does not rank
     */
    private static function severity(array $tag, $namespace, array $order)
    {
        if (empty($tag['name'])) {
            return PHP_INT_MAX;
        }
        $name = mb_strtolower((string)$tag['name']);
        $prefix = $namespace . ':';
        if (strpos($name, $prefix) !== 0) {
            return PHP_INT_MAX;
        }
        $predicate = substr($name, strlen($prefix));
        return isset($order[$predicate])
            ? $order[$predicate]
            : PHP_INT_MAX;
    }

    /**
     * Key => rank, position and tier, for one dimension.
     *
     * @param array $plan
     * @param string $scope
     * @return array
     */
    private static function places(array $plan, $scope)
    {
        $ranks = array(
            self::PINNED => 0,
            self::PREFERRED => 1,
            self::DEMOTED => 3,
        );
        $places = array();
        foreach (self::TIERS as $tier) {
            if (empty($plan[$scope][$tier])) {
                continue;
            }
            foreach ($plan[$scope][$tier] as $within => $key) {
                $places[$key] = array(
                    'rank' => $ranks[$tier],
                    'within' => $within,
                    'tier' => $tier,
                );
            }
        }
        return $places;
    }

    /**
     * @param array $group
     * @return string|null Null for a group carrying no key, which is
     *     unlisted by definition
     */
    private static function keyOf(array $group)
    {
        if (!isset($group['key'])) {
            return null;
        }
        $key = mb_strtolower(trim((string)$group['key']));
        return $key === '' ? null : $key;
    }

    /**
     * Whether this array is already a plan rather than a profile.
     *
     * A plan carries both dimensions with all three tiers, which no
     * profile section does: `planFor()` fills them in.
     *
     * @param mixed $candidate
     * @return bool
     */
    private static function isPlan($candidate)
    {
        if (!is_array($candidate)) {
            return false;
        }
        foreach (array(self::TAXONOMIES, self::GALAXIES) as $scope) {
            if (!isset($candidate[$scope])
                || !is_array($candidate[$scope])
            ) {
                return false;
            }
            foreach (self::TIERS as $tier) {
                if (!isset($candidate[$scope][$tier])
                    || !is_array($candidate[$scope][$tier])
                ) {
                    return false;
                }
            }
        }
        return true;
    }
}
