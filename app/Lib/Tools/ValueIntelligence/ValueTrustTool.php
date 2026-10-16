<?php

/**
 * What the analyst believes about their sources, turned into a number
 * the ledger can carry.
 *
 * `reference.org_trust` grades organisations on the admiralty scale and
 * `reference.org_trust_scale` says what each grade is worth. Both live
 * in the profile because **MISP has nowhere else to put them** —
 * `admiralty-scale` is a taxonomy, taxonomies reach MISP as tags, and
 * nothing in MISP attaches a tag to an organisation.
 *
 * ## The one sentence the whole mechanism reduces to
 *
 * **Trust weighting replaces a count of organisations with a weighted
 * count of organisations, and a count of their rows with a weighted
 * count of their rows.** That is all three trust-weighted signals:
 *
 * ```
 * reporting.independent_orgs   count(orgs)      → Σ factor
 * sightings.volume_recency     count(sightings) → Σ count × factor
 * sightings.false_positive     count(fp)        → Σ fp × factor
 *                              extra orgs       → Σ factor − 1
 * ```
 *
 * Every one of those degenerates to the unweighted number when every
 * factor is `1.0`, which is what makes *the same ledger to the unit*
 * arithmetic rather than luck. The cap is applied **after** the
 * weighting and the rounding happens **once**, in
 * `ValueSignalBase::row()`: rounding per organisation and then summing
 * produces a number that does not match the same calculation done the
 * other way.
 *
 * ## The map is the switch
 *
 * An empty `org_trust` map does not merely weight everything at `1.0` —
 * **it takes the mechanism out of the path entirely** (`inForce()`).
 * The distinction matters because the scale is data too: an analyst who
 * edits `unrated` to `0.5` and grades nobody would otherwise silently
 * halve every score on the instance. With the map as the switch,
 * `unrated` only means something once there is a graded organisation
 * for it to contrast with, and *"empty means as before"* holds
 * structurally instead of numerically.
 *
 * ## Keyed by uuid, resolved to ids once
 *
 * The profile keys grades by `organisations.uuid` and never by
 * `org_id`, because an id is local: the same organisation carries
 * different ids on different instances, so a profile keyed by id would
 * grade the wrong organisation after an export/import or against a
 * peer. Everything downstream — the org rows, the sighting rows
 * — carries the local id, so the uuid→id resolution happens once,
 * where the `organisations` table is in reach (`ValueIntelligence::
 * verdictTrust`), and the context carries the joined result. A graded
 * uuid that matches no row on this instance is **kept, ignored and
 * reported** rather than dropped: the organisation may return, or the
 * profile may have been written elsewhere.
 *
 * ## An organisation this viewer cannot name is unrated
 *
 * A sighting under `Plugin.Sightings_anonymise` arrives with its
 * `org_id` zeroed, so it cannot be graded and the question does not
 * arise. What can arise is an organisation whose id is on the row and
 * whose name is not disclosed — and grading *that* would change the
 * number for a reason the reader cannot see, which the evidence line
 * must never do. So it is treated as unrated. The rule costs a little
 * accuracy on a configuration almost nobody runs and it keeps the
 * evidence line honest on every configuration.
 *
 * No `$user`, no model, no view: the arithmetic and nothing else, so a
 * background worker and the editor's simulator read the same numbers
 * as the page.
 */
class ValueTrustTool
{
    /**
     * The admiralty scale's source-reliability grades, **seven** and
     * not the six a reader assumes: the shipped `admiralty-scale`
     * taxonomy runs `a` (*Completely reliable*) through `g`
     * (*Deliberately deceptive*).
     */
    const GRADES = array('A', 'B', 'C', 'D', 'E', 'F', 'G');

    /** The pseudo-grade every organisation the map does not name has. */
    const UNRATED = 'unrated';

    /**
     * Grade → multiplier, and the taxonomy's own `numerical_value`
     * column is the receipt: it runs `a=100, b=75, c=50, d=25, e=0,
     * f=50, g=0`, so **f equals c** — in the Admiralty System `F` is
     * *"Reliability cannot be judged"*, a neutral statement and the
     * semantic twin of `unrated`, not the bottom of the scale. The
     * ordering here follows that structure:
     * `A > B > C = F = unrated > D > E ≥ G`.
     *
     * Two deliberate departures from copying the numbers outright.
     * `E` (*Unreliable*) is `0.25` rather than the taxonomy's
     * zero, because unreliable still means *sometimes right* and a
     * floor keeps that evidence visibly discounted in the ledger
     * instead of silently erased. `G` (*Deliberately deceptive*) is a
     * true `0.00`: an accusation of deception rather than a quality
     * judgement, and it zeroes that organisation's evidence **in both
     * directions** — a deceptive organisation's false-positive
     * sightings, whitewashing a value it controls, count for exactly as
     * much as its reports.
     *
     * `C`, `F` and `unrated` are all `1.00`, which makes grading an
     * organisation `C` or `F` a deliberate statement that changes
     * nothing — useful, because it records that you considered them.
     */
    const DEFAULT_SCALE = array(
        'A' => 1.25,
        'B' => 1.10,
        'C' => 1.00,
        'D' => 0.75,
        'E' => 0.25,
        'F' => 1.00,
        'G' => 0.00,
        self::UNRATED => 1.00,
    );

    /**
     * What each letter means, in the shipped taxonomy's own words.
     *
     * A letter is not a grade anybody can read. `admiralty-scale`'s
     * `source-reliability` entries carry an `expanded` column — *B* is
     * *Usually reliable* — and a picker offering `A B C D E F G` asks
     * the analyst to have the taxonomy memorised before they can say
     * anything about a source. The wording is copied rather than read
     * out of the taxonomy at render time because a profile must still
     * be gradeable on an instance that never enabled `admiralty-scale`,
     * and because `F` and `G` are the two the reader most needs told:
     * `F` reads as *nearly failing* and means *cannot be judged*.
     *
     * `unrated` is not in the taxonomy. It is what every organisation
     * the map does not name already is, and it is offered so that
     * taking an opinion back is a choice in the list rather than a
     * deleted row.
     */
    const GRADE_LABELS = array(
        'A' => 'Completely reliable',
        'B' => 'Usually reliable',
        'C' => 'Fairly reliable',
        'D' => 'Not usually reliable',
        'E' => 'Unreliable',
        'F' => 'Reliability cannot be judged',
        'G' => 'Deliberately deceptive',
        self::UNRATED => 'No opinion recorded',
    );

    /**
     * The `reference` section, whichever shape the profile arrived in.
     *
     * `ValueVerdictTool::section()`'s twin, duplicated for the same
     * reason `ValueRelevanceTool` duplicates it: this class is pure and
     * a caller may hand over the parameters alone.
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
        if (isset($profile['parameters']['reference'])
            && is_array($profile['parameters']['reference'])
        ) {
            return $profile['parameters']['reference'];
        }
        if (isset($profile['reference'])
            && is_array($profile['reference'])
        ) {
            return $profile['reference'];
        }
        return array();
    }

    /**
     * The grades and the scale, resolved and validated.
     *
     * A grade the scale has no entry for, or a value that is not a
     * number, is **not** an error that stops the assessment: a profile
     * written against a later vocabulary has to survive being read by
     * an older instance, which is the rule for a whole missing signal
     * applied to one of its entries. Such an entry
     * is dropped from `grades` and named in `invalid`, so the editor
     * can say which line an analyst needs to look at.
     *
     * @param array|null $profile
     * @return array `grades` (uuid => GRADE), `scale` (grade => float),
     *               `in_force` and `invalid`
     */
    public static function planFor($profile)
    {
        $section = self::section($profile);
        $scale = self::scaleFrom($section);
        $grades = array();
        $invalid = array();
        $map = isset($section['org_trust'])
            && is_array($section['org_trust'])
            ? $section['org_trust']
            : array();
        foreach ($map as $uuid => $grade) {
            $uuid = strtolower(trim((string)$uuid));
            $normalised = self::normaliseGrade($grade);
            if ($uuid === '') {
                continue;
            }
            if ($normalised === null) {
                $invalid[$uuid] = (string)$grade;
                continue;
            }
            $grades[$uuid] = $normalised;
        }
        return array(
            'grades' => $grades,
            'scale' => $scale,
            /*
             * The switch, and the reason it reads the *validated* map:
             * a profile whose only entry is a typo weights nothing, so
             * it must not put the mechanism in the path and then leave
             * every factor at 1.0 — that state is indistinguishable
             * from a working map on the page, and the ledger would
             * carry a weighting note explaining a weighting that did
             * not happen.
             */
            'in_force' => !empty($grades),
            'invalid' => $invalid,
        );
    }

    /**
     * The same judgement applied to a second kind of source: how far
     * to believe an enrichment module.
     *
     * *How far do I trust this source* is one question, so it uses one
     * vocabulary — the admiralty scale the organisation map already
     * uses, the same `org_trust_scale` overrides, and the same editor
     * surface. A second grading scheme for vendors would be the same
     * judgement written twice.
     *
     * **And one deliberate divergence: ungraded is zero here, where
     * an ungraded organisation is 1.0.** The asymmetry is the whole of
     * what keeps the shipped default neutral. An organisation's
     * evidence is MISP's own and counts by default — not grading it
     * says nothing. An outside vendor's opinion is not something a
     * neutral document may assert a weight for, and a fallback grade
     * would have `default-v1` asserting that some particular service
     * is worth twelve points, which is precisely the shipped opinion
     * it refuses to be. So on a stock instance the rows appear, are
     * marked as not counted, and grading a module is the single act
     * that turns them on.
     *
     * @param array|null $profile
     * @return array `grades` (module => GRADE), `scale`, `in_force`
     *               and `invalid`
     */
    public static function modulePlanFor($profile)
    {
        $section = self::section($profile);
        $scale = self::scaleFrom($section);
        $grades = array();
        $invalid = array();
        $map = isset($section['module_trust'])
            && is_array($section['module_trust'])
            ? $section['module_trust']
            : array();
        foreach ($map as $module => $grade) {
            /*
             * Not lowercased, unlike an organisation's uuid. A module
             * name is matched exactly everywhere else in MISP —
             * `Plugin.Enrichment_<name>_enabled` is exact — and a
             * helpfully corrected name would be this class quietly
             * grading something the profile did not name.
             */
            $module = trim((string)$module);
            if ($module === '') {
                continue;
            }
            $normalised = self::normaliseGrade($grade);
            if ($normalised === null) {
                $invalid[$module] = (string)$grade;
                continue;
            }
            $grades[$module] = $normalised;
        }
        return array(
            'grades' => $grades,
            'scale' => $scale,
            'in_force' => !empty($grades),
            'invalid' => $invalid,
        );
    }

    /**
     * What one module's answer is multiplied by.
     *
     * Zero for a module the map does not name — see `modulePlanFor()`
     * — so a caller must check the factor rather than assume a row is
     * worth something.
     *
     * @param array $plan From `modulePlanFor()`
     * @param string $module
     * @return float
     */
    public static function moduleFactor(array $plan, $module)
    {
        $grade = self::moduleGrade($plan, $module);
        return $grade === null
            ? 0.0
            : self::factorForGrade($plan, $grade);
    }

    /**
     * One module's grade, or null where the profile has not given it
     * one.
     *
     * @param array $plan
     * @param string $module
     * @return string|null
     */
    public static function moduleGrade(array $plan, $module)
    {
        $grades = isset($plan['grades']) && is_array($plan['grades'])
            ? $plan['grades']
            : array();
        $module = trim((string)$module);
        return isset($grades[$module]) ? $grades[$module] : null;
    }

    /**
     * The scale in force: the default, with whatever the profile
     * overrode.
     *
     * Held in the profile alongside the map so an analyst who wants `D`
     * to mean `0.9` rather than `0.75` can say so, and so that *the same
     * map produces a different number* is a property of data rather than
     * of a release.
     *
     * @param array $section
     * @return array
     */
    private static function scaleFrom(array $section)
    {
        $scale = self::DEFAULT_SCALE;
        $given = isset($section['org_trust_scale'])
            && is_array($section['org_trust_scale'])
            ? $section['org_trust_scale']
            : array();
        foreach ($given as $grade => $factor) {
            $key = self::normaliseGrade($grade);
            if ($key === null || !is_numeric($factor)) {
                continue;
            }
            /*
             * Negative is refused rather than clamped. A negative
             * multiplier would flip a signal's sign, and a weighting
             * must not: `direction` is
             * derived from the sign of the anchored row, so a source
             * grade turning corroboration into a contradiction would
             * make the arrow beside a row point the other way for a
             * reason no reader could find.
             */
            $scale[$key] = max(0.0, (float)$factor);
        }
        return $scale;
    }

    /**
     * A grade as this class spells it, or null when it is not one.
     *
     * The taxonomy writes them lowercase, the page writes them upper,
     * and an analyst editing JSON will write whichever they saw last —
     * so both are the same grade rather than one grade and one typo.
     *
     * @param mixed $grade
     * @return string|null
     */
    public static function normaliseGrade($grade)
    {
        if (!is_string($grade) && !is_numeric($grade)) {
            return null;
        }
        $grade = strtoupper(trim((string)$grade));
        if ($grade === strtoupper(self::UNRATED)) {
            return self::UNRATED;
        }
        return in_array($grade, self::GRADES, true) ? $grade : null;
    }

    /**
     * What one grade is worth under this plan.
     *
     * @param array $plan From `planFor()`, or a context's trust block
     * @param string|null $grade
     * @return float
     */
    public static function factorForGrade(array $plan, $grade)
    {
        $scale = isset($plan['scale']) && is_array($plan['scale'])
            ? $plan['scale']
            : self::DEFAULT_SCALE;
        if ($grade === null || !isset($scale[$grade])) {
            $grade = self::UNRATED;
        }
        return isset($scale[$grade])
            ? (float)$scale[$grade]
            : 1.0;
    }

    /**
     * The context's trust block: the plan, joined to the organisations
     * this instance actually has.
     *
     * @param array $plan From `planFor()`
     * @param array $present uuid => `id` and `name`, for the graded
     *                       uuids found on this instance
     * @return array
     */
    public static function contextFrom(array $plan, array $present)
    {
        $grades = array();
        $factors = array();
        $names = array();
        $unknown = array();
        foreach ($plan['grades'] as $uuid => $grade) {
            if (!isset($present[$uuid]['id'])) {
                $unknown[$uuid] = $grade;
                continue;
            }
            $id = (int)$present[$uuid]['id'];
            $grades[$id] = $grade;
            $factors[$id] = self::factorForGrade($plan, $grade);
            $names[$id] = isset($present[$uuid]['name'])
                ? $present[$uuid]['name']
                : null;
        }
        return array(
            'in_force' => !empty($plan['in_force']),
            'grades' => $grades,
            'factors' => $factors,
            'names' => $names,
            'scale' => $plan['scale'],
            /*
             * Kept, ignored, and listed — never deleted, because the
             * organisation may return or the profile may be shared.
             * The editor renders it as *"3 grades for organisations
             * not known here"*.
             */
            'unknown' => $unknown,
            'invalid' => $plan['invalid'],
        );
    }

    /**
     * The trust block off a context, in the shape the readers below
     * expect however little of it a caller built.
     *
     * @param array $context
     * @return array
     */
    public static function blockFrom(array $context)
    {
        if (isset($context['trust']) && is_array($context['trust'])) {
            return $context['trust'];
        }
        return array(
            'in_force' => false,
            'grades' => array(),
            'factors' => array(),
            'names' => array(),
            'scale' => self::DEFAULT_SCALE,
            'unknown' => array(),
            'invalid' => array(),
        );
    }

    /**
     * Whether any signal should be weighting anything at all.
     *
     * Two conditions, and the second is the profile's: the map has to
     * be in force, **and** the signal's own entry has to declare
     * `trust_weighted`. A signal whose contribution is not
     * derived from *which organisations* said something has nothing to
     * weight — `reporting.published_ratio` is a property of events,
     * `attribution.galaxy` is not an organisation's claim in the same
     * way, and `lifecycle.*` has nothing to attribute.
     *
     * @param array $context
     * @param array $config The signal's entry from `profile.signals`
     * @return bool
     */
    public static function inForce(array $context, array $config)
    {
        $trust = self::blockFrom($context);
        return !empty($trust['in_force'])
            && !empty($config['trust_weighted']);
    }

    /**
     * One organisation's multiplier.
     *
     * An organisation the map does not name — and an organisation this
     * viewer cannot name, which arrives as id `0` — is `unrated`.
     *
     * @param array $context
     * @param int|null $orgId
     * @return float
     */
    public static function factor(array $context, $orgId)
    {
        $trust = self::blockFrom($context);
        $orgId = (int)$orgId;
        if ($orgId > 0 && isset($trust['factors'][$orgId])) {
            return (float)$trust['factors'][$orgId];
        }
        return self::factorForGrade($trust, self::UNRATED);
    }

    /**
     * One organisation's grade, or null when the map does not name it.
     *
     * @param array $context
     * @param int|null $orgId
     * @return string|null
     */
    public static function gradeFor(array $context, $orgId)
    {
        $trust = self::blockFrom($context);
        $orgId = (int)$orgId;
        return $orgId > 0 && isset($trust['grades'][$orgId])
            ? $trust['grades'][$orgId]
            : null;
    }

    /**
     * A weighted count: `Σ count × factor`.
     *
     * The one arithmetic every trust-weighted signal shares. Hand it
     * `orgId => count` and it returns the count the ledger should read
     * — the same number as `array_sum($counts)` when nothing is graded,
     * which is the invariant the whole weighting rests on.
     *
     * Returned as a float on purpose: the caller multiplies it by its
     * points and hands the product to `row()`, which rounds once.
     *
     * @param array $context
     * @param array $counts orgId => count
     * @return float
     */
    public static function weigh(array $context, array $counts)
    {
        $total = 0.0;
        foreach ($counts as $orgId => $count) {
            $total += (float)$count * self::factor($context, $orgId);
        }
        return $total;
    }

    /**
     * A weighted headcount: `Σ factor` over the organisations given.
     *
     * `weigh()` with every count at one, named separately because that
     * is what `reporting.independent_orgs` computes and reading
     * `weigh($context, array_fill_keys($ids, 1))` at the call site says
     * less than this does.
     *
     * @param array $context
     * @param array $orgIds
     * @return float
     */
    public static function weighOrgs(array $context, array $orgIds)
    {
        $total = 0.0;
        foreach ($orgIds as $orgId) {
            $total += self::factor($context, $orgId);
        }
        return $total;
    }

    /**
     * The organisation names a ledger row prints, with the grade
     * appended to the ones that carry one.
     *
     * `ORG-A (B), ORG-B (B), ORG-C (C), ORG-D (D)`, because a row
     * reading *"4 independent organisations reported it — +24"* where
     * the unweighted number would be `+28` is unexplainable without it.
     *
     * @param array $context
     * @param array $orgs `id` and `name` pairs, in the row's own order
     * @return array
     */
    public static function annotate(array $context, array $orgs)
    {
        $names = array();
        foreach ($orgs as $org) {
            $name = isset($org['name']) ? (string)$org['name'] : '';
            if ($name === '') {
                continue;
            }
            $grade = self::gradeFor(
                $context,
                isset($org['id']) ? $org['id'] : null
            );
            $names[] = $grade === null
                ? $name
                : sprintf('%s (%s)', $name, $grade);
        }
        return $names;
    }

    /**
     * The clause that says a weighting happened, or null when none did.
     *
     * **The one part of this feature that changes a number for a reason
     * invisible in the underlying data**, so the rule for when it
     * appears is *a grade touched this row* — not *the map is
     * non-empty*. The case it keeps quiet on: a grade for an
     * organisation with no occurrence of this value is normal and
     * uninteresting, and a note about it would appear on every value an
     * analyst has ever graded anybody for.
     *
     * A grade worth `0.00` is named explicitly: an organisation whose
     * evidence counted for nothing has to be visible as such, or the row
     * is short by an amount with no explanation anywhere on the page.
     *
     * @param array $context
     * @param array $orgIds Every organisation the row considered
     * @return string|null
     */
    public static function clause(array $context, array $orgIds)
    {
        $trust = self::blockFrom($context);
        $graded = array();
        $zeroed = array();
        foreach ($orgIds as $orgId) {
            $grade = self::gradeFor($context, $orgId);
            if ($grade === null) {
                continue;
            }
            $graded[] = $grade;
            if (self::factor($context, $orgId) == 0.0) {
                $name = isset($trust['names'][(int)$orgId])
                    ? $trust['names'][(int)$orgId]
                    : null;
                $zeroed[] = $name === null
                    ? sprintf(__('grade %s'), $grade)
                    : sprintf('%s (%s)', $name, $grade);
            }
        }
        if (empty($graded)) {
            return null;
        }
        $clause = __('weighted by your reliability grades');
        if (!empty($zeroed)) {
            $clause .= sprintf(
                __('; %s counts for nothing, in either direction'),
                implode(', ', $zeroed)
            );
        }
        return $clause;
    }

    /**
     * An evidence line with the clause appended, where there is one.
     *
     * @param array $context
     * @param string $evidence
     * @param array $orgIds
     * @return string
     */
    public static function appendClause(array $context, $evidence,
        array $orgIds
    ) {
        $clause = self::clause($context, $orgIds);
        if ($clause === null) {
            return $evidence;
        }
        return $evidence === ''
            ? $clause
            : sprintf('%s — %s', $evidence, $clause);
    }
}
