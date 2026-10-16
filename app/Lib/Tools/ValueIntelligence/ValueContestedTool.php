<?php

/**
 * The contested layout's three keys: the two cases, and what neither
 * case could take.
 *
 * `ValueSummaryTool`'s sibling and under the same rule — pure functions
 * of a finished assessment and the context it scored, no query and no
 * view. They are together in one file because they are one
 * design: a contested record is *two arguments and the things that
 * belong to neither*, and splitting the pair across two tools would let
 * the two halves drift.
 *
 * ## The cases are the lean ledger, read twice
 *
 * A contested lean is re-anchored threat-signed before it is banded
 * (`ValueVerdictTool`'s lean-disputed check), so the **lean** ledger
 * already holds both arguments: the positive rows are what says this is
 * a threat and the negative rows are what says it is not. The cases
 * fold out of those rows and out of nothing else, which is what lets a
 * reader add up either column by hand and arrive at the tug bar above
 * it: *two derivable quantities, no third bucket, no separate
 * computation.*
 *
 * **The lean ledger and not the whole one.** Splitting every row by
 * sign would seat corroboration breadth and temporal precision inside a
 * case titled *Reads as a threat*, and every absence penalty inside one
 * titled *Reads as benign*. Those rows weigh the record; they do not
 * read the value, and a case is a reading.
 *
 * **Exactly two, in order, or none at all.** `value_verdict_conflicted`
 * reads `$cases[0]` and `$cases[1]` positionally and its tug has two
 * feet, so one case or three would not degrade — it would produce an
 * undefined index. A pair is the contract.
 *
 * ## And what neither case could take
 *
 * `conflicts` and `ambiguities` are **one derivation shown in two
 * places**, which is what makes them cheap. They are separate keys but
 * not separate facts: a contradiction the engine had to settle by rule
 * rather than by
 * evidence belongs under the ledger on the agreeing layout and under
 * the two cases on the contested one, and it is the same contradiction
 * either way. One producer, two placements, and the two cannot
 * disagree.
 *
 * What does **not** go in them is anything the ledger netted off. The
 * exact-sum invariant means a fact that moved the signal strength is visible as
 * a row and adding it here again would be double-counting in prose.
 * Only two facts on this page survive scoring without being scored, and
 * both are resolutions by rule:
 *
 *   1. An organisation holding the value **both ways** — some of its
 *      occurrences carry `to_ids` and some do not. `ValueLeanTool`
 *      counts it with the asserters, because one occurrence carrying
 *      the flag is an assertion; its other occurrences are not netted
 *      off anywhere.
 *   2. **Warninglists that disagree** about the kind of listing. When
 *      hits resolve to more than one category the context settles on
 *      `false_positive`, and the `known` reading is then carried by no
 *      signal at all.
 */
class ValueContestedTool
{
    /**
     * The two opposed cases, folded from the ledger.
     *
     * @param array $verdict What the engine returned
     * @return array Exactly two cases — threat first — or none
     */
    public static function casesFor(array $verdict)
    {
        $lean = isset($verdict['lean']) ? $verdict['lean'] : null;
        if ($lean !== 'contested') {
            /*
             * The layout is for a record arguing with itself. A
             * `threat` record with a couple of negative rows is not
             * that: its ledger agrees on balance, and splitting it into
             * two columns would present a minority of the evidence as
             * an opposed case.
             */
            return array();
        }
        $sides = array('threat' => array(), 'benign' => array());
        foreach (self::rowsOf($verdict) as $row) {
            $points = (int)$row['contribution'];
            if ($points === 0) {
                continue;
            }
            $side = $points > 0 ? 'threat' : 'benign';
            $sides[$side][] = array(
                'signal' => $row['signal'],
                'points' => abs($points),
                'evidence' => $row['evidence'],
                'kind' => $row['kind'],
                'tab' => $row['tab'],
            );
        }
        if (empty($sides['threat']) || empty($sides['benign'])) {
            /*
             * One-sided, which a contested lean can still be: the
             * lean-disputed check fires on a ledger that went negative
             * against its anchor,
             * and a record whose every row disputes its own assertion
             * has no second column to draw. The agreeing layout carries
             * it, ledger and all, which says the same thing in the
             * shape that fits it.
             */
            return array();
        }
        $cases = array();
        foreach (array('threat', 'benign') as $side) {
            usort($sides[$side], function ($a, $b) {
                return $b['points'] - $a['points'];
            });
            $cases[] = array(
                'side' => $side,
                'title' => $side === 'threat'
                    ? __('Reads as a threat')
                    : __('Reads as benign'),
                'weight' => array_sum(array_column($sides[$side],
                    'points')),
                'rows' => $sides[$side],
            );
        }
        return $cases;
    }

    /**
     * The contradictions the engine settled by rule, not by evidence.
     *
     * Same list for `conflicts` and for `ambiguities`; each item
     * carries `title`, `evidence` and `note` so the ledger row and the
     * card under the cases each read the field they were written for.
     *
     * @param array $context The context the assessment scored
     * @return array
     */
    public static function unresolvedFor(array $context)
    {
        $items = array();
        $split = self::splitOrgs($context);
        if (!empty($split)) {
            $items[] = array(
                'title' => sprintf(
                    __n(
                        'One organisation holds it both ways',
                        '%d organisations hold it both ways',
                        count($split)
                    ),
                    count($split)
                ),
                'evidence' => sprintf(
                    __('%s — some occurrences have to_ids set and some'
                        . ' do not'),
                    implode(', ', $split)
                ),
                'note' => __('Counted with the asserters, because one'
                    . ' occurrence carrying to_ids is an assertion.'
                    . ' The occurrences that do not are netted off'
                    . ' nowhere.'),
            );
        }
        $categories = self::listCategories($context);
        if (count($categories) > 1) {
            $items[] = array(
                'title' => __('The warninglists disagree about what'
                    . ' kind of listing this is'),
                'evidence' => implode(' · ', $categories),
                'note' => __('A false-positive listing outranks a'
                    . ' known-infrastructure one, so that is the'
                    . ' category the record was scored under and the'
                    . ' other reading is carried by no signal.'),
            );
        }
        return $items;
    }

    /**
     * Every ledger row, ungrouped.
     *
     * @param array $verdict
     * @return array
     */
    private static function rowsOf(array $verdict)
    {
        /*
         * The lean ledger, which is a separate list rather than the
         * positive half of the signal strength one. A case is *what reads the
         * value this way*, and splitting the whole ledger by sign would
         * put five absences — no galaxy, no first-seen, no sighting,
         * nothing recent, no feed — under a heading claiming they read
         * the value as benign, and could show them winning 23 to 22 on
         * a domain nobody had called harmless.
         *
         * On the shipped catalogue this is one-sided by construction:
         * both lean signals argue benign, so `casesFor()` finds no
         * second column and the agreeing layout carries the value with
         * the dispute stated in the lean band. That is the honest
         * shape, and the two-column layout stays for a profile whose
         * catalogue has a lean signal arguing the other way.
         */
        return isset($verdict['lean_ledger'])
            && is_array($verdict['lean_ledger'])
                ? $verdict['lean_ledger']
                : array();
    }

    /**
     * Organisations whose own occurrences disagree about `to_ids`.
     *
     * @param array $context
     * @return array Their names, widest reporter first
     */
    private static function splitOrgs(array $context)
    {
        $orgs = isset($context['orgs']) ? $context['orgs'] : array();
        $names = array();
        foreach ($orgs as $org) {
            if (!empty($org['to_ids_yes']) && !empty($org['to_ids_no'])) {
                $names[] = isset($org['name']) ? $org['name'] : '';
            }
        }
        return array_values(array_filter($names));
    }

    /**
     * The distinct categories the matched lists resolved to.
     *
     * Read off the hits rather than off the summary, because the
     * summary is the *settled* answer and the disagreement is precisely
     * what settling threw away.
     *
     * @param array $context
     * @return array
     */
    private static function listCategories(array $context)
    {
        $hits = isset($context['warninglist']['hits'])
            ? $context['warninglist']['hits']
            : array();
        $seen = array();
        foreach ($hits as $hit) {
            if (empty($hit['category'])) {
                continue;
            }
            $seen[$hit['category']] = true;
        }
        return array_keys($seen);
    }
}
