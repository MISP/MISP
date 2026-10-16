<?php

App::uses('ValueStatementTool', 'Tools/ValueIntelligence');

/**
 * Why the lean is the lean, in one sentence.
 *
 * `ValueSummaryTool`'s sibling and `ValueChangersTool`'s: all three
 * turn a finished assessment into English, all three are pure
 * functions of the array the engine returned, and none of them touches
 * a database or a view. Staying pure is what lets a test harness reach
 * the exits no instance happens to occupy.
 *
 * **Nine exits.** `ValueLeanTool::leanFor()` has eight and
 * `ValueVerdictTool`'s lean-disputed check is the ninth — the only one
 * decided *after* the ledger, and without its own sentence it would
 * borrow the sentence of the lean it had just overturned.
 *
 * **Voices get a second sentence.** Once a dispute or a grade enters
 * the count the headcounts stop adding up to the share,
 * and *10 of 11 organisations assert this is a threat* under a
 * contested-looking false positive says nothing about why it did not
 * flip. `voicesSentence()` names the weights and every dispute.
 *
 * **Why every exit gets a sentence.** Of `leanFor()`'s seven exits only
 * a loaded escalation produces prose of its own. Without this, an
 * ordinary value would state *Asserted threat* and never say by whom,
 * on what count, or against which threshold — *Asserted threat,
 * signal strength 19* with a provenance line carrying only *Computed at render
 * · Analyst profile default-v1*. The stances that decide it —
 * `threat_orgs`, `benign_orgs`, the share and the supermajority in
 * force — are computed on every value, and this is what reads them.
 *
 * **It reads the exit rather than re-deriving it.** `decided_by` is
 * the engine's own name for the branch it took, and the false-positive
 * listing and the benign supermajority are why that matters: both
 * answer `benign`, and which one a value takes depends on an order of
 * writing that is invisible from outside the function.
 *
 * **Nothing here is a second opinion.** Every clause names a key the
 * engine emitted. A sentence disagreeing with the badge above it or
 * the organisations table below it would be a defect in the wording,
 * not a second computation.
 *
 * **It says what the record asserts, never what the value is.**
 * *Organisations assert this is a threat* is
 * a statement about the record; *this is a threat* is the claim an
 * engine reading MISP tables cannot make.
 */
class ValueLeanReasonTool
{
    /**
     * The sentence for one assessment.
     *
     * @param array $verdict What the engine returned
     * @return string|null Null where there is nothing to say — an
     *                     unnamed exit, or the empty record, whose hero
     *                     has already said it
     */
    public static function reasonFor(array $verdict)
    {
        $decidedBy = isset($verdict['decided_by'])
            ? $verdict['decided_by']
            : null;
        $stances = isset($verdict['stances'])
            && is_array($verdict['stances'])
            ? $verdict['stances']
            : array();
        if ($decidedBy === null || $decidedBy === 'nothing_visible') {
            return null;
        }
        $sentence = self::exitSentence($decidedBy, $verdict, $stances);
        if ($sentence === null) {
            return null;
        }
        $context = $decidedBy === 'unflagged'
            ? null
            : self::contextSentence($stances);
        if ($context !== null) {
            $sentence .= ' ' . $context;
        }
        $voices = self::voicesSentence($stances);
        return $voices === null ? $sentence : $sentence . ' ' . $voices;
    }

    /**
     * The reporters that recorded the value as context only, which the
     * counts above leave out: three organisations flagging it
     * and five recording it with `to_ids` off reads 3 of 3, and the
     * five are named here rather than vanishing.
     *
     * @param array $stances
     * @return string|null
     */
    private static function contextSentence(array $stances)
    {
        $count = (int)($stances['unflagged_orgs'] ?? 0);
        if ($count <= 0) {
            return null;
        }
        return sprintf(
            __n(
                '%d more organisation recorded it as context, not for'
                    . ' detection, and casts no vote.',
                '%d more organisations recorded it as context, not for'
                    . ' detection, and cast no vote.',
                $count
            ),
            $count
        );
    }

    /**
     * The sentence for the exit itself.
     *
     * @param string $decidedBy
     * @param array $verdict
     * @param array $stances
     * @return string|null
     */
    private static function exitSentence($decidedBy, array $verdict,
        array $stances
    ) {
        $threat = (int)(isset($stances['threat_orgs'])
            ? $stances['threat_orgs'] : 0);
        $benign = (int)(isset($stances['benign_orgs'])
            ? $stances['benign_orgs'] : 0);
        $total = (int)(isset($stances['orgs'])
            ? $stances['orgs'] : $threat + $benign);
        $threshold = self::thresholdLabel($stances);

        switch ($decidedBy) {
            case 'no_voice':
                $names = isset($stances['abstained'])
                    && is_array($stances['abstained'])
                    ? $stances['abstained']
                    : array();
                return empty($names)
                    ? __('Every organisation that reported this is graded'
                        . ' to count for nothing, so no stance is'
                        . ' counted.')
                    : sprintf(
                        __('Every organisation that reported this is'
                            . ' graded to count for nothing (%s), so no'
                            . ' stance is counted.'),
                        implode(', ', $names)
                    );

            case 'unflagged':
                $count = (int)($stances['unflagged_orgs'] ?? 0);
                return sprintf(
                    __n(
                        'The %d organisation that reported this recorded'
                            . ' it as context: nobody flagged it for'
                            . ' detection, and nobody said it is'
                            . ' harmless.',
                        'The %d organisations that reported this all'
                            . ' recorded it as context: nobody flagged'
                            . ' it for detection, and nobody said it is'
                            . ' harmless.',
                        $count
                    ),
                    $count
                );

            case 'escalation':
                /*
                 * The one exit that already has prose, and it is
                 * better prose than this file could write: the rule
                 * was authored for exactly this value's shape. The
                 * provenance line carries the rule itself, so this
                 * says only which exit was taken rather than two
                 * sentences saying one thing.
                 */
                return __('A conflict rule decided this reading.');

            case 'false_positive_listed':
                /*
                 * The false-positive listing. The warninglist band
                 * beside this one names the list; what it cannot say
                 * is that the organisations were *given the chance* to
                 * override it and did not reach the bar.
                 */
                /*
                 * *The threat stances run 1 of 2* rather than *1 of 2
                 * assert*, and `no_supermajority` below takes the same
                 * treatment for the same reason: these two exits are
                 * the ones where the numerator can be 1 under a plural
                 * total, and a verb after it agrees with neither
                 * consistently. `__n()` cannot help — it picks one
                 * plural form for the whole string, and the
                 * `no_supermajority` sentence has two counts that
                 * disagree about which form they want. The two
                 * supermajority exits keep their verb because a
                 * supermajority guarantees the numerator is plural
                 * whenever the total is.
                 */
                return sprintf(
                    __('A warninglist marks this a false positive, and'
                        . ' only %1$s of %2$s organisations call it a'
                        . ' threat, short of this profile\'s %3$s bar.'),
                    $threat,
                    $total,
                    $threshold
                );

            case 'false_positive_floor':
                return sprintf(
                    __n(
                        'A warninglist marks this a false positive, and'
                            . ' only %1$s organisation calls it a threat;'
                            . ' this profile wants %2$s before that'
                            . ' contradicts the list.',
                        'A warninglist marks this a false positive, and'
                            . ' only %1$s organisations call it a threat;'
                            . ' this profile wants %2$s before that'
                            . ' contradicts the list.',
                        $threat
                    ),
                    $threat,
                    (int)($stances['listed_floor'] ?? 0)
                );

            case 'threat_supermajority':
                return sprintf(
                    __n(
                        '%1$s of %2$s organisation asserts this is a'
                            . ' threat, meeting this profile\'s %3$s'
                            . ' bar.',
                        '%1$s of %2$s organisations assert this is a'
                            . ' threat, meeting this profile\'s %3$s'
                            . ' bar.',
                        $total
                    ),
                    $threat,
                    $total,
                    $threshold
                );

            case 'benign_supermajority':
                return sprintf(
                    __n(
                        '%1$s of %2$s organisation reports this as'
                            . ' harmless, meeting this profile\'s %3$s'
                            . ' bar.',
                        '%1$s of %2$s organisations report this as'
                            . ' harmless, meeting this profile\'s %3$s'
                            . ' bar.',
                        $total
                    ),
                    $benign,
                    $total,
                    $threshold
                );

            case 'lean_disputed':
                /*
                 * The lean-disputed check. It is not one of
                 * `leanFor()`'s seven — the lean it names was counted
                 * there and then overturned by the ledger, which is
                 * why `ValueVerdictTool` rewrites `decided_by` on its
                 * way out. Without that the band would print the
                 * *overturned* reading's sentence: a **Contested**
                 * badge over *2 of 2 organisations report this as
                 * harmless*.
                 *
                 * It names the counted lean rather than hiding it,
                 * because that half is still true and is what the
                 * stance bar directly above is drawing.
                 */
                $counted = isset($verdict['derived_lean'])
                    ? $verdict['derived_lean']
                    : null;
                if ($counted === 'benign') {
                    return __('The organisations report this as'
                        . ' harmless, but a warninglist argues'
                        . ' threat.');
                }
                if ($counted === 'threat') {
                    return __('The organisations call this a threat,'
                        . ' but a warninglist argues harmless.');
                }
                return __('A warninglist disputes what the'
                    . ' organisations reported.');

            case 'no_supermajority':
                /*
                 * No supermajority, and the exit that most needs a
                 * sentence. A value drawn as contested with two cases
                 * beside each other, where the reason is *neither side
                 * reached the bar* — which no other surface on this
                 * page says, so the contested layout would explain
                 * itself only on the values an escalation happened to
                 * catch.
                 */
                return sprintf(
                    __('Neither side reaches this profile\'s %1$s bar'
                        . ' (%2$s to %3$s).'),
                    $threshold,
                    $threat,
                    $benign
                );
        }

        return null;
    }

    /**
     * How the voices were weighed, where that is not simply one per
     * organisation.
     *
     * Null on the ordinary record — nobody graded, no dispute, no
     * verdict — whose headcounts already are the share.
     *
     * @param array $stances
     * @return string|null
     */
    private static function voicesSentence(array $stances)
    {
        $disputes = isset($stances['disputes'])
            && is_array($stances['disputes'])
            ? $stances['disputes']
            : array();
        if (empty($disputes) && empty($stances['weighted'])) {
            return null;
        }
        $threat = (float)($stances['threat_voices'] ?? 0);
        $benign = (float)($stances['benign_voices'] ?? 0);
        if ($threat + $benign <= 0.0) {
            return null;
        }
        $sentence = sprintf(
            empty($stances['weighted'])
                ? __('Counted as voices, %1$s for threat and %2$s'
                    . ' against: %3$s%% threat.')
                : __('Counted as voices weighted by your reliability'
                    . ' grades, %1$s for threat and %2$s against: %3$s%%'
                    . ' threat.'),
            self::voiceCount($threat),
            self::voiceCount($benign),
            (int)round((float)($stances['threat_share'] ?? 0) * 100)
        );
        $named = array();
        foreach ($disputes as $dispute) {
            $named[] = self::disputePhrase($dispute);
        }
        if (!empty($named)) {
            $sentence .= ' ' . sprintf(
                __('Among them: %s.'),
                implode('; ', $named)
            );
        }
        return $sentence;
    }

    /**
     * One dispute or verdict, as the voices sentence lists it.
     *
     * @param array $dispute
     * @return string
     */
    private static function disputePhrase(array $dispute)
    {
        $weight = self::voiceCount((float)($dispute['weight'] ?? 0));
        if (($dispute['kind'] ?? null) === 'enrichment') {
            return sprintf(
                __('%1$s said %2$s (weight %3$s)'),
                $dispute['module'],
                $dispute['word'],
                $weight
            );
        }
        $who = empty($dispute['name'])
            ? __('an organisation not named to you')
            : $dispute['name'];
        if (($dispute['kind'] ?? null) === 'warning') {
            return sprintf(
                __('%1$s warns of %2$s on its own report (weight %3$s)'),
                $who,
                ValueStatementTool::warningLabel($dispute['tag'] ?? ''),
                $weight
            );
        }
        if (!empty($dispute['withdrawn'])) {
            $phrase = sprintf(
                __('%s filed a false positive on its own report'),
                $who
            );
        } else {
            $phrase = sprintf(__('a false positive from %s'), $who);
        }
        if (!empty($dispute['stale'])) {
            $phrase .= ' ' . __('before others reasserted it');
        }
        return sprintf(__('%1$s (weight %2$s)'), $phrase, $weight);
    }

    /**
     * A voice total as a reader meets it: whole where it is whole,
     * otherwise to two places.
     *
     * @param float $count
     * @return string
     */
    private static function voiceCount($count)
    {
        $rounded = round((float)$count, 2);
        return $rounded == floor($rounded)
            ? (string)(int)$rounded
            : rtrim(rtrim(number_format($rounded, 2, '.', ''), '0'),
                '.');
    }

    /**
     * The supermajority, as a reader meets it.
     *
     * A percentage rather than the stored fraction, and rounded: the
     * shipped default is `0.66`, which is *not* two thirds, so spelling
     * it *two thirds* would print a threshold the engine does not use.
     * `66%` is what it is.
     *
     * @param array $stances
     * @return string
     */
    private static function thresholdLabel(array $stances)
    {
        $share = isset($stances['supermajority'])
            && is_numeric($stances['supermajority'])
            ? (float)$stances['supermajority']
            : null;
        if ($share === null) {
            return __('majority');
        }
        return sprintf(__('%s%%'), (int)round($share * 100));
    }
}
