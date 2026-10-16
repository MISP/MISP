<?php

/**
 * What the ledger's total banded as, and against what.
 *
 * The smallest of the axis explanations, because signal strength is the axis
 * that already shows its working: the ledger prints every signal and
 * its points, and the invariant is that those rows sum to the number
 * in the hero exactly. Nothing about the arithmetic is missing.
 *
 * **The band is.** A reader sees `Signal strength low · 19 / 100` and a ledger
 * summing to 19, and nothing else on the page says what `low` means —
 * where `medium` starts, how far off this record is, or whether the
 * points are even what decided it. Lean names its supermajority and
 * relevance its TTL; this names the setting signal strength is banded by.
 *
 * **And twice the band is not the points at all.** The thin-record
 * clamp lowers it — a record with one source and no sightings cannot
 * pass `low` however well it scores — and `signal_strength_high_min_signals`
 * holds it — points past the `high` floor on too few independent
 * readings stay `medium`. Both are stated in the profile, both are
 * deliberate, and a reader meeting either sees a number and a band
 * that contradict each other with no explanation in sight. The
 * falsifiability card says what would *change* it, which is a
 * different sentence from what *happened*.
 *
 * `ValueLeanReasonTool`'s sibling, and the same contract: a pure
 * function of the array the engine returned, so a test harness can
 * reach the two reasons real data rarely occupies — the clamp needs a
 * single-source record scoring past 30.
 */
class ValueBandReasonTool
{
    /**
     * The sentence for one assessment's band.
     *
     * @param array $verdict What the engine returned
     * @return string|null Null where the ledger's own empty state has
     *                     already said it
     */
    public static function reasonFor(array $verdict)
    {
        $reason = isset($verdict['band_reason']['reason'])
            ? $verdict['band_reason']['reason']
            : null;
        $floors = isset($verdict['band_reason']['floors'])
            && is_array($verdict['band_reason']['floors'])
            ? $verdict['band_reason']['floors']
            : array();
        if ($reason === null || $reason === 'no_signal') {
            /*
             * *No signal contributed to this assessment* is already
             * the ledger's empty state, in the place a reader is
             * looking when they want it; a second sentence under an
             * empty table would only repeat it.
             */
            return null;
        }

        $band = isset($verdict['band']) ? $verdict['band'] : 'none';
        $supporting = (int)(isset($verdict['signals']['supporting'])
            ? $verdict['signals']['supporting'] : 0);
        $high = (int)(isset($floors['high']) ? $floors['high'] : 60);

        switch ($reason) {
            case 'clamped':
                /*
                 * The one case where the number on the page and the
                 * band on the page are not the same statement, so it
                 * says both: what the points band as, and what is
                 * overriding them. Phrased as the profile's rule
                 * rather than as a fact about the value — an analyst
                 * who disagrees edits three numbers.
                 */
                if (!empty($floors['clamp_grade'])) {
                    return sprintf(
                        __('The points alone would make this %1$s. This'
                            . ' profile holds a single-source record'
                            . ' graded %2$s that nothing independent'
                            . ' confirms at %3$s.'),
                        self::bandWord(isset($floors['would_be'])
                            ? $floors['would_be'] : 'medium'),
                        $floors['clamp_grade'],
                        self::bandWord($band)
                    );
                }
                return sprintf(
                    __('The points alone would make this %1$s. This'
                        . ' profile holds a single-source record that'
                        . ' nothing independent confirms at %2$s.'),
                    self::bandWord(isset($floors['would_be'])
                        ? $floors['would_be'] : 'medium'),
                    self::bandWord($band)
                );

            case 'min_signals':
                return sprintf(
                    __n(
                        'The points reach %1$s (%2$s), but %1$s needs'
                            . ' %3$s signals adding points and only %4$s'
                            . ' does.',
                        'The points reach %1$s (%2$s), but %1$s needs'
                            . ' %3$s signals adding points and only %4$s'
                            . ' do.',
                        $supporting
                    ),
                    self::bandWord('high'),
                    $high,
                    (int)(isset($floors['min_signals'])
                        ? $floors['min_signals'] : 4),
                    $supporting
                );
        }

        /*
         * The ordinary case says nothing: the hero's bar marks every
         * floor already.
         */
        return null;
    }

    /**
     * A band, as the page says it.
     *
     * One writer, for the same reason `ValueRelevanceTool::stateLabel()`
     * is one: the hero, the ledger's foot and the falsifiability card
     * all name bands, and the copy that does not get updated is the one
     * that prints the stored key.
     *
     * @param string|null $band
     * @return string
     */
    public static function bandWord($band)
    {
        $words = array(
            'none' => __('none'),
            'low' => __('low'),
            'medium' => __('medium'),
            'high' => __('high'),
        );
        return isset($words[$band]) ? $words[$band] : (string)$band;
    }
}
