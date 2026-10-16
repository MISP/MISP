<?php
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');
/*
 * For the axis constants: `rowsById()` narrows to one axis so the two
 * exact sums stay per axis rather than over a mixture.
 */
App::uses('ValueVerdictTool', 'Tools/ValueIntelligence');

/**
 * What one profile does to a value that another does not.
 *
 * Hand it two assessments of the same value — one under the profile
 * in force, one
 * under the candidate being edited — and it returns the diff a reader
 * can check by hand: one row per ledger row, both contributions, the
 * delta, and rows that appeared or vanished marked as such.
 *
 * **This is only renderable because nothing is normalised.** The
 * exact-sum invariant means each column still
 * adds up to its own signal strength, so a diff of two ledgers is arithmetic
 * rather than impressionistic — and `sums` says so per column rather
 * than asserting it, because an invariant nobody checks is a comment.
 * A column that does not add up is reported, not hidden: it would mean
 * the engine had drifted from the one property the whole feature rests
 * on, and a simulator that showed a plausible diff over a broken ledger
 * would be the worst possible failure mode.
 *
 * No models, no `$user`, no database. Two arrays in, one array out.
 */
class ValueVerdictDiffTool
{
    /** A row present in both, with the same contribution. */
    const SAME = 'same';

    /** Present in both, contributing differently. */
    const CHANGED = 'changed';

    /** Only under the candidate. */
    const APPEARED = 'appeared';

    /** Only under the profile in force. */
    const VANISHED = 'vanished';

    /**
     * @param array $before The assessment under the profile in force
     * @param array $after The assessment under the candidate
     * @return array
     */
    public static function diff(array $before, array $after)
    {
        $beforeRows = self::rowsById($before);
        $afterRows = self::rowsById($after);
        $rows = array();
        foreach (self::mergedOrder($beforeRows, $afterRows) as $id) {
            $rows[] = self::row(
                $id,
                isset($beforeRows[$id]) ? $beforeRows[$id] : null,
                isset($afterRows[$id]) ? $afterRows[$id] : null
            );
        }
        $beforeSignalStrength = isset($before['signal_strength'])
            ? (int)$before['signal_strength']
            : 0;
        $afterSignalStrength = isset($after['signal_strength'])
            ? (int)$after['signal_strength']
            : 0;
        $beforeLean = isset($before['lean_weight'])
            ? (int)$before['lean_weight']
            : 0;
        $afterLean = isset($after['lean_weight'])
            ? (int)$after['lean_weight']
            : 0;
        $notCounted = self::notCounted($before, $after);
        $moved = array();
        foreach ($rows as $row) {
            if ($row['state'] !== self::SAME) {
                $moved[] = $row['id'];
            }
        }
        return array(
            'rows' => $rows,
            'moved' => $moved,
            /*
             * The signal strength's, and it says so: `rows` spans both axes,
             * so the deltas only sum to this over the rows
             * whose `axis` is `signal_strength`. `lean_totals` is the other
             * half, and the two together are what a reader adding the
             * table up by hand arrives at.
             */
            'totals' => array(
                'before' => $beforeSignalStrength,
                'after' => $afterSignalStrength,
                'delta' => $afterSignalStrength - $beforeSignalStrength,
            ),
            'lean_totals' => array(
                'before' => $beforeLean,
                'after' => $afterLean,
                'delta' => $afterLean - $beforeLean,
            ),
            /*
             * Per column, because the two are scored independently and a
             * drift in one is not a drift in the other. `ok` is the
             * conjunction, so a caller that only wants to know whether
             * the diff can be trusted reads one key.
             *
             * **Signal-strength rows only**: those are what sums to the
             * signal strength printed under the column. The
             * lean rows sum to `lean_weight` and are checked beside
             * them rather than folded in, which is the same invariant
             * held per axis rather than over a mixture.
             */
            'sums' => self::sums(
                self::rowsById($before, ValueVerdictTool::AXIS_SIGNAL_STRENGTH),
                self::rowsById($after, ValueVerdictTool::AXIS_SIGNAL_STRENGTH),
                $beforeSignalStrength,
                $afterSignalStrength
            ),
            'lean_sums' => self::sums(
                self::rowsById($before, ValueVerdictTool::AXIS_LEAN),
                self::rowsById($after, ValueVerdictTool::AXIS_LEAN),
                isset($before['lean_weight'])
                    ? (int)$before['lean_weight'] : 0,
                isset($after['lean_weight'])
                    ? (int)$after['lean_weight'] : 0
            ),
            'axes' => self::axes($before, $after),
            'not_counted' => $notCounted,
            'changed' => !empty($moved)
                || $beforeSignalStrength !== $afterSignalStrength
                || $beforeLean !== $afterLean
                || self::axesMoved($before, $after)
                || self::notCountedMoved($notCounted),
        );
    }

    /**
     * One value's headline under each profile — what the comparison set
     * shows per row, without the ledger.
     *
     * @param string $value
     * @param array $before
     * @param array $after
     * @return array
     */
    public static function headline($value, array $before, array $after)
    {
        $axes = self::axes($before, $after);
        $moved = self::axesMoved($before, $after);
        return array(
            'value' => $value,
            'axes' => $axes,
            'moved' => $moved,
            /*
             * Which way, so a design can colour the row without
             * asserting that the change is wrong. A signal strength that rose
             * is `up`; one that fell is `down`; a lean or band that moved
             * with the signal strength unchanged is `sideways`, which is a real
             * outcome — a clamp or a conflict rule firing differently.
             */
            'direction' => self::direction($before, $after),
        );
    }

    /**
     * @param array $before
     * @param array $after
     * @return string
     */
    private static function direction(array $before, array $after)
    {
        $delta = (int)($after['signal_strength'] ?? 0)
            - (int)($before['signal_strength'] ?? 0);
        if ($delta > 0) {
            return 'up';
        }
        if ($delta < 0) {
            return 'down';
        }
        return self::axesMoved($before, $after) ? 'sideways' : 'none';
    }

    /**
     * The three axes and the two derived words, before and after.
     *
     * `relevance` is here although the signal strength never reads it:
     * the axes are independent of each other, not invisible to a diff,
     * and a candidate that changed a TTL has changed the assessment
     * without touching a single ledger row. A diff that showed no
     * change there would be wrong about the only thing that moved.
     *
     * @param array $before
     * @param array $after
     * @return array
     */
    private static function axes(array $before, array $after)
    {
        $axes = array();
        foreach (array(
            'lean' => 'lean',
            'signal_strength' => 'signal_strength',
            /*
             * The lean's own arithmetic, which the signal strength cannot stand
             * in for because the two are separate sums. An edit to a
             * lean signal's weight moves this and nothing else, so a
             * headline without it would report *nothing changed* about
             * the two signals that decide the reading.
             */
            'lean_weight' => 'lean_weight',
            'band' => 'band',
            'rule' => 'rule',
        ) as $key => $path) {
            $axes[$key] = self::pair(
                isset($before[$path]) ? $before[$path] : null,
                isset($after[$path]) ? $after[$path] : null
            );
        }
        /*
         * The relevance axis travels as three things at once, because a
         * word is not enough for the surface that draws it: the
         * comparable state a diff can test, the label a reader sees,
         * and the runway — the shelf the value page already draws. A
         * caller handed only the state reduces the axis to a string,
         * and renders a clock as a word while signal strength gets a bar.
         */
        $axes['relevance'] = self::pair(
            self::relevanceState($before),
            self::relevanceState($after)
        ) + array(
            'label' => ValueRelevanceTool::stateLabel(
                isset($after['relevance']['state'])
                    ? $after['relevance']['state']
                    : null
            ),
            'runway' => isset($after['relevance'])
                && is_array($after['relevance'])
                ? $after['relevance']
                : null,
        );
        $axes['fired'] = self::pair(
            isset($before['signals']['fired'])
                ? (int)$before['signals']['fired']
                : null,
            isset($after['signals']['fired'])
                ? (int)$after['signals']['fired']
                : null
        );
        return $axes;
    }

    /**
     * The relevance axis as one comparable word plus its flag, since
     * the state is one word and the uncertainty also a flag —
     * *"expired · timeline uncertain"* is two of them at once.
     *
     * @param array $verdict
     * @return string|null
     */
    private static function relevanceState(array $verdict)
    {
        if (!isset($verdict['relevance'])
            || !is_array($verdict['relevance'])
        ) {
            return null;
        }
        $relevance = $verdict['relevance'];
        $state = isset($relevance['state']) ? $relevance['state'] : null;
        if ($state === null) {
            return null;
        }
        /*
         * The flag is appended only where it adds something. `expired ·
         * uncertain` is the intended reading — two states at once — but
         * the axis also has `uncertain` as a state in its own right,
         * and appending the flag there would print *"uncertain ·
         * uncertain"*, handing a design the same word twice and leaving
         * it to decide what it means.
         */
        if (empty($relevance['uncertain']) || $state === 'uncertain') {
            return $state;
        }
        return $state . ' · uncertain';
    }

    /**
     * @param mixed $before
     * @param mixed $after
     * @return array
     */
    private static function pair($before, $after)
    {
        return array(
            'before' => $before,
            'after' => $after,
            'changed' => $before !== $after,
        );
    }

    /**
     * @param array $before
     * @param array $after
     * @return bool
     */
    private static function axesMoved(array $before, array $after)
    {
        foreach (self::axes($before, $after) as $axis) {
            if ($axis['changed']) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array $notCounted
     * @return bool
     */
    private static function notCountedMoved(array $notCounted)
    {
        foreach ($notCounted as $entry) {
            if ($entry['state'] !== self::SAME) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $id
     * @param array|null $before
     * @param array|null $after
     * @return array
     */
    private static function row($id, $before, $after)
    {
        $present = $after !== null ? $after : $before;
        $beforeValue = $before === null
            ? null
            : (int)$before['contribution'];
        $afterValue = $after === null
            ? null
            : (int)$after['contribution'];
        if ($before === null) {
            $state = self::APPEARED;
        } elseif ($after === null) {
            $state = self::VANISHED;
        } elseif ($beforeValue === $afterValue) {
            $state = self::SAME;
        } else {
            $state = self::CHANGED;
        }
        return array(
            'id' => $id,
            'signal' => isset($present['signal']) ? $present['signal'] : $id,
            'group' => isset($present['kind']) ? $present['kind'] : null,
            /*
             * Which axis the row's points land on, carried so a caller
             * can sum per axis — `totals` is the signal strength's, and a lean
             * row's delta does not belong in it. Defaulted rather than
             * required, because a row that carries no axis is a
             * signal-strength row by construction.
             */
            'axis' => isset($present['axis'])
                ? $present['axis']
                : ValueVerdictTool::AXIS_SIGNAL_STRENGTH,
            /*
             * The candidate's prose where there is one. A row whose
             * points changed usually says something different about the
             * same evidence — *"4 organisations"* is the same sentence,
             * but a threshold in `config` can change the sentence too —
             * and the reader is deciding about the candidate.
             */
            'signal_before' => $before === null
                ? null
                : (isset($before['signal']) ? $before['signal'] : null),
            'evidence' => isset($present['evidence'])
                ? $present['evidence']
                : null,
            'before' => $beforeValue,
            'after' => $afterValue,
            'delta' => (int)$afterValue - (int)$beforeValue,
            'state' => $state,
        );
    }

    /**
     * Every ledger row of one assessment, keyed by signal id and
     * flattened out of its groups.
     *
     * **Public because the editor's Signals palette needs the same
     * answer**, and a second hand-rolled traversal — one walking
     * `ledger` alone — would miss the lean rows. One traversal, so the
     * next change to the ledger's shape has one place to reach.
     *
     * A signal returning several rows — `attribution.galaxy`'s
     * occurrence and event clusters, `enrichment.answer`'s verdicts —
     * keys its second and later rows `id#2`, `id#3`, so every row is
     * diffed and summed; each row keeps its own `id`.
     *
     * @param array $verdict
     * @param string|null $axis One of `ValueVerdictTool`'s axis
     *                          constants to take only that ledger;
     *                          null for both
     * @return array id => the row
     */
    public static function rowsById(array $verdict, $axis = null)
    {
        $rows = array();
        $ledger = isset($verdict['ledger']) && is_array($verdict['ledger'])
            ? $verdict['ledger']
            : array();
        if ($axis !== ValueVerdictTool::AXIS_LEAN) {
            foreach ($ledger as $group) {
                if (empty($group['signals'])) {
                    continue;
                }
                foreach ($group['signals'] as $row) {
                    $id = isset($row['id']) ? $row['id'] : null;
                    if ($id === null) {
                        continue;
                    }
                    $rows[self::rowKey($rows, $id)] = $row;
                }
            }
        }
        /*
         * **And the lean ledger**, which lives apart from `ledger`.
         * Skipping it would be the worst kind of failure for a
         * simulator: an analyst halving `lifecycle.warninglist` — the
         * heaviest row on a benign record — would get a diff of rows
         * all marked *same* and a headline saying `moved: false`. The
         * editor's whole job is to answer *what does this edit do*, and
         * it would answer *nothing* about the two signals that decide
         * the lean.
         *
         * `$axis` narrows it for the sums below, which still have to be
         * per axis: the signal-strength rows sum to the signal strength and the
         * lean rows to `lean_weight`, and adding the two together would
         * report a drift that is not there.
         */
        if ($axis !== ValueVerdictTool::AXIS_SIGNAL_STRENGTH) {
            $lean = isset($verdict['lean_ledger'])
                && is_array($verdict['lean_ledger'])
                    ? $verdict['lean_ledger']
                    : array();
            foreach ($lean as $row) {
                $id = isset($row['id']) ? $row['id'] : null;
                if ($id === null) {
                    continue;
                }
                $rows[self::rowKey($rows, $id)] = $row;
            }
        }
        return $rows;
    }

    /**
     * The key for the next row of signal `$id`.
     *
     * @param array $rows The rows keyed so far
     * @param string $id
     * @return string
     */
    private static function rowKey(array $rows, $id)
    {
        if (!isset($rows[$id])) {
            return $id;
        }
        $n = 2;
        while (isset($rows[$id . '#' . $n])) {
            $n++;
        }
        return $id . '#' . $n;
    }

    /**
     * The union of two row sets, in the candidate's order with the
     * profile-in-force's leftovers appended.
     *
     * The candidate leads because it is what the reader is deciding
     * about; a vanished row has no position of its own to keep, so it
     * goes after the rows that are still there rather than into a
     * position the new ledger never had.
     *
     * @param array $before
     * @param array $after
     * @return array
     */
    private static function mergedOrder(array $before, array $after)
    {
        $order = array_keys($after);
        foreach (array_keys($before) as $id) {
            if (!in_array($id, $order, true)) {
                $order[] = $id;
            }
        }
        return $order;
    }

    /**
     * Whether each column adds up to the signal strength printed under it.
     *
     * @param array $beforeRows
     * @param array $afterRows
     * @param int $beforeSignalStrength
     * @param int $afterSignalStrength
     * @return array
     */
    private static function sums(array $beforeRows, array $afterRows,
        $beforeSignalStrength, $afterSignalStrength
    ) {
        $beforeSum = 0;
        foreach ($beforeRows as $row) {
            $beforeSum += (int)$row['contribution'];
        }
        $afterSum = 0;
        foreach ($afterRows as $row) {
            $afterSum += (int)$row['contribution'];
        }
        return array(
            'before' => array(
                'ledger' => $beforeSum,
                'signal_strength' => $beforeSignalStrength,
                'ok' => $beforeSum === $beforeSignalStrength,
            ),
            'after' => array(
                'ledger' => $afterSum,
                'signal_strength' => $afterSignalStrength,
                'ok' => $afterSum === $afterSignalStrength,
            ),
            'ok' => $beforeSum === $beforeSignalStrength
                && $afterSum === $afterSignalStrength,
        );
    }

    /**
     * What each assessment could not count, and what moved between them.
     *
     * This is half the diff on an exclusions edit: switching `orgs.own`
     * on moves rows out of every aggregate and into a policy note, and
     * a diff that only compared ledgers would show a signal-strength drop with
     * nothing to attribute it to.
     *
     * @param array $before
     * @param array $after
     * @return array
     */
    private static function notCounted(array $before, array $after)
    {
        $beforeEntries = self::notCountedById($before);
        $afterEntries = self::notCountedById($after);
        $out = array();
        foreach (self::mergedOrder($beforeEntries, $afterEntries) as $key) {
            $b = isset($beforeEntries[$key]) ? $beforeEntries[$key] : null;
            $a = isset($afterEntries[$key]) ? $afterEntries[$key] : null;
            $present = $a !== null ? $a : $b;
            if ($b === null) {
                $state = self::APPEARED;
            } elseif ($a === null) {
                $state = self::VANISHED;
            } else {
                $state = ($b['note'] ?? null) === ($a['note'] ?? null)
                    ? self::SAME
                    : self::CHANGED;
            }
            $out[] = array(
                'id' => $key,
                'title' => isset($present['title'])
                    ? $present['title']
                    : $key,
                'reason' => isset($present['reason'])
                    ? $present['reason']
                    : null,
                'source' => isset($present['source'])
                    ? $present['source']
                    : null,
                'before' => $b === null
                    ? null
                    : (isset($b['note']) ? $b['note'] : ''),
                'after' => $a === null
                    ? null
                    : (isset($a['note']) ? $a['note'] : ''),
                'state' => $state,
            );
        }
        return $out;
    }

    /**
     * `not_counted` keyed by whatever identifies an entry.
     *
     * A signal entry carries `id`; a policy note carries the exclusion's
     * id; a budget note may carry neither, and falls back to its title —
     * which is stable for the same reason the note exists at all.
     *
     * @param array $verdict
     * @return array
     */
    private static function notCountedById(array $verdict)
    {
        $entries = array();
        $list = isset($verdict['not_counted'])
            && is_array($verdict['not_counted'])
            ? $verdict['not_counted']
            : array();
        foreach ($list as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $key = !empty($entry['id'])
                ? (string)$entry['id']
                : (isset($entry['title']) ? (string)$entry['title'] : null);
            if ($key === null || $key === '') {
                continue;
            }
            $entries[$key] = $entry;
        }
        return $entries;
    }
}
