<?php
/**
 * The dates the relevance axis is built on, side by side.
 *
 * Three bugs in this feature were one column being read as another: an
 * encoding lag measured off a last-modified timestamp
 * (`06-staleness.md` §7.11), an uncertainty flag that ignored the
 * sighting its own clock was running on (§7.12), and a clock an edit
 * could reset (§7.13). All three were **invisible from the card**,
 * because the card showed conclusions and the conclusions looked
 * reasonable. This is the working: what each date means, the column it
 * comes from, and what this value actually has.
 *
 * **Two panes render it**, and that is why it is an element rather than
 * markup in one of them. The value page's Lifetime card explains a
 * value; the profile editor's bench explains the same value under the
 * knobs that produce these numbers, and a reader tuning
 * `undated_assumed_days` is exactly the reader who needs to know
 * whether this value declares a `first_seen` at all.
 *
 * Folded shut. The card above is the answer; this is reference material
 * for the moment somebody disbelieves it.
 *
 * @var array $facts From `Value::timelineFactsFor()`
 * @var string|null $clockKind The clock event's kind
 * @var string $clockLabel The clock setting, in words
 * @var int|null $lastSighting Newest `date_sighting`, or null
 * @var int $sightingTotal
 */
$lastSighting = isset($lastSighting) ? $lastSighting : null;
$sightingTotal = isset($sightingTotal) ? (int)$sightingTotal : 0;
?>
<?php
$day = function ($stamp) {
    return $stamp === null
        ? null
        : date('Y-m-d', (int)$stamp);
};
$held = $clockKind;
/*
 * Which row the clock actually read — and the two
 * directions matter here, because they disagree.
 * `org_joined` resolves through `Value::observedFrom()`,
 * which asks `first_seen` first; `occurrence` and the
 * fallback resolve through `observedAt()`, which asks
 * `last_seen` first. Marking `first_seen` for both put
 * the badge on 2026-03-03 beside a card reading *added
 * 2026-03-25*, which is the table contradicting the
 * line it exists to explain.
 *
 * Each chain then falls through to the row that is
 * actually populated: naming a column nothing set would
 * point the badge at an empty cell.
 */
$chain = $held === 'org_joined'
    ? array('first_seen', 'last_seen')
    : array('last_seen', 'first_seen');
$declared = array(
    'first_seen' => $facts['with_first_seen'] > 0,
    'last_seen' => $facts['with_last_seen'] > 0,
);
$usedRow = empty($facts['created_at']) ? 'written' : 'created';
if (in_array($held, array('sighting', 'foreign_sighting'),
    true)
) {
    $usedRow = 'sighting';
} else {
    foreach ($chain as $candidate) {
        if (!empty($declared[$candidate])) {
            $usedRow = $candidate;
            break;
        }
    }
}

$rows = array(
    array(
        'key' => 'first_seen',
        'what' => __('First observed'),
        'from' => array('Attribute', 'first_seen'),
        'value' => $day($facts['first_seen']),
        'note' => $facts['occurrences'] > 0
            ? sprintf(
                __('%1$s of %2$s occurrences'),
                $facts['with_first_seen'],
                $facts['occurrences']
            )
            : null,
    ),
    array(
        'key' => 'last_seen',
        'what' => __('Last observed'),
        'from' => array('Attribute', 'last_seen'),
        'value' => $day($facts['last_seen']),
        'note' => $facts['occurrences'] > 0
            ? sprintf(
                __('%1$s of %2$s occurrences'),
                $facts['with_last_seen'],
                $facts['occurrences']
            )
            : null,
    ),
    array(
        'key' => 'sighting',
        'what' => __('Last sighted'),
        'from' => array('Sighting', 'date_sighting'),
        'value' => $day($lastSighting),
        'note' => empty($sightingTotal)
            ? null
            : sprintf(
                __n(
                    '%s sighting',
                    '%s sightings',
                    $sightingTotal
                ),
                $sightingTotal
            ),
    ),
    array(
        'key' => 'created',
        'what' => __('Recorded'),
        'from' => array('Attribute', 'creation_datetime'),
        'value' => $day($facts['created_at'] ?? null),
        'absent' => __('MISP stores no creation date for'
            . ' an attribute yet'),
    ),
    array(
        'key' => 'written',
        'what' => __('Row last written'),
        'from' => array('Attribute', 'timestamp'),
        'value' => $day($facts['written_last']),
        'note' => __('moves on any edit'),
    ),
    array(
        'key' => 'event_date',
        'what' => __('Event date'),
        'from' => array('Event', 'date'),
        'value' => $facts['event_date_last'],
        'note' => __('typed by an analyst'),
    ),
    array(
        'key' => 'published',
        'what' => __('Published'),
        'from' => array('Event', 'publish_timestamp'),
        'value' => $day($facts['published_last']),
        'note' => sprintf(
            __('%1$s of %2$s events'),
            $facts['published_events'],
            $facts['events']
        ),
    ),
);
?>
<details class="vp-dates">
    <summary>
        <?= h(__('The dates behind this')) ?>
        <span class="vp-dates-sub"><?= h(sprintf(
            __('the clock read %s'),
            $clockLabel
        )) ?></span>
    </summary>
    <table class="vp-dates-tbl">
        <thead>
            <tr>
                <th><?= h(__('What it is')) ?></th>
                <th><?= h(__('Where it comes from')) ?></th>
                <th><?= h(__('This value')) ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($rows as $row): ?>
                <tr class="<?= $row['key'] === $usedRow
                    ? 'is-held'
                    : '' ?><?= $row['value'] === null
                        ? ' is-absent'
                        : '' ?>">
                    <td>
                        <?= h($row['what']) ?>
                        <?php if ($row['key'] === $usedRow): ?>
                            <span class="vp-dates-held"
                                  title="<?= h(__('The'
                                      . ' date the clock'
                                      . ' above is'
                                      . ' measured'
                                      . ' from.')) ?>"><?=
                                h(__('clock')) ?></span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php
                        /*
                         * Split at the dot, with a
                         * `wbr` in the gap: the rail is
                         * ~150px of column and
                         * `Sighting.date_sighting`
                         * wrapped one character from
                         * its end, which reads as a
                         * typo rather than as a wrap.
                         */
                        ?>
                        <code><?=
                            h($row['from'][0]) ?>.<wbr><?=
                            h($row['from'][1]) ?></code>
                    </td>
                    <td>
                        <?php if ($row['value'] !== null): ?>
                            <span class="vp-dates-when"><?=
                                h($row['value']) ?></span>
                        <?php else: ?>
                            <span class="vp-dates-none"><?=
                                h(isset($row['absent'])
                                    ? $row['absent']
                                    : __('not set')) ?></span>
                        <?php endif; ?>
                        <?php if (!empty($row['note'])): ?>
                            <span class="vp-dates-note"><?=
                                h($row['note']) ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <p class="vp-dates-foot">
        <?= h(__('Only the first three are observations.'
            . ' The rest record when MISP was written'
            . ' to, which is always later and moves'
            . ' again on every edit — so the clock takes'
            . ' them only when nothing better exists.')) ?>
    </p>
</details>
