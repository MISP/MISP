<?php
/**
 * A short timeline of spans, in lanes, over one shared axis.
 *
 * **Why this is not the Timeline tab's lane grid.** It draws the same
 * marks and deliberately borrows the same CSS — `.vp-lanes`,
 * `.vp-lane-axis`, `.vp-lane-span`, and the `--vp-tl-…` palette — because
 * a span here and a span there must not look like two different claims.
 * What differs is everything around the marks: that grid is redrawn in
 * JavaScript from a JSON feed, over a rolling twelve-month window a
 * brush moves, across eight fixed sources. This one is rendered by the
 * server over **the data's own extent**, with lanes the caller names,
 * and it follows whatever narrowing the surrounding `[data-vp-list]`
 * applies. Sharing the stylesheet and not the machinery is the part
 * that keeps them honest.
 *
 * **The axis is the extent and not a calendar.** A resolution history
 * that ran 2013→2018 is an empty strip under a twelve-month axis, and
 * the reading a span strip exists for — *four addresses in fourteen
 * days, four years of nothing, then one more* — is only visible when
 * the axis is as long as the story.
 *
 * **Every span names its row.** `entries[].key` is the key the table row
 * carries in `data-vp-span-key`, so `VP.spanStrip` can dim the spans of
 * rows a filter has removed. A strip still drawing a span whose row is
 * gone is worse than no strip: it asserts the filter did nothing.
 *
 * @var string $stripId    Namespaced per panel; two strips on one page
 *                         must not collide over an id
 * @var array $stripSpan   `from`, `to` as unix seconds. A zero-length
 *                         span is legal and is padded, so one instant
 *                         still draws a mark rather than dividing by
 *                         zero
 * @var array $stripLanes  [['label'=>, 'token'=>, 'count'=>,
 *                         'entries'=>[['key','value','relation','from',
 *                         'to','origin']]], …]
 * @var string $stripHue   The colour of a span, as a `var(--x)` the
 *                         stylesheet resolves
 * @var string $stripLabel Accessible name for the strip
 * @var string $stripNoun  What one lane holds, for the count column
 * @var string $stripLaneHead What a lane *is*, over the label column.
 *                         The caller owns it because the caller owns
 *                         the grouping: a strip whose lanes are values
 *                         under a column headed `Template` is a chart
 *                         lying about its own axis
 * @var string $stripLaneIcon The lane chip's icon, or `''` for none —
 *                         which is what a value wants, because the
 *                         table printing the same string beside it
 *                         gives it no icon either
 * @var bool $stripLaneMono Whether a lane label is a stored string
 *                         rather than a name. Verbatim and monospace if
 *                         so; see `.vp-strip-tag-mono`
 * @var string $stripNote  One line under the strip, for a grouping or
 *                         a fold the strip picked and the reader did
 *                         not. Empty renders nothing
 */
$stripLanes = $stripLanes ?? array();
$stripSpan = $stripSpan ?? array('from' => 0, 'to' => 0);
$stripHue = $stripHue ?? 'var(--vp-rel-object)';
$stripLabel = $stripLabel ?? __('Spans over time');
$stripNoun = $stripNoun ?? __('spans');
$stripLaneHead = $stripLaneHead ?? __('Template');
$stripLaneIcon = $stripLaneIcon ?? 'fas fa-cube';
$stripLaneMono = !empty($stripLaneMono);
$stripNote = $stripNote ?? '';

if (empty($stripLanes)) {
    return;
}

/*
 * The viewBox the axis is stretched to. The same 1000×38 the Timeline
 * tab's lanes use, for the same reason: `preserveAspectRatio="none"`
 * means nothing inside the SVG may carry a word, so the only thing the
 * number decides is arithmetic precision.
 */
$LANE_W = 1000;
$LANE_H = 38;
/*
 * Below this width in viewBox units a span is drawn as a **moment**
 * rather than as a short bar, and that is an honesty rule and not a
 * cosmetic one. `draculax.myq-see.com.` is the case: five resolutions
 * over four years, four of which lasted an instant and one thirteen
 * minutes. On a four-year axis all five are two pixels wide, so drawing
 * them as bars renders the section's own argument — a span is a
 * duration — as five specks nobody can see, while widening them to be
 * visible would claim a duration of days that MISP never recorded.
 *
 * A moment therefore gets the Timeline tab's point mark: narrow, taller
 * than a bar, fully opaque. It reads as *a thing happened here* and not
 * as *this lasted a while*, which is the distinction the table beside it
 * already draws with the words "same instant".
 */
$MOMENT_W = 4;

$from = (int)$stripSpan['from'];
$to = (int)$stripSpan['to'];
/*
 * A strip whose every row records the same instant has no span to
 * divide by. Padding it by a day gives the marks somewhere to sit and
 * makes the axis say what it is rather than collapsing to one date
 * printed twice.
 */
if ($to <= $from) {
    $to = $from + 86400;
}
$seconds = max(1, $to - $from);

/**
 * Where an instant sits on the axis, in viewBox units.
 *
 * Clamped, because a lane may be handed a row from outside the window
 * once a caller reuses this — and a mark at x = -40 is a mark the
 * reader cannot see but the count still claims.
 *
 * @param int $at
 * @return float
 */
$xFor = function ($at) use ($from, $seconds, $LANE_W, $MOMENT_W) {
    $fraction = ($at - $from) / $seconds;
    $fraction = max(0, min(1, $fraction));
    return round($fraction * ($LANE_W - $MOMENT_W), 1);
};

/*
 * Five ticks, which is what fits without the labels colliding at the
 * width a panel column gives this. Dates and not datetimes: the axis
 * is here for shape, and the exact instant of any one span is in its
 * own row two inches below.
 */
$TICKS = 5;
$ticks = array();
for ($i = 0; $i < $TICKS; $i++) {
    $ticks[] = date('Y-m-d', $from + (int)round($seconds * $i / ($TICKS - 1)));
}

/*
 * Whether the legend is needed at all. A strip of bars needs no key —
 * a bar over a dated axis explains itself — but a strip mixing bars and
 * dots does, because the difference between them is a claim about the
 * data and not a drawing style.
 */
$hasMoment = false;
$hasSpan = false;
/*
 * And whether any two spans in one lane cover the same instant, which
 * the stylesheet now draws as a deeper patch rather than as a
 * by-product of stacking translucent bars. A drawn claim the reader
 * has no key for is the thing this strip's own comments refuse
 * elsewhere, so the legend says it — and says it only when it is true,
 * because *darker where they overlap* under a strip with no overlap in
 * it sends a reader hunting for one.
 *
 * Measured in viewBox units and through `$xFor`, not on the raw
 * timestamps: two spans a minute apart on a four-year axis are the
 * same pixels, so what counts as overlapping is what the eye is
 * actually shown.
 */
$hasOverlap = false;
foreach ($stripLanes as $lane) {
    $drawn = array();
    foreach ($lane['entries'] as $entry) {
        $x = $xFor((int)$entry['from']);
        $end = $xFor((int)$entry['to']);
        if ($end - $x < $MOMENT_W) {
            $hasMoment = true;
            continue;
        }
        $hasSpan = true;
        foreach ($drawn as $seen) {
            if ($x < $seen[1] && $seen[0] < $end) {
                $hasOverlap = true;
                break;
            }
        }
        $drawn[] = array($x, $end);
    }
}
?>
<?php
/*
 * A label column wide enough for what is in it. A stored value needs
 * more of the panel than a template name does, and for a reason the
 * render found rather than one anybody guessed: at 11rem two of
 * `luxtrust-unlock.com`'s neighbours both elided to
 * `ns-1769.awsdns-29.co…`. `.vp-strip-wide` carries the numbers.
 */
$stripWide = $stripLaneMono;
?>
<div class="vp-strip<?= $stripWide ? ' vp-strip-wide' : '' ?>"
     id="<?= h($stripId) ?>"
     data-vp-span-strip
     role="img"
     aria-label="<?= h($stripLabel) ?>">

    <div class="vp-lanes">

        <div class="vp-lane-head"><?= h($stripLaneHead) ?></div>
        <div class="vp-lane-head">
            <div class="vp-lane-ticks">
                <?php foreach ($ticks as $tick): ?>
                    <span><?= h($tick) ?></span>
                <?php endforeach; ?>
            </div>
        </div>
        <div class="vp-lane-head vp-strip-headnum"><?= h($stripNoun) ?></div>

        <?php foreach ($stripLanes as $lane): ?>

            <div class="vp-lane-label">
                <?php
                /*
                 * The chip truncates rather than widening the column:
                 * `url-honeypot-detection` is 22 characters and the axis
                 * is what the strip is for, so the name gives way and
                 * keeps its full text in the title.
                 */
                ?>
                <span class="vp-rel-tag vp-strip-tag<?=
                          $stripLaneMono ? ' vp-strip-tag-mono' : '' ?>"
                      title="<?= h($lane['label']) ?>">
                    <?php if ($stripLaneIcon !== ''): ?>
                        <i class="<?= h($stripLaneIcon) ?>"></i>
                    <?php endif; ?>
                    <?php
                    /*
                     * The name gets its own span because `.vp-rel-tag`
                     * is an inline-flex chip: a bare text node inside
                     * one is an anonymous flex item, which
                     * `text-overflow` cannot reach, so the label
                     * clipped mid-letter instead of eliding.
                     */
                    ?>
                    <span class="vp-strip-tag-name"><?=
                        h($lane['label']) ?></span>
                </span>
            </div>

            <div class="vp-lane-axis"
                 data-vp-span-lane="<?= h($lane['token']) ?>">
                <?php
                /*
                 * `style="fill: var(…)"` and never the `fill`
                 * attribute: a presentation attribute does not resolve
                 * a custom property, and the palette here is custom
                 * properties precisely so a span in this strip and a
                 * span on the Timeline tab cannot drift apart.
                 */
                ?>
                <svg viewBox="0 0 <?= (int)$LANE_W ?> <?= (int)$LANE_H ?>"
                     preserveAspectRatio="none"
                     class="vp-lane-svg">
                    <?php foreach ($lane['entries'] as $entry): ?>
                        <?php
                        $x = $xFor((int)$entry['from']);
                        $end = $xFor((int)$entry['to']);
                        $width = $end - $x;
                        $moment = $width < $MOMENT_W;
                        /*
                         * The title is the whole tooltip: a mark four
                         * pixels wide is not self-describing, and the
                         * far value is the one thing a reader wants
                         * from it before deciding to look down at the
                         * table. It prints both dates even for a
                         * moment, because *why is this a dot* is the
                         * question a dot invites.
                         */
                        $title = sprintf(
                            '%s — %s → %s',
                            $entry['value'],
                            date('Y-m-d H:i', (int)$entry['from']),
                            date('Y-m-d H:i', (int)$entry['to'])
                        );
                        if (!empty($entry['origin'])) {
                            $title .= ' · ' . $entry['origin'];
                        }
                        ?>
                        <?php if ($moment): ?>
                            <rect class="vp-lane-mark"
                                  data-vp-span-row="<?= h($entry['key']) ?>"
                                  x="<?= h($x) ?>" y="13"
                                  width="<?= (int)$MOMENT_W ?>" height="12"
                                  rx="1.5"
                                  style="--vp-tl-hue: <?= h($stripHue) ?>;">
                                <title><?= h($title) ?></title>
                            </rect>
                        <?php else: ?>
                            <rect class="vp-lane-span"
                                  data-vp-span-row="<?= h($entry['key']) ?>"
                                  x="<?= h($x) ?>" y="19"
                                  width="<?= h($width) ?>" height="7" rx="3"
                                  style="--vp-tl-hue: <?= h($stripHue) ?>;">
                                <title><?= h($title) ?></title>
                            </rect>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </svg>
            </div>

            <div class="vp-lane-count">
                <?php
                /*
                 * The total is in the markup and not read back off the
                 * rendered number: a panel re-rendered by the server
                 * with facets already ticked would have the first paint
                 * mistake the narrowed count for the whole.
                 */
                ?>
                <span data-vp-span-count="<?= h($lane['token']) ?>"
                      data-vp-span-total="<?= (int)$lane['count'] ?>"><?=
                    h(number_format($lane['count'])) ?></span>
                <div class="vp-tl-why" data-vp-span-of
                     hidden><?= h(sprintf(
                         __('of %s'),
                         number_format($lane['count'])
                     )) ?></div>
            </div>

        <?php endforeach; ?>

    </div>

    <?php if ($hasMoment || $hasOverlap): ?>
        <div class="vp-strip-legend">
            <?php if ($hasMoment): ?>
            <span class="vp-tl-key">
                <svg class="vp-strip-swatch" viewBox="0 0 14 14"
                     aria-hidden="true">
                    <rect class="vp-lane-mark" x="5" y="1" width="4"
                          height="12" rx="1.5"
                          style="--vp-tl-hue: <?= h($stripHue) ?>;"></rect>
                </svg>
                <?= h(__('one instant, or too short to draw')) ?>
            </span>
            <?php endif; ?>
            <?php if ($hasSpan): ?>
                <span class="vp-tl-key">
                    <svg class="vp-strip-swatch" viewBox="0 0 14 14"
                         aria-hidden="true">
                        <rect class="vp-lane-span" x="0" y="4" width="14"
                              height="6" rx="3"
                              style="--vp-tl-hue: <?= h($stripHue) ?>;"></rect>
                    </svg>
                    <?= h(__('a span, drawn to scale')) ?>
                </span>
            <?php endif; ?>
            <?php if ($hasOverlap): ?>
                <span class="vp-tl-key">
                    <?php
                    /*
                     * Two spans in the swatch and not one, because the
                     * key has to *be* the thing it names: the right
                     * half is the same paint laid twice and comes out
                     * deeper on its own, through the same rule the
                     * lanes use. A swatch with a hand-picked darker
                     * fill would be a drawing of the claim rather than
                     * the claim.
                     */
                    ?>
                    <svg class="vp-strip-swatch vp-strip-swatch-stack"
                         viewBox="0 0 14 14" aria-hidden="true">
                        <rect class="vp-lane-span" x="0" y="4" width="14"
                              height="6" rx="3"
                              style="--vp-tl-hue: <?= h($stripHue) ?>;"></rect>
                        <rect class="vp-lane-span" x="7" y="4" width="7"
                              height="6" rx="3"
                              style="--vp-tl-hue: <?= h($stripHue) ?>;"></rect>
                    </svg>
                    <?= h(__('deeper where spans cover the same dates')) ?>
                </span>
            <?php endif; ?>
        </div>
    <?php endif; ?>

</div>
<?php if ($stripNote !== ''): ?>
    <?php
    /*
     * Outside the strip, and that is the point of putting it here
     * rather than one line up. `.vp-strip` is `role="img"` with an
     * accessible name of its own, so a screen reader is told to ignore
     * everything inside it — a note explaining why the lanes are what
     * they are would be read by nobody if it sat with the legend.
     *
     * Indented to the axis rather than the panel edge, because it is a
     * statement about the lanes and not about the section.
     */
    ?>
    <div class="vp-strip-note<?=
        $stripWide ? ' vp-strip-note-wide' : '' ?>"><?=
        h($stripNote) ?></div>
<?php endif; ?>
