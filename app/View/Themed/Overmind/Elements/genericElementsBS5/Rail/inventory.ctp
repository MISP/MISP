<?php
/**
 * Inventory body: a total, then each group with its counted chips. A bar
 * is drawn only where the parts add up to the whole (`partition`).
 */
$rc = $this->RailCard;
$groups = $card['groups'];
$groupPaints = $rc->paints($groups);
echo $rc->figure($card['total']['count'], $card['total']['label']);
if ($card['partition'] && count($groups) > 1) {
    echo $rc->stack($groups, 'rcard-stack-lg', $groupPaints);
}
?>
<ul class="rcard-groups">
    <?php foreach ($groups as $i => $group): ?>
        <?php
        $facets = $group['facets'];
        $counts = array_values(array_filter(array_column($facets, 'count'), 'is_int'));
        $max = empty($counts) ? 0 : max($counts);
        $varied = count(array_unique($counts)) > 1;
        $split = $group['partition'] && count($counts) === count($facets);
        $facetPaints = [];
        if ($split) {
            $parts = $facets;
            $rest = max(0, $group['count'] - array_sum($counts));
            if ($rest) {
                $parts[] = ['label' => __('Other'), 'count' => $rest, 'other' => true];
            }
            $split = count($parts) > 1;
            $facetPaints = $rc->paints($parts, $groupPaints[$i]['color']);
        }
        ?>
        <li class="rcard-group">
            <div class="rcard-group-head">
                <?= $card['partition'] ? $rc->swatch($groupPaints[$i]) : '' ?>
                <?php if (!empty($group['color']) && !empty($group['icon'])): ?>
                    <i class="<?= h($group['icon']) ?> rcard-ico rcard-ico-c rcard-c-tx"
                        style="--rcard-c: var(--bs-<?= h($group['color']) ?>);" aria-hidden="true"></i>
                <?php else: ?>
                    <?= $rc->icon($group['icon']) ?>
                <?php endif; ?>
                <span class="rcard-group-label" title="<?= h($group['label']) ?>"><?= h($group['label']) ?></span>
                <span class="rcard-group-count"><?= $rc->num($group['count']) ?></span>
            </div>
            <?php if (!empty($facets) || !empty($group['more'])): ?>
                <?= $split ? $rc->stack($parts, 'rcard-stack-sm', $facetPaints) : '' ?>
                <div class="rcard-chips">
                    <?php foreach ($facets as $j => $facet): ?>
                        <?php
                        $content = ($split ? $rc->swatch($facetPaints[$j], 'rcard-swatch-sm') : '')
                            . '<span class="rcard-chip-label">' . h($facet['label']) . '</span>';
                        if ($facet['count'] !== null) {
                            $content .= '<span class="rcard-chip-count">' . $rc->num($facet['count']) . '</span>';
                        }
                        $class = 'rcard-chip' . $rc->toneClass($facet['tone']);
                        $style = null;
                        if (!$split && $varied && $max && $facet['count']) {
                            $class .= ' rcard-chip-gauge';
                            $style = '--rcard-fill: ' . round($facet['count'] / $max * 100, 1) . '%';
                        }
                        echo $rc->link($facet['href'], $class, $content, $facet['label'], $style);
                        ?>
                    <?php endforeach; ?>
                    <?= $rc->moreChip($group['more'], $card, $tab,
                        $split ? $rc->swatch(['class' => 'rcard-other', 'color' => null], 'rcard-swatch-sm') : '') ?>
                </div>
            <?php endif; ?>
        </li>
    <?php endforeach; ?>
</ul>
