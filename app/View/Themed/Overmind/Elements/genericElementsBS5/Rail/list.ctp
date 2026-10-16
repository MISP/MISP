<?php
/**
 * List body: compact rows of records. Shares draw a meter, and so do counts
 * when they differ; a badge on every row also draws a band, oldest first.
 */
$rc = $this->RailCard;
$rows = $card['rows'];
$counts = array_values(array_filter(array_column($rows, 'count'), 'is_int'));
$maxCount = empty($counts) ? 0 : max($counts);
$countBars = count($counts) > 1 && count(array_unique($counts)) > 1;
$allBadged = count($rows) > 1 && count(array_filter($rows, function ($row) {
    return in_array($row['badge']['tone'] ?? null, RailCardHelper::TONES, true);
})) === count($rows);
?>
<?php if ($allBadged): ?>
    <div class="rcard-band" role="img" aria-label="<?= h(implode(', ', array_column(array_column($rows, 'badge'), 'label'))) ?>">
        <?php foreach (array_reverse($rows) as $row): ?>
            <span class="rcard-band-cell rcard-fill-<?= h($row['badge']['tone']) ?>"
                title="<?= h((empty($row['meta'][0]) ? '' : $row['meta'][0] . ': ') . $row['badge']['label']) ?>"></span>
        <?php endforeach; ?>
    </div>
<?php endif; ?>
<ul class="rcard-rows">
    <?php foreach ($rows as $row): ?>
        <?php
        $hasShare = is_numeric($row['share']);
        $showIcon = !empty($row['icon']) && $row['icon'] !== $card['icon'];
        $meta = array_values(array_filter($row['meta'], 'strlen'));
        ?>
        <li class="rcard-row<?= $rc->toneClass($row['tone']) ?><?= $showIcon ? ' rcard-row-iconed' : '' ?>">
            <?= $showIcon ? $rc->icon($row['icon']) : '' ?>
            <div class="rcard-row-main">
                <?= $rc->link($row['href'], 'rcard-row-label', h($row['label']), $row['label']) ?>
                <?php if (!empty($meta)): ?>
                    <div class="rcard-row-meta">
                        <?php foreach ($meta as $item): ?>
                            <span><?= h($item) ?></span>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
            <?php if ($hasShare || is_int($row['count']) || $row['badge'] || $row['action']): ?>
                <div class="rcard-row-end">
                    <?php if ($hasShare): ?>
                        <span class="rcard-row-figs">
                            <span class="rcard-row-share"><?= h($rc->pct($row['share'])) ?></span>
                            <?php if (is_int($row['count'])): ?>
                                <span class="rcard-row-sub"><?= $rc->num($row['count']) ?></span>
                            <?php endif; ?>
                        </span>
                    <?php elseif (is_int($row['count'])): ?>
                        <span class="rcard-row-count"><?= $rc->num($row['count']) ?></span>
                    <?php endif; ?>
                    <?php if ($row['badge']): ?>
                        <span class="rcard-badge<?= $rc->toneClass($row['badge']['tone']) ?>"><?= h($row['badge']['label']) ?></span>
                    <?php endif; ?>
                    <?php if ($row['action']): ?>
                        <?php
                        $action = $row['action'];
                        $actionClass = 'btn btn-sm btn-outline-secondary rcard-action';
                        if (strtolower($action['method']) === 'post') {
                            echo $this->Form->postLink(
                                $action['label'],
                                $rc->href($action['href']),
                                ['class' => $actionClass],
                                $action['confirm']
                            );
                        } else {
                            echo $rc->link($action['href'], $actionClass, h($action['label']));
                        }
                        ?>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
            <?php if ($hasShare): ?>
                <?= $rc->meter($row['share'], $row['tone'], $rc->pct($row['share'])) ?>
            <?php elseif ($countBars && is_int($row['count'])): ?>
                <?= $rc->meter($row['count'] / $maxCount, $row['tone'], number_format($row['count'])) ?>
            <?php endif; ?>
        </li>
    <?php endforeach; ?>
</ul>
<?php if (!empty($card['more'])): ?>
    <div class="rcard-foot">
        <?= $rc->link($card['more']['href'], 'rcard-more',
            h($card['more']['label']) . ' <i class="fas fa-chevron-right" aria-hidden="true"></i>') ?>
    </div>
<?php endif; ?>
