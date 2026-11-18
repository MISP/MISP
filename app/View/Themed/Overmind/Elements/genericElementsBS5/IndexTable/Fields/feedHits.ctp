<?php
/*
 * Feed and server hits for an attribute: one tinted pill each, the look the
 * table's other counted cells use (Fields/sightings), styled in
 * attribute-elements.css.
 *
 * The details go in a plain-text title rather than an HTML tooltip: a tab
 * loaded over ajax never initialises Bootstrap tooltips, and the browser then
 * showed the raw markup.
 */
$attribute = isset($row['Attribute']) ? $row['Attribute'] : null;

$feeds   = isset($attribute['Feed'])   ? $attribute['Feed']   : [];
$servers = isset($attribute['Server']) ? $attribute['Server'] : [];

if (empty($feeds) && empty($servers)) {
    return;
}

$canPreview = !empty($isSiteAdmin) || !empty($hostOrgUser);

$maxVisible = 4;
$total      = count($feeds);
foreach ($servers as $server) {
    $total += count($server['event_uuids']);
}
$overflow = max(0, $total - $maxVisible);
$i        = 0;

$titleOf = function (array $lines) {
    $out = [];
    foreach ($lines as $label => $value) {
        if ($value !== null && $value !== '') {
            $out[] = $label . ': ' . $value;
        }
    }
    return implode("\n", $out);
};
?>

<div class="feed-hits">

    <?php foreach ($feeds as $feed): ?>
        <?php
            $hidden = ($i >= $maxVisible && $overflow > 0);
            $extraClass = $hidden ? ' d-none feed-hit-extra' : '';
            $events = !empty($feed['event_uuids']) ? count($feed['event_uuids']) : null;
            $title = $titleOf([
                __('Feed') => $feed['name'],
                __('Provider') => $feed['provider'] ?? null,
                __('Events') => $events,
            ]);
            ob_start();
        ?>
            <i class="fas fa-rss" aria-hidden="true"></i><span class="feed-hit-name"><?= h($feed['name']) ?></span><?php if ($events): ?><b><?= h($events) ?></b><?php endif; ?>
        <?php
            $inner = ob_get_clean();
        ?>
        <?php if ($canPreview && ($feed['source_format'] ?? '') === 'misp'): ?>
            <form action="<?= $baseurl ?>/feeds/previewIndex/<?= h($feed['id']) ?>"
                  method="post" class="d-inline-flex m-0<?= $extraClass ?>">
                <input type="hidden"
                       name="data[Feed][eventid]"
                       value="<?= h(json_encode($feed['event_uuids'])) ?>">
                <button type="submit" class="feed-hit" title="<?= h($title) ?>"><?= $inner ?></button>
            </form>
        <?php elseif ($canPreview): ?>
            <a href="<?= $baseurl ?>/feeds/previewIndex/<?= h($feed['id']) ?>"
               class="feed-hit<?= $extraClass ?>" title="<?= h($title) ?>"><?= $inner ?></a>
        <?php else: ?>
            <span class="feed-hit<?= $extraClass ?>" title="<?= h($title) ?>"><?= $inner ?></span>
        <?php endif; ?>
        <?php $i++; ?>
    <?php endforeach; ?>

    <?php foreach ($servers as $server): ?>
        <?php foreach ($server['event_uuids'] as $k => $eventUuid): ?>
            <?php
                $hidden     = ($i >= $maxVisible && $overflow > 0);
                $extraClass = $hidden ? ' d-none feed-hit-extra' : '';
                $label      = 'S' . $server['id'] . ':' . ($k + 1);
                $title      = __('Server') . ' ' . $server['id'];
            ?>
            <?php if (!empty($isSiteAdmin)): ?>
                <a href="<?= $baseurl ?>/servers/previewEvent/<?= h($server['id']) ?>/<?= h($eventUuid) ?>"
                   class="feed-hit is-server<?= $extraClass ?>" title="<?= h($title) ?>">
                    <i class="fas fa-server" aria-hidden="true"></i><span class="feed-hit-name"><?= h($label) ?></span>
                </a>
            <?php else: ?>
                <span class="feed-hit is-server<?= $extraClass ?>" title="<?= h($title) ?>">
                    <i class="fas fa-server" aria-hidden="true"></i><span class="feed-hit-name"><?= h($label) ?></span>
                </span>
            <?php endif; ?>
            <?php $i++; ?>
        <?php endforeach; ?>
    <?php endforeach; ?>

    <?php if ($overflow > 0): ?>
        <button type="button" class="feed-hit feed-hit-more"
                title="<?= h(__('Show %d more', $overflow)) ?>"
                data-overflow="<?= (int)$overflow ?>"
                data-collapse="<?= h(__('Collapse')) ?>"
                data-expand="<?= h(__('Show %d more', $overflow)) ?>"
                onclick="
                    var extras = this.closest('.feed-hits').querySelectorAll('.feed-hit-extra');
                    var open = extras[0].classList.contains('d-none');
                    extras.forEach(function (el) { el.classList.toggle('d-none', !open); });
                    this.textContent = open ? '−' : '+' + this.dataset.overflow;
                    this.title = open ? this.dataset.collapse : this.dataset.expand;
                ">+<?= (int)$overflow ?></button>
    <?php endif; ?>

</div>
