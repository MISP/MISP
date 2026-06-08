<?php
/*
 *
 * Displays feed and server hits for an attribute as BS5 badge links with tooltips.
 */
$isCard    = isset($viewMode) && $viewMode === 'card';
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
?>

<div class="d-flex flex-wrap align-items-center gap-1">

    <?php foreach ($feeds as $feed): ?>
        <?php
            $hidden = ($i >= $maxVisible && $overflow > 0);
            $lines = [
                __('Name')     => h($feed['name']),
                __('Provider') => h($feed['provider']),
            ];
            if (!empty($feed['event_uuids'])) {
                $lines[__('Events')] = count($feed['event_uuids']);
            }
            $tooltipHtml = '';
            foreach ($lines as $k => $v) {
                $tooltipHtml .= '<strong>' . $k . '</strong>: ' . $v . '<br>';
            }
            $extraClass = $hidden ? ' d-none feed-hit-extra' : '';
        ?>
        <?php if ($canPreview && $feed['source_format'] === 'misp'): ?>
            <form action="<?= $baseurl ?>/feeds/previewIndex/<?= h($feed['id']) ?>"
                  method="post" class="d-inline m-0<?= $hidden ? ' d-none feed-hit-extra' : '' ?>">
                <input type="hidden"
                       name="data[Feed][eventid]"
                       value="<?= h(json_encode($feed['event_uuids'])) ?>">
                <button type="submit"
                        class="badge btn btn-sm p-0 px-2 py-1 text-bg-info border-0 text-dark"
                        data-bs-toggle="tooltip"
                        data-bs-html="true"
                        title="<?= h($tooltipHtml) ?>">
                    <i class="fas fa-rss me-1"></i><?= h($feed['name']) ?>
                </button>
            </form>
        <?php elseif ($canPreview): ?>
            <a href="<?= $baseurl ?>/feeds/previewIndex/<?= h($feed['id']) ?>"
               class="badge text-decoration-none text-bg-info text-dark<?= $extraClass ?>"
               data-bs-toggle="tooltip"
               data-bs-html="true"
               title="<?= h($tooltipHtml) ?>">
                <i class="fas fa-rss me-1"></i><?= h($feed['name']) ?>
            </a>
        <?php else: ?>
            <span class="badge text-bg-secondary<?= $extraClass ?>"
                  title="<?= h($feed['name']) ?>">
                <i class="fas fa-rss me-1"></i><?= h($feed['name']) ?>
            </span>
        <?php endif; ?>
        <?php $i++; ?>
    <?php endforeach; ?>

    <?php foreach ($servers as $server): ?>
        <?php foreach ($server['event_uuids'] as $k => $eventUuid): ?>
            <?php
                $hidden     = ($i >= $maxVisible && $overflow > 0);
                $extraClass = $hidden ? ' d-none feed-hit-extra' : '';
                $label      = 'S' . h($server['id']) . ':' . ($k + 1);
            ?>
            <?php if ($isSiteAdmin): ?>
                <a href="<?= $baseurl ?>/servers/previewEvent/<?= h($server['id']) ?>/<?= h($eventUuid) ?>"
                   class="badge text-decoration-none text-bg-warning text-dark<?= $extraClass ?>"
                   title="<?= __('Server') . ' ' . h($server['id']) ?>">
                    <i class="fas fa-server me-1"></i><?= $label ?>
                </a>
            <?php else: ?>
                <span class="badge text-bg-secondary<?= $extraClass ?>"
                      title="<?= __('Server') . ' ' . h($server['id']) ?>">
                    <i class="fas fa-server me-1"></i><?= $label ?>
                </span>
            <?php endif; ?>
            <?php $i++; ?>
        <?php endforeach; ?>
    <?php endforeach; ?>

    <?php if ($overflow > 0): ?>
        <span class="badge bg-secondary text-white feed-hit-toggle"
              style="cursor:pointer;"
              title="<?= __('Show %d more', $overflow) ?>"
              data-overflow="<?= $overflow ?>"
              onclick="
                var btn = this;
                var extras = btn.closest('.d-flex').querySelectorAll('.feed-hit-extra');
                var isHidden = extras[0].classList.contains('d-none');
                extras.forEach(function(el){ el.classList.toggle('d-none', !isHidden); });
                btn.textContent = isHidden ? '−' : '+' + btn.dataset.overflow;
                btn.title = isHidden ? '<?= __('Collapse') ?>' : '<?= __('Show %d more', $overflow) ?>';
              ">
            +<?= $overflow ?>
        </span>
    <?php endif; ?>

</div>
