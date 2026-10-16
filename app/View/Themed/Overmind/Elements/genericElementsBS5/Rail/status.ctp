<?php
/**
 * Status body: the state as one sentence, then its key → value items.
 */
$rc = $this->RailCard;
$state = in_array($card['state'], RailCardHelper::TONES, true) ? $card['state'] : 'muted';
?>
<div class="rcard-state rcard-t-<?= h($state) ?>">
    <span class="rcard-state-dot rcard-fill-<?= h($state) ?>" aria-hidden="true">
        <i class="<?= h(RailCardHelper::STATE_ICONS[$state]) ?>"></i>
    </span>
    <p class="rcard-state-text"><?= h($card['headline'] ?: ($card['empty'] ?? '')) ?></p>
</div>
<?php if (!empty($card['items'])): ?>
    <dl class="rcard-kv">
        <?php foreach ($card['items'] as $item): ?>
            <div class="rcard-kv-row">
                <dt class="rcard-kv-label" title="<?= h($item['label']) ?>"><?= h($item['label']) ?></dt>
                <dd class="rcard-kv-value<?= $rc->toneClass($item['tone'], 'rcard-tx-') ?>"
                    title="<?= h((string)$item['value']) ?>"><?= $rc->num($item['value']) ?></dd>
            </div>
        <?php endforeach; ?>
    </dl>
<?php endif; ?>
<?php if (!empty($card['action'])): ?>
    <div class="rcard-foot">
        <?php
        $actionClass = 'btn btn-sm btn-outline-secondary rcard-status-action';
        if (strtolower($card['action']['method'] ?? 'get') === 'post') {
            echo $this->Form->postLink(
                $card['action']['label'],
                $rc->href($card['action']['href']),
                ['class' => $actionClass],
                $card['action']['confirm'] ?? null
            );
        } else {
            echo $rc->link($card['action']['href'], $actionClass, h($card['action']['label']));
        }
        ?>
    </div>
<?php endif; ?>
