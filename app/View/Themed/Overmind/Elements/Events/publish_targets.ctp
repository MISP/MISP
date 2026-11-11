<?php
/*
 * Where publishing this event will send it: one row per push-enabled server,
 * saying whether the event reaches it and, when it does not, why.
 *
 * Rendered as the $bodyHtml of Modals/confirmation_form by
 * Events/ajax/eventPublishConfirmationForm, so it returns a self-contained
 * block and adds no margins of its own — the modal body's gap spaces it.
 *
 * Required params:
 *   $servers  array  Event::listServerToPush() output: name => true when the
 *                    event is pushed, name => reason string when it is not
 *
 * Optional params:
 *   $accent   string  accent key, see ModalAccent (default 'event')
 *   $limit    int     rows shown before the list scrolls (default 5)
 */

$servers = $servers ?? [];
$accent = $this->ModalAccent->get($accent ?? 'event');
$limit = $limit ?? 5;

$reached = array_keys(array_filter($servers, function ($reason) {
    return $reason === true;
}));
$total = count($servers);
$scrolls = $total > $limit;
?>
<div>
    <?= $this->element('genericElementsBS5/Forms/section_label', [
        'accent' => $accent['key'],
        'label' => __('Push targets'),
        'badge' => sprintf('%d / %d', count($reached), $total),
        'class' => 'mb-2',
    ]) ?>

    <div class="border rounded-2 overflow-hidden">
        <div<?= $scrolls ? ' style="max-height:13rem; overflow-y:auto;"' : '' ?>>
            <?php $first = true; foreach ($servers as $serverName => $reason): ?>
                <div class="px-3 py-2<?= $first ? '' : ' border-top' ?>">
                    <div class="d-flex align-items-center justify-content-between gap-2">
                        <span class="d-flex align-items-center gap-2">
                            <i class="fas fa-server text-body-secondary flex-shrink-0" style="font-size:.7rem;"></i>
                            <span class="fw-semibold text-break" style="font-size:.85rem;"><?= h($serverName) ?></span>
                        </span>
                        <?php if ($reason === true): ?>
                            <span class="badge bg-success-subtle text-success-emphasis border border-success-subtle rounded-pill flex-shrink-0"
                                  style="font-size:.65rem;">
                                <i class="fas fa-check me-1"></i><?= __('Will be pushed') ?>
                            </span>
                        <?php endif; ?>
                    </div>

                    <?php if ($reason !== true): ?>
                        <div class="d-flex align-items-start gap-1 text-body-secondary lh-base mt-1"
                             style="font-size:.72rem; padding-left:1.2rem;">
                            <i class="fas fa-ban flex-shrink-0" style="font-size:.65rem; margin-top:.15rem;"></i>
                            <span><?= h($reason) ?></span>
                        </div>
                    <?php endif; ?>
                </div>
            <?php $first = false; endforeach; ?>
        </div>
    </div>

    <?= $this->element('genericElementsBS5/Forms/field_hint', [
        'text' => empty($reached)
            ? __('No connected server will receive this event.')
            : __n(
                'One server will receive this event.',
                '%s servers will receive this event.',
                count($reached),
                count($reached)
            ),
        'icon' => empty($reached) ? 'fas fa-circle-exclamation' : 'fas fa-share-nodes',
    ]) ?>
</div>
