<?php
/**
 * Where an attribute sits inside its event, and what its reporter said
 * about it.
 *
 * Two questions, one column, because neither fills one on its own and
 * both answer "what is this row, beyond its value": the object it belongs
 * to with the relation it plays there, and the analyst's comment.
 *
 * Expected:
 *   $field['object_name_path'] path to the object name (default Object.name)
 *   $field['object_id_path']   path to the object id, for the link
 *   $field['relation_path']    path to the object_relation
 *   $field['comment_path']     path to the attribute comment; omit to
 *                              render the object line alone
 *   $field['spelled_path']     path to the spelling the row holds the
 *                              value in, set only where it is not the
 *                              page's
 */
$objectName = Hash::get($row, $field['object_name_path'] ?? 'Object.name');
$objectId = empty($field['object_id_path'])
    ? null
    : Hash::get($row, $field['object_id_path']);
$relation = empty($field['relation_path'])
    ? null
    : Hash::get($row, $field['relation_path']);
$comment = empty($field['comment_path'])
    ? null
    : Hash::get($row, $field['comment_path']);
$spelled = empty($field['spelled_path'])
    ? null
    : Hash::get($row, $field['spelled_path']);

$isCard = isset($viewMode) && $viewMode === 'card';
?>
<div class="d-flex flex-column gap-1">

    <?php if (!empty($objectName)): ?>
        <div class="d-inline-flex align-items-center gap-1 text-nowrap">
            <span class="misp-icon misp-icon-object misp-simple"
                  style="color: var(--object);"></span>
            <?php if (!empty($objectId)): ?>
                <a href="<?= $baseurl ?>/objects/view/<?= h($objectId) ?>"
                   class="text-decoration-none fw-semibold">
                    <?= h($objectName) ?>
                </a>
            <?php else: ?>
                <span class="fw-semibold"><?= h($objectName) ?></span>
            <?php endif; ?>
            <?php if (!empty($relation)): ?>
                <span class="vp-relation" title="<?= h(__('Object relation')) ?>">
                    <?= h($relation) ?>
                </span>
            <?php endif; ?>
        </div>
    <?php else: ?>
        <span class="text-muted small"><?= __('Standalone attribute') ?></span>
    <?php endif; ?>

    <?php if ($spelled !== null && $spelled !== ''): ?>
        <div class="small text-truncate" style="max-width: 18rem;"
             title="<?= h(__('Recorded in this spelling. MISP shows it with the value you opened, but an accent can make a different domain.')) ?>">
            <span class="text-warning-emphasis"><?= __('spelled') ?></span>
            <span class="font-monospace"><?= h($spelled) ?></span>
        </div>
    <?php endif; ?>

    <?php if (!empty($comment)): ?>
        <div class="text-muted small <?= $isCard ? '' : 'text-truncate' ?>"
             style="<?= $isCard ? '' : 'max-width: 18rem;' ?>"
             title="<?= h($comment) ?>">
            <?= $isCard ? nl2br(h($comment)) : h($comment) ?>
        </div>
    <?php endif; ?>

</div>
