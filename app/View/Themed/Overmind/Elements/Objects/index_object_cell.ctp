<?php
/**
 * The Object cell of an objects index row: the toggle that opens its
 * attributes, the header line (Objects/object_header) and the comment. Shared
 * by the objects index and the event's Objects tab.
 *
 * Parameters:
 *   object  array  the row's Object, with its attribute_count and headline
 *   open    bool   drawn open (default false)
 */
$headline = $object['headline'] ?? null;
$open = !empty($open);
?>
<div class="oi-object">
    <button type="button" class="oi-expand" data-oi-expand="<?= (int)$object['id'] ?>"
            aria-expanded="<?= $open ? 'true' : 'false' ?>" title="<?= h(__('Show its attributes')) ?>">
        <i class="fas fa-chevron-right"></i>
    </button>
    <?= $this->element('Objects/object_header', [
        'object' => $object,
        'ctx' => [
            'count' => (int)($object['attribute_count'] ?? 0),
            'deleted' => !empty($object['deleted']),
            'firstValue' => $headline === null ? '' : (string)$headline['value'],
            'firstRelation' => $headline === null ? '' : (string)$headline['relation'],
        ],
    ]) ?>
</div>
<?php if (!empty($object['comment'])): ?>
    <div class="oi-comment" title="<?= h($object['comment']) ?>">
        <i class="fas fa-comment"></i> <?= h($object['comment']) ?>
    </div>
<?php endif; ?>
