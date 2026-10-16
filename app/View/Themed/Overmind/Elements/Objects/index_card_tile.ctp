<?php
/**
 * One object in the objects index card view, wired in through `card_element`
 * (see genericElementsBS5/IndexTable/index_card).
 *
 * The header line is the event Objects tab's own (Objects/object_header). The
 * attributes open inside the card from the same endpoint as the table's
 * expanded row. The analyst badges and the action menu are the scaffold's
 * ($sections['analyst'] / ['actions']).
 */
$object = $row['Object'] ?? [];
if (empty($object['id'])) {
    return;
}
$id = (int)$object['id'];
$headline = $object['headline'] ?? null;
$count = (int)($object['attribute_count'] ?? 0);
$out = (int)($object['references_out'] ?? 0);
$in = (int)($object['references_in'] ?? 0);
$day = function ($value) {
    $dt = date_create((string)$value);
    return $dt === false ? (string)$value : $dt->format('Y-m-d');
};
$first = $object['first_seen'] ?? null;
$last = $object['last_seen'] ?? null;
?>
<div class="card-body oi-tile">
    <div class="oi-tile-head">
        <?= $this->element('Objects/object_header', [
            'object' => $object,
            'ctx' => [
                'count' => $count,
                'deleted' => false,
                'firstValue' => $headline === null ? '' : (string)$headline['value'],
                'firstRelation' => $headline === null ? '' : $headline['relation'],
            ],
        ]) ?>
        <?php if (!empty($sections['actions'])): ?>
            <div class="oi-tile-actions"><?= implode('', $sections['actions']) ?></div>
        <?php endif; ?>
    </div>

    <?php if (!empty($object['comment'])): ?>
        <div class="oi-tile-comment" title="<?= h($object['comment']) ?>">
            <i class="fas fa-comment"></i> <?= h($object['comment']) ?>
        </div>
    <?php endif; ?>

    <dl class="oi-tile-facts">
        <dt><?= __('Event') ?></dt>
        <dd>
            <a class="oi-event" href="<?= h($baseurl . '/events/view/' . (int)$row['Event']['id']) ?>"
               title="<?= h($row['Event']['info']) ?>">
                <span class="oi-event-id">#<?= (int)$row['Event']['id'] ?></span>
                <span class="oi-event-info"><?= h($row['Event']['info']) ?></span>
            </a>
        </dd>
        <?php if (Configure::read('MISP.showorg') && !empty($row['Orgc'])): ?>
            <dt><?= __('Creator org') ?></dt>
            <dd><?= $this->element('genericElementsBS5/IndexTable/Fields/organisation', [
                'row' => $row,
                'field' => ['data_path' => 'Orgc'],
            ]) ?></dd>
        <?php endif; ?>
        <dt><?= __('References') ?></dt>
        <dd>
            <span class="oi-refs<?= $out + $in === 0 ? ' is-empty' : '' ?>"
                  title="<?= h(__('%s outgoing, %s incoming references', $out, $in)) ?>">
                <span><i class="fas fa-arrow-right"></i> <?= $out ?></span>
                <span><i class="fas fa-arrow-left"></i> <?= $in ?></span>
            </span>
        </dd>
        <?php if (!empty($first) || !empty($last)): ?>
            <dt><?= __('Seen') ?></dt>
            <dd class="oi-seen">
                <?= empty($first) ? '?' : h($day($first)) ?><span class="oi-seen-dash">&ndash;</span><?= empty($last) ? '?' : h($day($last)) ?>
            </dd>
        <?php endif; ?>
    </dl>

    <div class="oi-tile-foot">
        <button type="button" class="btn btn-sm btn-outline-primary oi-tile-toggle"
                data-oi-expand="<?= $id ?>" aria-expanded="false">
            <i class="fas fa-chevron-right"></i>
            <?= h(__n('%s attribute', '%s attributes', $count, $count)) ?>
        </button>
        <?php if (!empty($sections['analyst'])): ?>
            <div class="oi-tile-analyst"><?= implode('', $sections['analyst']) ?></div>
        <?php endif; ?>
    </div>
    <div class="oi-tile-attrs" hidden></div>
</div>
