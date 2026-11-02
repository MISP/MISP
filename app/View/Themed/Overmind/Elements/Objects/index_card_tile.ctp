<?php
/**
 * One object in the card view of the objects index and of the event's Objects
 * tab, wired in through `card_element` (see genericElementsBS5/IndexTable/index_card).
 *
 * Handled as the attribute indexes' cards (Attributes/index_card_tile): the
 * object icon leads and gives way to the selection box on hover, the menu
 * shows on hover. The header line is Objects/object_header, with the last
 * change as the page header gives it. The analyst badges and the action menu
 * are the scaffold's ($sections['analyst'] / ['actions']). Event and creator
 * org show when the row carries them, which the event's own tab does not.
 *
 * The attributes open inside the card. The objects index fetches them from the
 * same endpoint as its table's expanded row. The event tab hands them over as
 * $sections['attributes'], with the relationship menu as
 * $sections['references'] and `open` on the row for a card drawn open.
 */
$object = $row['Object'] ?? [];
if (empty($object['id'])) {
    return;
}
$id = (int)$object['id'];
$headline = $object['headline'] ?? null;
$count = (int)($object['attribute_count'] ?? 0);
$timestamp = (int)($object['timestamp'] ?? 0);
$attributes = $sections['attributes'] ?? [];
$open = !empty($row['open']) && !empty($attributes);
$modified = $timestamp > 0
    ? '<span class="oi-tile-modified">' . $this->element('genericElementsBS5/Badges/timestamp_pill', [
        'record' => ['timestamp' => $timestamp],
    ]) . '</span>'
    : '';
?>
<div class="card-body oi-tile">
    <div class="oi-tile-head">
        <span class="oi-tile-lead">
            <i class="misp-icon misp-icon-object misp-simple text-object" aria-hidden="true"></i>
            <?php if (!empty($sections['selector'])): ?>
                <span class="oi-tile-sel"><?= implode('', $sections['selector']) ?></span>
            <?php endif; ?>
        </span>
        <?= $this->element('Objects/object_header', [
            'object' => $object,
            'ctx' => [
                'count' => $count,
                'deleted' => !empty($object['deleted']),
                'firstValue' => $headline === null ? '' : (string)$headline['value'],
                'firstRelation' => $headline === null ? '' : (string)$headline['relation'],
            ],
            'asideHtml' => $modified,
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
        <?php if (!empty($row['Event'])): ?>
            <dt><?= __('Event') ?></dt>
            <dd>
                <a class="oi-event" href="<?= h($baseurl . '/events/view/' . (int)$row['Event']['id']) ?>"
                   title="<?= h($row['Event']['info']) ?>">
                    <span class="oi-event-id">#<?= (int)$row['Event']['id'] ?></span>
                    <span class="oi-event-info"><?= h($row['Event']['info']) ?></span>
                </a>
            </dd>
        <?php endif; ?>
        <?php if (Configure::read('MISP.showorg') && !empty($row['Orgc'])): ?>
            <dt><?= __('Creator org') ?></dt>
            <dd><?= $this->element('genericElementsBS5/IndexTable/Fields/organisation', [
                'row' => $row,
                'field' => ['data_path' => 'Orgc'],
            ]) ?></dd>
        <?php endif; ?>
        <dt><?= __('References') ?></dt>
        <dd>
            <?php if (!empty($sections['references'])): ?>
                <?= implode('', $sections['references']) ?>
            <?php else: ?>
                <?= $this->element('Objects/index_refs', [
                    'out' => $object['references_out'] ?? 0,
                    'in' => $object['references_in'] ?? 0,
                ]) ?>
            <?php endif; ?>
        </dd>
        <?php if (!empty($object['first_seen']) || !empty($object['last_seen'])): ?>
            <dt><?= __('Seen') ?></dt>
            <dd><?= $this->element('Objects/index_seen', ['object' => $object]) ?></dd>
        <?php endif; ?>
    </dl>

    <div class="oi-tile-foot">
        <button type="button" class="btn btn-sm oi-tile-toggle"
                data-oi-expand="<?= $id ?>" aria-expanded="<?= $open ? 'true' : 'false' ?>">
            <i class="fas fa-chevron-right"></i>
            <span class="misp-icon misp-icon-attribute misp-simple" aria-hidden="true"></span>
            <?= h(__n('%s attribute', '%s attributes', $count, $count)) ?>
        </button>
        <?php if (!empty($sections['analyst'])): ?>
            <div class="oi-tile-analyst"><?= implode('', $sections['analyst']) ?></div>
        <?php endif; ?>
    </div>
    <div class="oi-tile-attrs"<?= $open ? '' : ' hidden' ?>><?= implode('', $attributes) ?></div>
</div>
