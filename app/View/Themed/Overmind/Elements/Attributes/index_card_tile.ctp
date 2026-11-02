<?php
/**
 * One attribute in the card view of the attribute indexes (the event's
 * Attributes tab and /attributes/index), wired in through `card_element`
 * (see genericElementsBS5/IndexTable/index_card).
 *
 * Sized as the objects index's cards (Objects/index_card_tile) and handled as
 * the events index's (Events/index_card): the attribute icon leads and gives
 * way to the selection box on hover, the menu shows on hover. Then the
 * distribution, the category and type (drawn as the table draws them) and the
 * last change (as the page header gives it) over the value, the facts closed
 * by the IDS and correlation toggles, and a foot with the sightings and the
 * analyst data.
 *
 * Each part the index configures arrives as the section its field names
 * (Elements/Attributes/index.ctp). The two toggles are drawn here in their card
 * form, which attributes-index.css turns into status chips.
 *
 * Also the card of an attribute inside an object's card
 * (Objects/object_attribute_list), which hands over the sections itself, the
 * object relation as $sections['relation'] between the category and the type,
 * and `readonly` for a page that has not loaded the attribute's event: the IDS
 * and correlation states without their toggles.
 */
$attribute = $row['Attribute'] ?? $row;
if (empty($attribute['id'])) {
    return;
}
$dist = $this->DistributionLevel->get((int)($attribute['distribution'] ?? 0));
$distTitle = __('Distribution: %s', $dist['label'])
    . (empty($attribute['SharingGroup']['name']) ? '' : ' (' . $attribute['SharingGroup']['name'] . ')');
$timestamp = (int)($attribute['timestamp'] ?? 0);
$isProposal = !empty($attribute['is_proposal']);
$readonly = !empty($readonly);
$section = function ($name) use ($sections) {
    return implode('', $sections[$name] ?? []);
};

$facts = [];
if (!empty($sections['event']) && !empty($row['Event']['id'])) {
    $facts[__('Event')] = sprintf(
        '<a class="ai-event" href="%s" title="%s"><span class="ai-event-id">#%d</span>'
            . '<span class="ai-event-info">%s</span></a>',
        h($baseurl . '/events/view/' . (int)$row['Event']['id']),
        h($row['Event']['info'] ?? ''),
        (int)$row['Event']['id'],
        h($row['Event']['info'] ?? '')
    );
}
$facts[__('Creator org')] = $section('orgc');
$facts[__('Owner org')] = $section('org');
$facts[__('Tags')] = $section('tags');
$facts[__('Galaxies')] = $section('galaxies');
$facts[__('Related')] = $section('related');
$facts[__('Feed hits')] = $section('feeds');
$facts = array_filter($facts, function ($html) {
    return trim($html) !== '';
});
?>
<div class="card-body ai-tile">
    <div class="ai-tile-head">
        <span class="ai-tile-lead">
            <i class="misp-icon misp-icon-attribute misp-simple text-attribute" aria-hidden="true"></i>
            <?php if (!empty($sections['selector'])): ?>
                <span class="ai-tile-sel"><?= $section('selector') ?></span>
            <?php endif; ?>
        </span>
        <span class="ov-obj-dist"
              style="--ov-dist-bg:<?= h($this->DistributionLevel->themed($dist, 'bg')) ?>;--ov-dist-ink:<?= h($this->DistributionLevel->themed($dist, 'fg')) ?>;"
              title="<?= h($distTitle) ?>">
            <i class="<?= h($dist['icon']) ?>"></i>
        </span>
        <div class="ai-tile-title">
            <div class="ai-tile-kind">
                <?= $section('category') ?>
                <?= $section('relation') ?>
                <?= $section('type') ?>
                <?php if (!empty($attribute['deleted'])): ?>
                    <span class="ov-obj-deleted"><i class="fas fa-trash"></i><?= __('Deleted') ?></span>
                <?php endif; ?>
                <?php if ($timestamp > 0): ?>
                    <span class="ai-tile-modified"><?= $this->element('genericElementsBS5/Badges/timestamp_pill', [
                        'record' => ['timestamp' => $timestamp],
                    ]) ?></span>
                <?php endif; ?>
            </div>
            <div class="ai-tile-value"><?= $section('value') ?></div>
        </div>
        <?php if (!empty($sections['actions'])): ?>
            <div class="ai-tile-actions"><?= $section('actions') ?></div>
        <?php endif; ?>
    </div>

    <?php if (!empty($facts)): ?>
        <dl class="ai-tile-facts">
            <?php foreach ($facts as $label => $html): ?>
                <dt><?= h($label) ?></dt>
                <dd><?= $html ?></dd>
            <?php endforeach; ?>
        </dl>
    <?php endif; ?>

    <?php if (!$isProposal): ?>
        <div class="ai-tile-state">
            <?= $this->element('genericElementsBS5/IndexTable/Fields/ids', [
                'row' => $row,
                'field' => ['data_path' => 'to_ids', 'readonly' => $readonly],
                'viewMode' => 'card',
            ]) ?>
            <?= $this->element('genericElementsBS5/IndexTable/Fields/correlate', [
                'row' => $row,
                'field' => ['data_path' => 'disable_correlation', 'readonly' => $readonly],
                'viewMode' => 'card',
            ]) ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($sections['sightings']) || !empty($sections['analyst'])): ?>
        <div class="ai-tile-foot">
            <?php if (!empty($sections['sightings'])): ?>
                <div class="ai-tile-sightings"><?= $section('sightings') ?></div>
            <?php endif; ?>
            <?php if (!empty($sections['analyst'])): ?>
                <div class="ai-tile-analyst"><?= $section('analyst') ?></div>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>
