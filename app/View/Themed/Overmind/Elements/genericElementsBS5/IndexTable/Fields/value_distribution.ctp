<?php
/**
 * Who can actually see this occurrence.
 *
 * Not `Attribute.distribution`, which is `Inherited` on almost every row
 * a real instance holds: an attribute's audience is the conjunction of
 * its own level, its object's and its event's, and that is what the
 * reader is asking. `ValueStatsTool::effectiveDistribution()` resolves
 * it and `ValueIntelligence::attachEffectiveDistribution()` stamps it on the
 * row, so every surface that draws the level draws the same one.
 *
 * An element rather than a per-table closure because the Overview card
 * and the Occurrences tab both draw this column over the same rows, and
 * a card and a table that resolve a distribution differently are two
 * answers to one question on one page — which is what the card gave
 * while it rendered the attribute's own column: `Inherited` beside the
 * tab's `This community only`, on the same attribute.
 *
 * The shared `distribution` field renderer has no slot for the two
 * things that have to be said here — where the level came from, and
 * when the badge is understating the restriction. The badge itself is
 * still MISP's own element.
 *
 * Expected:
 *   $row['effective_distribution'] as stamped by the model
 *   $field['sharing_group_line'] (bool, default true) — name the
 *     sharing group on a line of its own. The Overview card passes
 *     false to keep its rows one line each and takes the name in the
 *     title instead.
 */
App::uses('DistributionLevel', 'Tools');

$effective = isset($row['effective_distribution'])
    ? $row['effective_distribution']
    : null;
if (empty($effective) || $effective['level'] === null) {
    echo '<span class="text-muted">&mdash;</span>';
    return;
}
$sharingGroupLine = !isset($field['sharing_group_line'])
    || $field['sharing_group_line'];

// "Attribute: Inherited → Event: This community only" — the whole
// chain, so a level nobody set on the attribute is traceable to
// whoever did set it.
$chain = array();
$chain[] = sprintf(
    '%s: %s',
    __('Attribute'),
    DistributionLevel::get((int)$row['Attribute']['distribution'])['label']
);
if (!empty($row['Object']['id'])) {
    $chain[] = sprintf(
        '%s: %s',
        __('Object'),
        DistributionLevel::get((int)$row['Object']['distribution'])['label']
    );
}
$chain[] = sprintf(
    '%s: %s',
    __('Event'),
    DistributionLevel::get((int)$row['Event']['distribution'])['label']
);
$title = implode(' → ', $chain);
if ($effective['intersects']) {
    /*
     * A sharing group alongside another constraint means the real
     * audience is an intersection, and no single level says that. The
     * badge shows the tightest level it can name; this says the real
     * audience is narrower still.
     */
    $title .= ' · ' . __(
        'Both apply, so the real audience is narrower than any one of them'
    );
}
$named = (int)$effective['level'] === 4
    && !empty($effective['sharing_group_name']);
if ($named && !$sharingGroupLine) {
    $title .= ' · ' . $effective['sharing_group_name'];
}
?>
<span title="<?= h($title) ?>">
    <?= $this->element(
        'genericElementsBS5/Badges/distribution',
        array('distribution' => $effective['level'], 'full' => false)
    ) ?>
    <?php if ($effective['intersects']): ?>
        <i class="fas fa-link ms-1 text-warning-emphasis"
           aria-hidden="true"></i>
    <?php endif; ?>
</span>
<?php
/*
 * "Sharing group" is the only level that does not say who it means.
 * Named by whichever link in the chain won, so an attribute inheriting
 * its event's sharing group names that group rather than nothing — and
 * linked to it, because "which organisations is that" is the next
 * question and only the group's own page answers it.
 *
 * Safe to link unconditionally: the name is only ever set from
 * `SharingGroup::fetchAllAuthorised($user, 'name')`, so a name that
 * resolved is a group this viewer may open. Where it did not resolve,
 * the badge stands alone and there is nothing to link.
 */
if ($named && $sharingGroupLine):
?>
    <div class="text-muted small text-truncate mt-1">
        <a class="text-reset"
           href="<?= h($baseurl) ?>/sharing_groups/view/<?=
               h($effective['sharing_group_id']) ?>"
           title="<?= h(sprintf(
               __('%s — who this is shared with'),
               $effective['sharing_group_name']
           )) ?>"><?= h($effective['sharing_group_name']) ?></a>
    </div>
<?php endif; ?>
