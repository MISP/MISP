<?php
/*
 * Shows per-type counts (note / opinion / relationship incl. inbound) for the row's
 * object and opens the read-only summary modal (AnalystData::viewForObject) on click.
 *
 * Config:
 *   $field['note_path'] / ['opinion_path'] / ['relationship_path']
 *   / ['relationship_inbound_path'] — Hash paths to the attached arrays
 *   $field['uuid_path']    — Hash path to the object's uuid
 *   $field['object_type']  — the parent object type (e.g. 'Attribute')
 */
$noteCount    = count((array)Hash::get($row, $field['note_path'] ?? ''));
$opinionCount = count((array)Hash::get($row, $field['opinion_path'] ?? ''));
$relOut       = count((array)Hash::get($row, $field['relationship_path'] ?? ''));
$relIn        = count((array)Hash::get($row, $field['relationship_inbound_path'] ?? ''));
$relCount     = $relOut + $relIn;
$total        = $noteCount + $opinionCount + $relCount;

$uuid       = (string)Hash::get($row, $field['uuid_path'] ?? '');
$objectType = $field['object_type'] ?? 'Attribute';

if ($uuid === '') {
    echo '<span class="text-muted">&mdash;</span>';
    return;
}
$onclick = sprintf(
    "event.stopPropagation(); openModal('%s/analystData/viewForObject/%s/%s');",
    h($baseurl), h($objectType), h($uuid)
);
?>
<?php if ($total === 0): ?>
    <a href="#" class="text-muted text-decoration-none" title="<?= __('View / add analyst data') ?>"
       onclick="<?= $onclick ?>">
        <i class="fas fa-comment-slash"></i>
    </a>
<?php else: ?>
    <span class="d-flex flex-column align-items-start gap-1" role="button"
          title="<?= __('View analyst data') ?>" style="cursor:pointer;" onclick="<?= $onclick ?>">
        <?php if ($noteCount): ?>
            <span class="badge bg-primary-subtle text-primary-emphasis border border-primary-subtle">
                <i class="misp-icon misp-icon-analyst-note misp-simple me-1"></i><?= $noteCount ?>
            </span>
        <?php endif; ?>
        <?php if ($opinionCount): ?>
            <span class="badge bg-success-subtle text-success-emphasis border border-success-subtle">
                <i class="misp-icon misp-icon-analyst-opinion misp-simple me-1"></i><?= $opinionCount ?>
            </span>
        <?php endif; ?>
        <?php if ($relCount): ?>
            <span class="badge bg-warning-subtle text-warning-emphasis border border-warning-subtle">
                <i class="fas fa-diagram-project me-1"></i><?= $relCount ?>
            </span>
        <?php endif; ?>
    </span>
<?php endif; ?>
