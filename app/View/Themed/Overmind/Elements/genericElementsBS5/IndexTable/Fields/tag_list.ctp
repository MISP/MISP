<?php
$data = Hash::extract($row, $field['data_path']);

/*
 * Optional inline "+" button to attach a tag to this object. Enabled by the
 * caller via $field['add_tag'] (already ACL-gated upstream). $field['add_tag_url']
 * holds a URL template with a %id% placeholder, resolved from
 * $field['add_tag_id_path'] (falls back to $row['id']).
 */
$allowAddTag = !empty($field['add_tag']);
$addUrl      = null;
if ($allowAddTag) {
    $addId = Hash::get($row, $field['add_tag_id_path'] ?? 'id');
    if (empty($addId) && !empty($row['id'])) {
        $addId = $row['id'];
    }
    $isDeleted = !empty($row['deleted']) || !empty($row['Attribute']['deleted']);
    if (!empty($addId) && !$isDeleted && !empty($field['add_tag_url'])) {
        $addUrl = str_replace('%id%', rawurlencode($addId), $field['add_tag_url']);
    }
}

if (empty($data) && empty($addUrl)) {
    return;
}

$data = $data ?: [];

$maxVisible = 4;
// Count only real tags, not galaxy-tags
$realTags = array_filter($data, function($t) {
    return !empty($t['Tag']) && empty($t['Tag']['is_galaxy']);
});
$totalTags   = count($realTags);
$hiddenCount = max(0, $totalTags - $maxVisible);

?>

<div class="tag-container d-inline-flex flex-wrap align-items-center">

<?php
$visibleIndex = 0;

foreach ($data as $tagWrapper) {
    if (empty($tagWrapper['Tag'])) {
        continue;
    }
    // Galaxy-tags live in AttributeTag too
    if (!empty($tagWrapper['Tag']['is_galaxy'])) {
        continue;
    }

    $hiddenClass = ($visibleIndex >= $maxVisible) ? 'd-none extra-tag' : '';

    echo $this->element('genericElementsBS5/Badges/tag', [
        'tag' => $tagWrapper['Tag'],
        'local' => $tagWrapper['local'] ?? false,
        'hiddenClass' => $hiddenClass,
        'showFavourite' => false
    ]);

    $visibleIndex++;
}
?>

<?php if ($hiddenCount > 0): ?>
    <span
        class="badge bg-secondary text-white me-1 mb-1 tag-expand"
        style="cursor:pointer;"
        onclick="toggleTags(this)"
    >
        +<?= $hiddenCount ?>
    </span>
<?php endif; ?>

<?php if (!empty($addUrl)): ?>
    <button
        type="button"
        class="badge border-0 me-1 mb-1 attr-add-tag-btn"
        style="cursor:pointer; background:#DB6A4718; color:#DB6A47;"
        title="<?= __('Add a tag') ?>"
        aria-label="<?= __('Add a tag') ?>"
        onclick="event.stopPropagation(); openModal('<?= h($addUrl) ?>', 'xl');"
    >
        <i class="fas fa-plus"></i>
    </button>
<?php endif; ?>

</div>
