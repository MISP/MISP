<?php
$data = Hash::extract($row, $field['data_path']);

/*
 * Optional inline "+" button to attach a tag to this object. Enabled by the
 * caller via $field['add_tag'] (already ACL-gated upstream). $field['add_tag_url']
 * holds a URL template with a %id% placeholder, resolved from
 * $field['add_tag_id_path'] (falls back to $row['id']).
 * $field['add_relationship_url'] adds its sibling
 */
// A callable lets the caller decide per row — an extended event view
// grants the button on the rows of the events you can actually tag.
$allowAddTag = $field['add_tag'] ?? false;
if (is_callable($allowAddTag)) {
    $allowAddTag = $allowAddTag($row);
}
$allowAddTag = !empty($allowAddTag);
$addUrl      = null;
$addRelationshipUrl = null;
if ($allowAddTag) {
    $addId = Hash::get($row, $field['add_tag_id_path'] ?? 'id');
    if (empty($addId) && !empty($row['id'])) {
        $addId = $row['id'];
    }
    $isDeleted = !empty($row['deleted']) || !empty($row['Attribute']['deleted']);
    if (!empty($addId) && !$isDeleted) {
        if (!empty($field['add_tag_url'])) {
            $addUrl = str_replace(
                '%id%', rawurlencode($addId), $field['add_tag_url']
            );
        }
        if (!empty($field['add_relationship_url'])) {
            $addRelationshipUrl = str_replace(
                '%id%', rawurlencode($addId), $field['add_relationship_url']
            );
        }
    }
}

$data = $data ?: [];
if (isset($data['name'])) {
    $data = [$data];
}
$normalised = [];
foreach ($data as $entry) {
    if (!is_array($entry)) {
        continue;
    }
    if (isset($entry['Tag'])) {
        $normalised[] = $entry;
    } elseif (isset($entry['name'])) {
        $normalised[] = ['Tag' => $entry, 'local' => $entry['local'] ?? false];
    }
}
$data = $normalised;

/*
 * Some records carry a tag collection instead of a tag (feeds, servers).
 */
$tagCollection = null;
if (empty($data) && !empty($field['tag_collection_path'])) {
    $collections = Hash::get($row, $field['tag_collection_path']);
    if (!empty($collections[0]['TagCollection'])) {
        $tagCollection = $collections[0]['TagCollection'];
        foreach (Hash::extract($collections[0], 'TagCollectionTag.{n}.Tag') as $tag) {
            $data[] = ['Tag' => $tag, 'local' => false];
        }
    }
}

if (empty($data) && empty($tagCollection) && empty($addUrl)) {
    return;
}

// Count only real tags, not galaxy-tags
$realTags = array_filter($data, function($t) {
    return !empty($t['Tag']) && empty($t['Tag']['is_galaxy']);
});
$totalTags   = count($realTags);

// Nothing attached, nothing to relate
if ($totalTags === 0) {
    $addRelationshipUrl = null;
}

?>

<div class="tag-container d-inline-flex flex-wrap align-items-center gap-1">

<?php if (!empty($tagCollection)): ?>
    <a
        class="badge bg-body border text-body-emphasis me-1 mb-1"
        href="<?= h($baseurl . '/tag_collections/view/' . $tagCollection['id']) ?>"
        title="<?= h(__('Tag Collection')) ?>"
    >
        <i class="fas fa-layer-group me-1"></i><?= h($tagCollection['name']) ?>
    </a>
<?php endif; ?>

<?php
$realTags = array_values($realTags);
// Optional reader's label priority; absent or undeclared keeps arrival order
if (!empty($field['plan'])) {
    App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
    foreach ($realTags as $at => $tag) {
        $realTags[$at]['name'] = $tag['Tag']['name'] ?? null;
        $realTags[$at]['key'] = ValueLabelPriority::namespaceOf(
            $realTags[$at]['name']
        );
    }
    $realTags = ValueLabelPriority::labels(
        $realTags,
        $field['plan'],
        ValueLabelPriority::TAXONOMIES
    );
}
echo $this->TagChip->collection($realTags, [
    'searchUrl' => '',
    'fold' => 5,
    'limit' => 4,
]);
?>

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

<?php if (!empty($addRelationshipUrl)): ?>
    <button
        type="button"
        class="badge border-0 me-1 mb-1 attr-add-relationship-btn"
        style="cursor:pointer; background:#DB6A4718; color:#DB6A47;"
        title="<?= __('Add a relationship') ?>"
        aria-label="<?= __('Add a relationship') ?>"
        onclick="event.stopPropagation(); openModal('<?= h($addRelationshipUrl) ?>', 'xl');"
    >
        <i class="fas fa-link"></i>
    </button>
<?php endif; ?>

</div>
