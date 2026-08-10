<?php
/*
 * The theme's tag picker as a form field — same category buttons, same search
 * and same badges as Modals/tag_picker.ctp (both run initTagPickerSection()),
 * except the selection ends up in hidden inputs instead of a JSON POST, so it
 * travels with the surrounding form.
 *
 * Required params:
 *   $field       string  dotted field path, e.g. 'TagCollection.tags'
 *   $uid         string  unique DOM id fragment (e.g. 'tc-tags')
 *   $categories  ordered map of category => ['label' => string, 'tags' => [{id,name,colour}]]
 *                (a 'collections' category expects [{id,name,tags:[{…}]}])
 * Optional params:
 *   $selected    [{id, name, colour}, ...] pre-selected tags
 *   $placeholder string  search input placeholder
 *   $emptyText   string  shown while nothing is selected
 */

$selected = $selected ?? [];
$placeholder = $placeholder ?? __('Search tags to add…');
$emptyText = $emptyText ?? __('No tags selected.');


$this->Form->unlockField($field);
$inputName = 'data[' . implode('][', explode('.', $field)) . ']';

$catData = [];
foreach ($categories as $key => $category) {
    $catData[$key] = $category['tags'] ?? [];
}
?>

<div class="om-tag-picker" data-tag-picker="<?= h($uid) ?>">

    <div class="d-flex flex-wrap gap-2 mb-2 tag-cat-list">
        <?php $first = true; foreach ($categories as $key => $category): ?>
            <button type="button"
                    class="btn btn-sm btn-outline-tag tag-cat-btn<?= $first ? ' active' : '' ?>"
                    data-cat="<?= h($key) ?>">
                <?= h($category['label'] ?? $key) ?>
            </button>
        <?php $first = false; endforeach; ?>
    </div>

    <select class="tag-picker" placeholder="<?= h($placeholder) ?>"></select>

    <div class="mt-2 d-flex flex-wrap tag-selected"></div>
    <div class="text-muted small fst-italic tag-selected-empty">
        <?= h($emptyText) ?>
    </div>


    <div class="tag-picker-inputs d-none">
        <input type="hidden" name="<?= h($inputName) ?>" value="">
        <?php foreach ($selected as $tag): ?>
            <input type="hidden" name="<?= h($inputName) ?>[]"
                   value="<?= h($tag['id']) ?>">
        <?php endforeach; ?>
    </div>

</div>

<script>
(function () {
    var uid = <?= json_encode($uid, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var inputName = <?= json_encode($inputName, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var catData = <?= json_encode($catData, JSON_HEX_TAG | JSON_HEX_AMP) ?: '{}' ?>;
    var initTags = <?= json_encode($selected, JSON_HEX_TAG | JSON_HEX_AMP) ?: '[]' ?>;

    var root = document.querySelector('[data-tag-picker="' + uid + '"]');
    if (!root || root.dataset.tagPickerReady) { return; }
    root.dataset.tagPickerReady = '1';

    var inputsEl = root.querySelector('.tag-picker-inputs');

    initTagPickerSection(root, catData, initTags, {
        onChange: function (ids) {
            /* Rebuild the posted list, keeping the empty scalar in front */
            inputsEl.innerHTML = '';
            var sentinel = document.createElement('input');
            sentinel.type = 'hidden';
            sentinel.name = inputName;
            sentinel.value = '';
            inputsEl.appendChild(sentinel);
            ids.forEach(function (id) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = inputName + '[]';
                input.value = id;
                inputsEl.appendChild(input);
            });
        }
    });
})();
</script>
