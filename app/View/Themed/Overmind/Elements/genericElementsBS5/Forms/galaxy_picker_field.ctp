<?php
/*
 * The theme's galaxy-cluster picker as a form field — same galaxy category
 * buttons, same remote search and same badges as Modals/galaxy_picker.ctp
 * (both run initGalaxyPickerSection()), except the selection ends up in hidden
 * inputs instead of a JSON POST, so it travels with the surrounding form.
 *
 * Required params:
 *   $field       string  dotted field path, e.g. 'TagCollection.galaxies'
 *   $uid         string  unique DOM id fragment (e.g. 'tc-galaxies')
 *   $galaxyList  [{id, name, icon}, ...]  for the category buttons
 * Optional params:
 *   $selected    [{id, name, galaxy, hue}, ...] pre-selected clusters
 *   $placeholder string  search input placeholder
 *   $emptyText   string  shown while nothing is selected
 */

$selected = $selected ?? [];
$placeholder = $placeholder ?? __('Search clusters to add…');
$emptyText = $emptyText ?? __('No clusters selected.');

$this->Form->unlockField($field);
$inputName = 'data[' . implode('][', explode('.', $field)) . ']';

$searchUrl = $baseurl . '/events/searchGalaxyClusters';

/* FontAwesome brand-icon names (rendered with the `fab` prefix) */
$brandIcons = [
    'github', 'gitlab', 'docker', 'linux', 'android', 'apple',
    'google', 'microsoft', 'facebook', 'twitter', 'linkedin',
    'btc', 'ethereum', 'optin-monster', 'internet-explorer',
];
?>

<div class="om-galaxy-picker" data-galaxy-picker="<?= h($uid) ?>">

    <!-- Category buttons: All + one per galaxy (scrollable) -->
    <div class="border rounded p-2 mb-2"
         style="max-height:118px; overflow-y:auto;">
        <div class="d-flex flex-wrap gap-2 galaxy-cat-list">
            <button type="button"
                    class="btn btn-sm btn-outline-galaxy galaxy-cat-btn active"
                    data-cat="all"><?= __('All Galaxies') ?></button>
            <?php foreach ($galaxyList as $g):
                $pref = in_array($g['icon'], $brandIcons, true) ? 'fab' : 'fas';
            ?>
                <button type="button"
                        class="btn btn-sm btn-outline-galaxy galaxy-cat-btn"
                        data-cat="galaxy"
                        data-galaxy-id="<?= (int)$g['id'] ?>"
                        title="<?= h($g['name']) ?>">
                    <i class="<?= $pref ?> fa-<?= h($g['icon']) ?> me-1"></i><?= h($g['name']) ?>
                </button>
            <?php endforeach; ?>
        </div>
    </div>

    <select class="galaxy-picker" placeholder="<?= h($placeholder) ?>"></select>
    <?= $this->element('genericElementsBS5/Forms/field_hint', [
        'text' => __('Type at least 2 characters to search across all galaxies.'),
    ]) ?>

    <div class="mt-2 d-flex flex-wrap gap-2 galaxy-selected"></div>
    <div class="text-muted small fst-italic galaxy-selected-empty">
        <?= h($emptyText) ?>
    </div>

    <div class="galaxy-picker-inputs d-none">
        <input type="hidden" name="<?= h($inputName) ?>" value="">
        <?php foreach ($selected as $cluster): ?>
            <input type="hidden" name="<?= h($inputName) ?>[]"
                   value="<?= h($cluster['id']) ?>">
        <?php endforeach; ?>
    </div>

</div>

<script>
(function () {
    var uid = <?= json_encode($uid, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var inputName = <?= json_encode($inputName, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var searchUrl = <?= json_encode($searchUrl, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var initClusters = <?= json_encode($selected, JSON_HEX_TAG | JSON_HEX_AMP) ?: '[]' ?>;

    var root = document.querySelector('[data-galaxy-picker="' + uid + '"]');
    if (!root || root.dataset.galaxyPickerReady) { return; }
    root.dataset.galaxyPickerReady = '1';

    var inputsEl = root.querySelector('.galaxy-picker-inputs');

    initGalaxyPickerSection(root, initClusters, {
        searchUrl: searchUrl,
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
