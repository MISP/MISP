<?php
/**
 * The filter bar of a server settings page: the index filter bar's look
 * (IndexTable/filter_bar, index-filters.css) over a filter that runs
 * client-side, every keystroke and toggle applying at once (server-settings.js).
 *
 * The search box, the Filters button and its panel of switches, then the row
 * with the count and the chips, which the panel's foot repeats.
 *
 * Params:
 *  - search  array  ['placeholder', 'label', 'attr'] — attr marks the input
 *                   for server-settings.js (data-ss-filter, data-ss-module-filter)
 *  - toggles array  [{key, label, icon, count, title, countAttr}] in the panel;
 *                   countAttr is name => value on the count, for the JS to refresh it
 *  - toggleAttr string attribute carrying a toggle's key (data-ss-toggle,
 *                   data-ss-module-only)
 */
$panelId = 'ssFilterPanel' . dechex(mt_rand());
$toggles = $toggles ?? array();
?>
<div class="ifp-bar d-flex flex-wrap align-items-center" data-ss-bar>
    <label class="ifp-query">
        <i class="fas fa-search ifp-q-icon" aria-hidden="true"></i>
        <input type="search" <?= h($search['attr']) ?> autocomplete="off" spellcheck="false" aria-keyshortcuts="/"
               aria-label="<?= h($search['label'] ?? $search['placeholder']) ?>"
               placeholder="<?= h($search['placeholder']) ?>">
        <span class="ifp-q-end">
            <button type="button" class="ifp-q-clear" data-ss-query-clear
                    title="<?= h(__('Clear the search')) ?>" aria-label="<?= h(__('Clear the search')) ?>">
                <i class="fas fa-times" aria-hidden="true"></i>
            </button>
            <kbd class="ifp-q-kbd" title="<?= h(__('Press / to search')) ?>">/</kbd>
        </span>
    </label>

    <?php if (!empty($toggles)): ?>
        <button type="button" class="ifp-fbtn" data-ss-filters aria-expanded="false" aria-controls="<?= h($panelId) ?>"
                title="<?= h(__('Show or hide the filters (F)')) ?>" aria-keyshortcuts="f">
            <i class="fas fa-sliders" aria-hidden="true"></i>
            <span><?= h(__('Filters')) ?></span>
            <span class="badge rounded-pill bg-primary" data-ss-filters-count hidden>0</span>
            <i class="fas fa-chevron-down ifp-caret" aria-hidden="true"></i>
        </button>
        <div class="ifp-panel" id="<?= h($panelId) ?>" role="region" aria-label="<?= h(__('Filters')) ?>" hidden>
            <div class="ifp-panel-body">
                <div class="ifp-quicks">
                    <?php foreach ($toggles as $toggle): ?>
                        <button type="button" class="ifp-quick" role="switch" aria-checked="false"
                                <?= h($toggleAttr) ?>="<?= h($toggle['key']) ?>"<?php
                                if (!empty($toggle['title'])): ?> title="<?= h($toggle['title']) ?>"<?php endif; ?>>
                            <span class="ifp-switch" aria-hidden="true"></span>
                            <i class="<?= h($toggle['icon']) ?>" aria-hidden="true"></i>
                            <span class="ifp-quick-label"><?= h($toggle['label']) ?></span>
                            <?php if (isset($toggle['count'])): ?>
                                <span class="ifp-quick-n"<?php
                                    foreach (($toggle['countAttr'] ?? array()) as $attrName => $attrValue): ?> <?= h($attrName) ?>="<?= h($attrValue) ?>"<?php
                                    endforeach; ?>><?= h($toggle['count']) ?></span>
                            <?php endif; ?>
                        </button>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="ifp-win-foot">
                <div class="ifp-chips" data-ss-chips></div>
            </div>
        </div>
    <?php endif; ?>
</div>
<div class="ifp-row">
    <span class="ifp-count" data-ss-count></span>
    <div class="ifp-chips" data-ss-chips hidden></div>
</div>
