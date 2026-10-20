<?php
/**
 * The bookmarks panel's list (Elements/bookmarks_panel.ctp): the user's own
 * bookmarks, then the ones their organisation shares. bookmarks-panel.js
 * filters it and marks the page the user is on.
 */
$host = (string)$this->request->host();
$sections = [
    ['title' => __('Mine'), 'items' => $mine, 'own' => true],
    ['title' => __('Shared by %s', $orgName), 'items' => $shared, 'own' => false],
];
$total = count($mine) + count($shared);
?>
<?php if ($total === 0): ?>
    <div class="sp-empty">
        <i class="fas fa-star" aria-hidden="true"></i>
        <strong><?= __('No bookmarks yet.') ?></strong>
        <p><?= __('Bookmark the pages you come back to, and they show up here.') ?></p>
    </div>
<?php endif; ?>
<?php foreach ($sections as $section): ?>
    <?php if (empty($section['items'])) continue; ?>
    <section class="bm-section">
        <h3 class="bm-section-title">
            <?= h($section['title']) ?>
            <span class="bm-section-count"><?= count($section['items']) ?></span>
        </h3>
        <?php foreach ($section['items'] as $bookmark): ?>
            <?php
            $b = $bookmark['Bookmark'];
            $url = (string)$b['url'];
            $parts = preg_match('#^https?://#i', $url) ? parse_url($url) : false;
            $local = false;
            $shown = $url;
            if ($parts) {
                $local = strcasecmp(($parts['host'] ?? '') . (isset($parts['port']) ? ':' . $parts['port'] : ''), $host) === 0;
                $shown = $local
                    ? ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '')
                    : preg_replace('#^https?://#i', '', $url);
            }
            $search = mb_strtolower($b['name'] . ' ' . $url . ' ' . ($b['comment'] ?? ''));
            ?>
            <div class="bm-item" data-bm-text="<?= h($search) ?>">
                <?php if ($parts): ?>
                    <a class="bm-link" href="<?= h($url) ?>" data-bm-href<?= $local ? '' : ' target="_blank" rel="noopener noreferrer"' ?>>
                <?php else: ?>
                    <span class="bm-link">
                <?php endif; ?>
                    <span class="bm-ico" aria-hidden="true"><i class="fas fa-bookmark"></i></span>
                    <span class="bm-text">
                        <span class="bm-name">
                            <span><?= h($b['name']) ?></span>
                            <?php if ($section['own'] && !empty($b['exposed_to_org'])): ?>
                                <span class="bm-tag" title="<?= __('Every user of your organisation sees it') ?>"><?= __('Shared') ?></span>
                            <?php endif; ?>
                        </span>
                        <span class="bm-url" title="<?= h($url) ?>"><?= h($shown) ?></span>
                    </span>
                    <?php if ($parts && !$local): ?>
                        <i class="fas fa-arrow-up-right-from-square bm-ext" title="<?= __('Opens in a new tab') ?>"></i>
                    <?php endif; ?>
                <?= $parts ? '</a>' : '</span>' ?>
                <?php if (!empty($b['comment'])): ?>
                    <p class="bm-comment"><?= h($b['comment']) ?></p>
                <?php endif; ?>
                <?php if (!empty($b['may_modify'])): ?>
                    <div class="bm-acts">
                        <button type="button" class="sp-tool" data-sp-modal="<?= h($baseurl . '/bookmarks/edit/' . $b['id']) ?>"
                                title="<?= __('Edit') ?>" aria-label="<?= h(__('Edit %s', $b['name'])) ?>">
                            <i class="fas fa-pen-to-square" aria-hidden="true"></i>
                        </button>
                        <button type="button" class="sp-tool sp-tool-danger" data-sp-modal="<?= h($baseurl . '/bookmarks/deleteSelection/' . $b['id']) ?>"
                                data-sp-modal-size="md" title="<?= __('Delete') ?>" aria-label="<?= h(__('Delete %s', $b['name'])) ?>">
                            <i class="fas fa-trash" aria-hidden="true"></i>
                        </button>
                    </div>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </section>
<?php endforeach; ?>
<?php if ($total > 0): ?>
    <p class="bm-nomatch" data-bm-nomatch hidden><?= __('No bookmark matches.') ?></p>
<?php endif; ?>
