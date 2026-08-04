<?php
/**
 * Beta UI — Event Collections index
 *
 * A card-grid replacement for the generic scaffold table.
 * No sidebar, consistent with the beta Events/index pattern.
 *
 * @since 2.5.x (beta)
 */

$currentFilter = $this->request->params['pass'][0] ?? null;
$collectionsIndexUrl = $baseurl . '/collections/index';

$buildCollectionsIndexUrl = function ($suffix = '') use ($collectionsIndexUrl) {
    return $collectionsIndexUrl . ($suffix !== '' ? '/' . $suffix : '');
};

$isCollectionsFilterActive = function ($filterName) use ($currentFilter) {
    return $currentFilter === $filterName;
};
?>
<div class="collections index beta-collections-index">

    <!-- Header row -->
    <div class="beta-events-header-row">
        <div class="beta-header-left">
            <h2><?= __('Event Collections') ?></h2>
            <div class="beta-header-filters beta-collections-filters">
                <?php if ($this->Acl->canAccess('collections', 'add')): ?>
                    <div class="btn-group beta-create-event-group">
                        <button class="btn btn-primary"
                                onclick="openGenericModal('<?= $baseurl ?>/collections/add')">
                            <i class="fa fa-plus"></i> <?= __('New Collection') ?>
                        </button>
                    </div>
                <?php endif; ?>
                <a href="<?= $buildCollectionsIndexUrl('my_collections') ?>"
                   class="btn btn-default beta-filter-button <?= $isCollectionsFilterActive('my_collections') ? 'active' : '' ?>">
                    <?= __('My Collections') ?>
                </a>
                <a href="<?= $buildCollectionsIndexUrl('org_collections') ?>"
                   class="btn btn-default beta-filter-button <?= $isCollectionsFilterActive('org_collections') ? 'active' : '' ?>">
                    <?= __('Org Collections') ?>
                </a>
                <a href="<?= $collectionsIndexUrl ?>"
                   class="btn btn-default beta-filter-button">
                    <?= __('All Collections') ?>
                </a>
                <div class="beta-search-controls">
                    <div class="beta-search-input-group">
                        <div class="beta-search-input-wrap">
                            <input type="text" id="collectionsQuickFilter" class="form-control beta-search-input"
                                   placeholder="<?= __('Search collections…') ?>">
                            <?php if (!empty($passedArgs)): ?>
                                <a href="<?= $baseurl ?>/collections/index" id="collectionsFilterClear" class="beta-search-clear" title="<?= __('Clear filter') ?>">
                                    <i class="fa fa-times"></i>
                                </a>
                            <?php endif; ?>
                        </div>
                        <button id="collectionsFilterBtn" class="btn btn-primary beta-search-button">
                            <?= __('Filter') ?>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <?php
    // Decode active quick-filter if any
    $activeQuickFilter = '';
    if (!empty($passedArgs)) {
        $decoded = json_decode($passedArgs, true);
        if (!empty($decoded['quickFilter'])) {
            $activeQuickFilter = $decoded['quickFilter'];
        }
    }
    ?>
    <?php if (!empty($activeQuickFilter)): ?>
        <div class="beta-active-filters">
            <span class="bold"><?= __('Filter') ?>:</span> <?= h($activeQuickFilter) ?>
            <a href="<?= $collectionsIndexUrl ?>" class="btn btn-xs btn-default" title="<?= __('Clear') ?>">
                <i class="fa fa-times"></i> <?= __('Clear') ?>
            </a>
        </div>
    <?php endif; ?>

    <!-- Pagination (top) -->
    <div class="beta-pagination-top" style="margin-bottom:1rem;">
        <?php
            $pagination = $this->Paginator->prev('&laquo; ' . __('previous'), ['tag' => 'li', 'escape' => false], null, ['tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span']);
            $pagination .= $this->Paginator->numbers(['modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span']);
            $pagination .= $this->Paginator->next(__('next') . ' &raquo;', ['tag' => 'li', 'escape' => false], null, ['tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span']);
        ?>
        <div class="pagination" style="margin:0;"><ul><?= $pagination ?></ul></div>
    </div>

    <!-- Collection cards grid -->
    <div class="beta-collections-grid">
        <?php if (empty($data)): ?>
            <div class="beta-collections-empty">
                <i class="fa fa-folder-open fa-3x" style="color:#dee2e6; margin-bottom:1rem;"></i>
                <p><?= __('No collections found.') ?></p>
                <?php if ($this->Acl->canAccess('collections', 'add')): ?>
                    <button class="btn btn-primary"
                            onclick="openGenericModal('<?= $baseurl ?>/collections/add')">
                        <i class="fa fa-plus"></i> <?= __('Create your first collection') ?>
                    </button>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <?php foreach ($data as $collection): ?>
                <?php
                    $c = $collection['Collection'];
                    $orgName = !empty($collection['Orgc']['name']) ? $collection['Orgc']['name'] : (!empty($c['Orgc']['name']) ? $c['Orgc']['name'] : '');
                    $type = !empty($c['type']) ? $c['type'] : 'other';
                    $elementCount = isset($c['element_count']) ? (int)$c['element_count'] : 0;
                    $distribution = isset($c['distribution']) ? (int)$c['distribution'] : 0;
                    $sgName = !empty($collection['SharingGroup']['name']) ? $collection['SharingGroup']['name'] : '';
                    $distLabel = $distribution == 4 ? $sgName : (isset($distributionLevels[$distribution]) ? $distributionLevels[$distribution] : '');
                    $description = !empty($c['description']) ? $c['description'] : '';
                    $created = !empty($c['created']) ? $c['created'] : '';
                    $modified = !empty($c['modified']) ? $c['modified'] : '';
                ?>
                <div class="beta-collection-card">
                    <div class="beta-collection-card-header">
                        <a href="<?= $baseurl ?>/collections/view/<?= h($c['id']) ?>"
                           class="beta-collection-name">
                            <?= h($c['name']) ?>
                        </a>
                        <span class="beta-collection-type-badge beta-type-<?= h($type) ?>">
                            <?= h($type) ?>
                        </span>
                    </div>

                    <?php if (!empty($description)): ?>
                        <div class="beta-collection-description">
                            <?= nl2br(h($description)) ?>
                        </div>
                    <?php else: ?>
                        <div class="beta-collection-description beta-collection-no-desc">
                            <em><?= __('No description provided.') ?></em>
                        </div>
                    <?php endif; ?>

                    <div class="beta-collection-card-footer">
                        <span class="beta-collection-meta-item" title="<?= __('Organisation') ?>">
                            <i class="fa fa-building" style="color:#888;"></i>
                            <?= h($orgName) ?>
                        </span>
                        <span class="beta-collection-meta-item" title="<?= __('Events / elements') ?>">
                            <i class="fa fa-layer-group" style="color:#888;"></i>
                            <?= $elementCount ?> <?= $elementCount === 1 ? __('element') : __('elements') ?>
                        </span>
                        <span class="beta-collection-meta-item">
                            <span class="dist-widget dist-<?= $distribution ?>"
                                  title="<?= h($distLabel) ?>"></span>
                            <small><?= h($distLabel) ?></small>
                        </span>
                        <div class="beta-collection-actions">
                            <a href="<?= $baseurl ?>/collections/view/<?= h($c['id']) ?>"
                               class="btn btn-xs btn-default" title="<?= __('View') ?>">
                                <i class="fa fa-eye"></i>
                            </a>
                            <?php if ($this->Acl->canAccess('collections', 'edit')): ?>
                                <a href="#" onclick="openGenericModal('<?= $baseurl ?>/collections/edit/<?= h($c['id']) ?>'); return false;"
                                   class="btn btn-xs btn-default" title="<?= __('Edit') ?>">
                                    <i class="fa fa-edit"></i>
                                </a>
                            <?php endif; ?>
                            <?php if ($this->Acl->canAccess('collections', 'delete')): ?>
                                <a href="#" onclick="openGenericModal('<?= $baseurl ?>/collections/delete/<?= h($c['id']) ?>'); return false;"
                                   class="btn btn-xs btn-danger" title="<?= __('Delete') ?>">
                                    <i class="fa fa-trash"></i>
                                </a>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>

    <!-- Pagination (bottom) -->
    <div class="beta-pagination-bottom">
        <p>
            <?php
            echo $this->Paginator->counter([
                'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
            ]);
            ?>
        </p>
        <div class="pagination"><ul><?= $pagination ?></ul></div>
    </div>
</div>

<script>
$(function() {
    var collectionsIndexUrl = <?= json_encode($collectionsIndexUrl) ?>;

    function applyCollectionsQuickFilter() {
        var val = $('#collectionsQuickFilter').val().trim();
        window.location.href = val
            ? collectionsIndexUrl + '/quickFilter:' + encodeURIComponent(val)
            : collectionsIndexUrl;
    }

    <?php if (!empty($activeQuickFilter)): ?>
    $('#collectionsQuickFilter').val(<?= json_encode($activeQuickFilter) ?>);
    <?php endif; ?>

    $('#collectionsFilterBtn').on('click', function(e) {
        e.preventDefault();
        applyCollectionsQuickFilter();
    });

    $('#collectionsQuickFilter').on('keypress', function(e) {
        if (e.which === 13) {
            e.preventDefault();
            applyCollectionsQuickFilter();
        }
    });

    $('#collectionsFilterClear').on('click', function(e) {
        e.preventDefault();
        $('#collectionsQuickFilter').val('');
        window.location.href = collectionsIndexUrl;
    });
});
</script>
