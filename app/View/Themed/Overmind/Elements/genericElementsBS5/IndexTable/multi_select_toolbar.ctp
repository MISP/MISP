<?php
$filter_bar = $filter_bar ?? [];
?>
<div id="multiSelectToolbar"
     class="mt-2 d-none">

    <div class="p-2 border rounded bg-light d-flex align-items-center gap-2 flex-wrap">

        <strong>
            <?= __('Selected items') ?>:
            <span id="selectedCount">0</span>
        </strong>

        <?php if (!empty($filter_bar['export'])): ?>
            <button id="multi-export-button"
                    class="btn btn-primary btn-sm ms-2"
                    title="<?= __('Export selected attributes') ?>"
                    aria-label="<?= __('Export selected attributes') ?>"
                    onclick="multiSelectItems('<?= h($baseurl . $item_url . '/restSearchExport') ?>', '')">
                <i class="fas fa-file-export"></i>
                <?= __('Export') ?>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['fetch'])): ?>
            <?php
                // Remote-preview indexes are scoped by a positional id, so they
                // pass the whole path in `fetch_url` instead of a suffix.
                $massFetchUrl = !empty($filter_bar['fetch_url'])
                    ? ($baseurl . $filter_bar['fetch_url'])
                    : ($baseurl . $item_url . $filter_bar['fetch']);
            ?>
            <button id="mass-fetch-button"
                    class="btn btn-primary btn-sm ms-2 d-none"
                    title="<?= __('Fetch the selected events') ?>"
                    aria-label="<?= __('Fetch the selected events') ?>"
                    onclick="multiSelectItems('<?= h($massFetchUrl) ?>', '')">
                <i class="fas fa-circle-arrow-down"></i>
                <?= __('Fetch') ?>
            </button>
        <?php endif; ?>

        <?php
            /*
             * Only for specific indexes that need a custom action button in the mass-action toolbar.
             */
            foreach (($filter_bar['custom_actions'] ?? []) as $customAction):
        ?>
            <button id="<?= h($customAction['id']) ?>"
                    class="btn btn-sm ms-2 <?= h($customAction['class'] ?? 'btn-primary') ?>"
                    title="<?= h($customAction['label']) ?>"
                    aria-label="<?= h($customAction['label']) ?>"
                    onclick="<?= h($customAction['onclick']) ?>">
                <?php if (!empty($customAction['icon'])): ?>
                    <i class="fas fa-<?= h($customAction['icon']) ?>"></i>
                <?php endif; ?>
                <?= h($customAction['label']) ?>
            </button>
        <?php endforeach; ?>

        <?php if (!empty($filter_bar['mass_edit'])): ?>
            <button id="mass-edit-button"
                    class="btn btn-secondary btn-sm d-none"
                    title="<?= __('Edit selected attributes') ?>"
                    aria-label="<?= __('Edit selected attributes') ?>"
                    onclick="multiSelectItems('#', '')">
                <i class="fas fa-edit text-white"></i>
                <span class="text-white"> <?= __('Edit') ?></span>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['mass_tag'])): ?>
            <button id="mass-tag-button"
                    class="btn btn-tag btn-sm d-none"
                    title="<?= __('Add Tag on selected attributes') ?>"
                    aria-label="<?= __('Add Tag on selected attributes') ?>"
                    onclick="multiSelectItems('#', '')">
                <span class="misp-icon misp-icon-tag misp-simple text-white"></span>
                <span class="text-white"> <?= __('Tag') ?></span>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['mass_local_tag'])): ?>
            <button id="mass-local-tag-button"
                    class="btn btn-tag btn-sm d-none"
                    title="<?= __('Add Local Tag on selected attributes') ?>"
                    aria-label="<?= __('Add Local Tag on selected attributes') ?>"
                    onclick="multiSelectItems('#', '')">
                <i class="fas fa-user text-white"></i>
                <span class="text-white"> <?= __('Local Tag') ?></span>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['mass_cluster'])): ?>
            <button id="mass-cluster-button",
                    class="btn btn-galaxy btn-sm d-none"
                    title="<?= __('Add Cluster on selected attributes') ?>"
                    aria-label="<?= __('Add Cluster to selected attributes') ?>"
                    onclick="multiSelectItems('#', '')">
                <span class="misp-icon misp-icon-galaxy misp-simple text-white"></span>
                <span class="text-white"> <?= __('Cluster') ?></span>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['mass_local_cluster'])): ?>
            <button id="mass-local-cluster-button"
                    class="btn btn-galaxy btn-sm d-none"
                    title="<?= __('Add Local Cluster on selected attributes') ?>"
                    aria-label="<?= __('Add Local Cluster to selected attributes') ?>"
                    onclick="multiSelectItems('#', '')">
                <i class="fas fa-user text-white"></i>
                <span class="text-white"> <?= __('Local Cluster') ?></span>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['mass_object'])): ?>
            <button id="mass-object-button"
                    class="btn btn-object btn-sm d-none"
                    title="<?= __('Group selected Attributes into an Object') ?>"
                    aria-label="<?= __('Group selected Attributes into an Object') ?>"
                    onclick="multiSelectItems('#', '')">
                <span class="misp-icon misp-icon-object misp-simple text-white"></span>
                <span class="text-white"> <?= __('Object') ?></span>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['mass_relationship'])): ?>
            <button id="mass-relationship-button"
                    class="btn btn-correlation btn-sm d-none"
                    title="<?= __('Create new relationship for selected entities') ?>"
                    aria-label="<?= __('Create new relationship for selected entities') ?>"
                    onclick="multiSelectItems('#', '')">
                <i class="fas fa-diagram-project text-white"></i>
                <span class="text-white"> <?= __('Relationship') ?></span>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['mass_sighting'])): ?>
            <button id="mass-sighting-button"
                    class="btn btn-sighting btn-sm d-none"
                    title="<?= __('Sightings display for selected attributes') ?>"
                    aria-label="<?= __('Sightings display for selected attributes') ?>"
                    onclick="multiSelectItems('#', '')">
                <span class="misp-icon misp-icon-sighting misp-simple text-white"></span>
                <span class="text-white"> <?= __('Sightings') ?></span>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['enable'])): ?>
            <?php
                /*
                 * Controllers exposing a single toggle endpoint that takes the
                 * target state positionally (feeds: /toggleSelected/<on>/<cache>)
                 * pass the whole path in `enable_url` / `disable_url` instead of
                 * relying on the massEnable/massDisable convention.
                 */
                $massEnableUrl = !empty($filter_bar['enable_url'])
                    ? ($baseurl . $filter_bar['enable_url'])
                    : ($baseurl . $item_url . '/massEnable');
                $massDisableUrl = !empty($filter_bar['disable_url'])
                    ? ($baseurl . $filter_bar['disable_url'])
                    : ($baseurl . $item_url . '/massDisable');
            ?>
            <button id="mass-enable-button"
                    class="btn btn-outline-success btn-sm d-none"
                    title="<?= __('Enable selected items') ?>"
                    onclick="multiSelectItems('<?= h($massEnableUrl) ?>', '')">
                <i class="fas fa-play"></i> <?= __('Enable') ?>
            </button>
            <button id="mass-disable-button"
                    class="btn btn-outline-danger btn-sm d-none"
                    title="<?= __('Disable selected items') ?>"
                    onclick="multiSelectItems('<?= h($massDisableUrl) ?>', '')">
                <i class="fas fa-stop"></i> <?= __('Disable') ?>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['require'])): ?>
            <button id="mass-require-button"
                    class="btn btn-dark btn-sm d-none"
                    title="<?= __('Make the selected items required') ?>"
                    onclick="multiSelectItems('<?= h($baseurl . $item_url . '/massRequire') ?>', '')">
                <i class="fas fa-asterisk"></i> <?= __('Required') ?>
            </button>
            <button id="mass-optional-button"
                    class="btn btn-outline-dark btn-sm d-none"
                    title="<?= __('Make the selected items optional') ?>"
                    onclick="multiSelectItems('<?= h($baseurl . $item_url . '/massOptional') ?>', '')">
                <i class="fas fa-question"></i> <?= __('Optional') ?>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['highlight'])): ?>
            <button id="mass-highlight-button"
                    class="btn btn-primary btn-sm d-none"
                    title="<?= __('Highlight selected items') ?>"
                    onclick="multiSelectItems('<?= h($baseurl . $item_url . '/massHighlight') ?>', '')">
                <i class="fas fa-highlighter"></i> <?= __('Highlight') ?>
            </button>
            <button id="mass-removehighlight-button"
                    class="btn btn-outline-primary btn-sm d-none"
                    title="<?= __('Remove highlight for selected items') ?>"
                    onclick="multiSelectItems('<?= h($baseurl . $item_url . '/massRemoveHighlight') ?>', '')">
                <i class="fas fa-down-long"></i> <?= __('Remove Highlight') ?>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['activate'])): ?>
            <button id="mass-activate-button"
                    class="btn btn-outline-success btn-sm d-none"
                    title="<?= __('Activate selected items') ?>"
                    onclick="multiSelectItems('<?= h($baseurl . $item_url . '/massActivate') ?>', '')">
                <i class="fas fa-play"></i> <?= __('Activate') ?>
            </button>
            <button id="mass-deactivate-button"
                    class="btn btn-outline-danger btn-sm d-none"
                    title="<?= __('Deactivate selected items') ?>"
                    onclick="multiSelectItems('<?= h($baseurl . $item_url . '/massDeactivate') ?>', '')">
                <i class="fas fa-stop"></i> <?= __('Deactivate') ?>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['soft_delete'])): ?>
            <button id="multi-soft-delete-button"
                    class="btn btn-warning btn-sm d-none"
                    title="<?= __('Soft-delete selected items') ?>"
                    aria-label="<?= __('Soft-delete selected items') ?>"
                    onclick="multiSelectItems('<?= h($baseurl . $item_url . $filter_bar['soft_delete']) ?>', '')">
                <i class="fas fa-trash"></i>
                <span> <?= __('Soft-delete') ?></span>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['accept'])): ?>
            <button id="mass-accept-button"
                    class="btn btn-success btn-sm"
                    title="<?= __('Process the selected registrations') ?>"
                    aria-label="<?= __('Process the selected registrations') ?>"
                    onclick="multiSelectItems('<?= h($baseurl . $item_url . $filter_bar['accept']) ?>', '', 'xl')">
                <i class="fas fa-check"></i>
                <span> <?= __('Process') ?></span>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['discard'])): ?>
            <button id="mass-discard-button"
                    class="btn btn-danger btn-sm"
                    title="<?= __('Discard the selected registrations') ?>"
                    aria-label="<?= __('Discard the selected registrations') ?>"
                    onclick="multiSelectItems('<?= h($baseurl . $item_url . $filter_bar['discard']) ?>', '')">
                <i class="fas fa-trash text-white"></i>
                <span class="text-white"> <?= __('Discard') ?></span>
            </button>
        <?php endif; ?>

        <?php if (!empty($filter_bar['delete'])): ?>
            <?php
                // `delete_url` overrides the constructed URL for indexes whose
                // item_url is not the plain controller
                $multiDeleteUrl = !empty($filter_bar['delete_url'])
                    ? ($baseurl . $filter_bar['delete_url'])
                    : ($baseurl . $item_url . $filter_bar['delete']);
            ?>
            <button id="multi-delete-button"
                    class="btn btn-danger btn-sm d-none"
                    title="<?= __('Delete selected items') ?>"
                    aria-label="<?= __('Delete selected items') ?>"
                    onclick="multiSelectItems('<?= h($multiDeleteUrl) ?>', '/true')">
                <i class="fas fa-trash text-white"></i>
                <span class="text-white"> <?= __('Delete') ?></span>
            </button>
        <?php endif; ?>

    </div>
</div>
