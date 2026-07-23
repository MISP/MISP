<?php
    // Pagination logic calculated here to keep EventsController minimal
    $paging = $this->params->params['paging']['Event'] ?? $this->params->params['paging']['MispAttribute'] ?? [];
    $items = isset($attributes) && is_array($attributes) ? $attributes : ($event['objects'] ?? []);
    $betaTotalAttributes = $paging['count'] ?? count($items);
    $betaPageSize = ($paging['limit'] ?? 0) != 0 ? $paging['limit'] : ($betaTotalAttributes ?: 50);
    $betaCurrentPage = $paging['page'] ?? 1;
    $betaTotalPages = $paging['pageCount'] ?? 1;
    $betaShowStart = ($betaTotalAttributes > 0) ? ($betaCurrentPage - 1) * $betaPageSize + 1 : 0;
    $betaShowEnd = min($betaCurrentPage * $betaPageSize, $betaTotalAttributes);

    $items = $this->Event->attachRelatedAttributesToItems($items, $event['RelatedAttribute'] ?? []);

    $buildWarningPopoverContent = function ($warnings) {
        $content = '';
        foreach ($warnings as $warning) {
            $content .= '<span class="bold">' . h($warning['match']) . ':</span> <span class="red">' . h($warning['warninglist_name']) . '</span>';
            if (isset($warning['comment'])) {
                $content .= ' (' . h($warning['comment']) . ')';
            }
            $content .= '<br>';
        }
        return $content;
    };

    $groupGalaxyClustersByName = function ($galaxies) {
        $clustersByGalaxy = [];
        foreach ($galaxies as $galaxy) {
            foreach ($galaxy['GalaxyCluster'] as $cluster) {
                $clustersByGalaxy[$galaxy['name']][] = $cluster;
            }
        }
        return $clustersByGalaxy;
    };

    $countRelatedEvents = function ($relatedAttributes) {
        if (empty($relatedAttributes)) {
            return 0;
        }
        $uniqueEventIds = [];
        foreach ($relatedAttributes as $relatedAttribute) {
            $uniqueEventIds[$relatedAttribute['id']] = true;
        }
        return count($uniqueEventIds);
    };

    $renderWarningIcon = function ($warnings) use ($buildWarningPopoverContent) {
        if (empty($warnings)) {
            return '';
        }
        $content = $buildWarningPopoverContent($warnings);
        return '<span aria-label="' . __('warning') . '" role="img" tabindex="0" class="fa fa-exclamation-triangle" style="color: #f0ad4e;" data-placement="right" data-toggle="popover" data-content="' . h($content) . '" data-trigger="hover">&nbsp;</span>';
    };

    $canModifyGlobalTags = $this->Acl->canModifyTag($event);
    $canModifyLocalTags = $this->Acl->canModifyTag($event, true);
    $canDisableCorrelation = $this->Acl->canDisableCorrelation($event);

    $renderGalaxyElements = function ($galaxies, $targetId) use ($groupGalaxyClustersByName, $baseurl, $canModifyGlobalTags, $canModifyLocalTags) {
        if (empty($galaxies)) {
            return '';
        }
        $html = '';
        $clustersByGalaxy = $groupGalaxyClustersByName($galaxies);
        foreach ($clustersByGalaxy as $galaxyName => $clusters) {
            $html .= $this->element('Events/View/galaxy_compact_beta', [
                'galaxyName' => $galaxyName,
                'clusters' => $clusters,
                'baseurl' => $baseurl,
                'canModify' => $canModifyGlobalTags,
                'canModifyLocal' => $canModifyLocalTags,
                'target_type' => 'attribute',
                'target_id' => $targetId,
            ]);
        }
        return $html;
    };

    $countDirectRelatedAttributes = function ($item) {
        return !empty($item['RelatedAttribute']) ? count($item['RelatedAttribute']) : 0;
    };

    if (!isset($bulkAttributePermissions) || !is_array($bulkAttributePermissions)) {
        $bulkAttributePermissions = [
            'edit' => $mayModify && $this->Acl->canAccess('attributes', 'editSelected'),
            'tagGlobal' => $this->Acl->canAccess('attributes', 'addTag') && $this->Acl->canModifyTag($event),
            'tagLocal' => $this->Acl->canAccess('attributes', 'addTag') && $this->Acl->canModifyTag($event, true),
            'galaxyGlobal' => $this->Acl->canAccess('galaxies', 'selectGalaxyNamespace') && $this->Acl->canModifyTag($event),
            'galaxyLocal' => $this->Acl->canAccess('galaxies', 'selectGalaxyNamespace') && $this->Acl->canModifyTag($event, true),
            'groupIntoObject' => $mayModify && $this->Acl->canAccess('objects', 'proposeObjectsFromAttributes'),
            'addRelationships' => $mayModify && $this->Acl->canAccess('objectReferences', 'bulkAdd'),
            'sightings' => $this->Acl->canAccess('sightings', 'advanced'),
            'delete' => $mayModify && $this->Acl->canAccess('attributes', 'deleteSelected'),
        ];
    }
    $hasBulkAttributePermissions = isset($hasBulkAttributePermissions)
        ? (bool)$hasBulkAttributePermissions
        : in_array(true, $bulkAttributePermissions, true);
    $canAddSighting = $this->Acl->canAccess('sightings', 'add');
    $canAdvancedSighting = $this->Acl->canAccess('sightings', 'advanced');
    $deleteSelectedUrl = $baseurl . '/attributes/deleteSelected/' . $event['Event']['id'];
    if (empty($event['Event']['publish_timestamp'])) {
        $deleteSelectedUrl .= '/1';
    }
?>

<?php
    echo $this->Form->create('Attribute', array('id' => 'delete_selected', 'url' => $deleteSelectedUrl));
    echo $this->Form->input('ids_delete', array(
        'type' => 'text',
        'value' => '',
        'style' => 'display:none;',
        'label' => false,
    ));
    echo $this->Form->end();
?>

<style>
    .beta-attributes-list {
        padding: 0;
        box-sizing: border-box;
    }
    .beta-toolbar {
        margin-left: -10px;
        margin-right: -10px;
        justify-content: flex-start;
    }
    .beta-toolbar .pull-right {
        margin-left: auto;
    }
    .beta-attr-row:hover .beta-row-menu-trigger {
        visibility: visible;
    }

    .attr-icon {
        width: 20px;
        text-align: center;
        color: #999;
        margin-right: 5px;
    }
    .attr-value {
        font-family: 'Consolas', 'Monaco', monospace;
        color: #263443;
        word-break: break-all;
        font-size: 13px;
    }
    .attr-tag {
        display: inline-block;
        padding: 3px 8px;
        font-size: 12px;
        border-radius: 3px;
        margin-right: 4px;
        margin-bottom: 2px;
        border: 1px solid transparent;
    }
    .standalone-attr-row td {
        background: #fff;
    }
    .object-header-row {
        background-color: #eef6fc;
    }
    .object-attr-row, .object-attr-row + .beta-sub-row {
        background-color: #f7fbfe;
    }
    .object-header-row td {
        padding-top: 10px;
        padding-bottom: 10px;
        border-top: 8px solid #fff;
        border-bottom: 1px solid #d4e3ef;
        background: linear-gradient(180deg, #f2f8fd 0%, #eaf4fb 100%);
    }
    .object-header-row td:first-child {
        border-left: 1px solid #d7e6f1;
        border-top-left-radius: 4px;
        box-shadow: inset 8px 0 0 #31708f;
        padding-left: 0;
    }
    .object-header-row td:last-child {
        border-top-right-radius: 4px;
        border-right: 1px solid #d7e6f1;
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.85);
    }
    .object-title {
        font-weight: bold;
        color: #31708f;
        font-size: 14px;
    }
    .object-label {
        background: #31708f;
        color: white;
        font-size: 9px;
        padding: 1px 4px;
        border-radius: 3px;
        text-transform: uppercase;
        vertical-align: middle;
        margin-right: 5px;
        letter-spacing: 0.5px;
    }
    .object-header-meta {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        margin-left: 14px;
        padding-left: 14px;
        border-left: 1px solid #d8e7f2;
        text-align: left;
    }
    .object-desc {
        font-size: 11px;
        color: #91a0af;
    }
    .object-summary-inline {
        display: inline-flex;
        align-items: center;
        gap: 0;
        min-width: 0;
        flex-wrap: wrap;
    }
    .object-summary-text {
        display: inline-flex;
        align-items: baseline;
        gap: 10px;
        min-width: 0;
        flex-wrap: wrap;
    }
    .object-count-label {
        display: inline-flex;
        align-items: center;
        min-height: 22px;
        padding: 0 10px;
        border-radius: 999px;
        background: #dcecf7;
        border: 1px solid #c6deee;
        font-size: 11px;
        font-weight: 700;
        color: #4f6f8b;
        white-space: nowrap;
    }
    .object-summary-inline .object-label {
        margin-right: 0;
    }
    .object-summary-inline .object-label,
    .object-summary-inline .object-title,
    .object-summary-inline .object-desc {
        display: inline-flex;
        align-items: center;
        min-height: 28px;
        padding: 0 14px 0 18px;
        margin-right: 0;
        border: 1px solid transparent;
        border-radius: 0;
        font-size: 10px;
        font-weight: 600;
        line-height: 1;
        position: relative;
        white-space: nowrap;
    }
    .object-summary-inline .object-label::after,
    .object-summary-inline .object-title::after {
        content: '';
        position: absolute;
        top: -1px;
        right: -14px;
        width: 28px;
        height: 28px;
        background: inherit;
        border-top: 1px solid currentColor;
        border-right: 1px solid currentColor;
        transform: rotate(45deg) scale(0.71);
        transform-origin: center;
        z-index: 1;
        opacity: 1;
    }
    .object-summary-inline .object-title::before,
    .object-summary-inline .object-desc::before {
        content: '';
        position: absolute;
        top: -1px;
        left: -14px;
        width: 28px;
        height: 28px;
        background: #f3f6f9;
        border-top: 1px solid #d9e1e8;
        border-right: 1px solid #d9e1e8;
        transform: rotate(45deg) scale(0.71);
        transform-origin: center;
        z-index: 0;
        opacity: 1;
    }
    .object-summary-inline .object-label {
        background: #eef4fa;
        border-color: #d5e2ef;
        color: #5b7894;
        border-top-left-radius: 999px;
        border-bottom-left-radius: 999px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        padding-left: 14px;
        font-weight: 700;
    }
    .object-summary-inline .object-title {
        background: #f4f7fb;
        border-color: #d8e0e9;
        color: #4d6175;
        font-size: 10px;
        font-weight: 600;
        border-top-right-radius: 999px;
        border-bottom-right-radius: 999px;
        padding-right: 14px;
    }
    .object-summary-inline .object-desc {
        background: #f7f9fc;
        border-color: #dce3eb;
        color: #7f90a0;
        padding-right: 14px;
        font-weight: 500;
    }
    .object-summary-inline .object-label::before {
        display: none;
    }
    .object-summary-inline .object-title::after {
        display: none;
    }
    .object-summary-inline .object-desc::after {
        display: none;
    }
    .object-attr-row td:first-child,
    .object-attr-row + .beta-sub-row td:first-child {
        border-left: 1px solid #d7e6f1;
        box-shadow: inset 8px 0 0 rgba(49, 112, 143, 0.18);
        padding-left: 0;
    }
    .object-attr-row td,
    .object-attr-row + .beta-sub-row td {
        border-top: 1px solid #e2edf5;
        border-bottom: 1px solid #e2edf5;
        background: #f7fbfe;
    }
    .object-attr-row td:last-child,
    .object-attr-row + .beta-sub-row td:last-child {
        border-right: 1px solid #d7e6f1;
    }
    .object-attr-row:last-of-type td:first-child,
    .object-attr-row:last-of-type td:last-child {
        border-bottom-color: #d7e6f1;
    }
    .object-attr-row:last-of-type td:first-child {
        border-bottom-left-radius: 4px;
    }
    .object-attr-row:last-of-type td:last-child {
        border-bottom-right-radius: 4px;
    }
    .object-attr-row td:first-child {
        /* border-left handled inline for positioning */
    }
    .object-attr-row .beta-left-cell-stack {
        margin-left: 8px;
    }
    .object-header-row .beta-left-cell-stack {
        margin-left: 8px;
    }
    .object-attr-row .beta-attr-meta-block {
        position: relative;
        padding-left: 8px;
    }
    .beta-sub-row {
        /* background-color inherited from preceding row logic where possible, otherwise white */
        background-color: #fff;
    }
    .beta-sub-row td {
        padding: 4px 10px 8px 10px;
        border-bottom: 1px solid #edf2f6;
        vertical-align: top;
        border-left: 4px solid transparent; /* Keep aligned */
    }
    .beta-tags-container, .beta-galaxies-container {
        display: flex;
        flex-wrap: wrap;
        gap: 5px;
    }
    .beta-sighting-alert {
        color: #d9534f;
        font-weight: bold;
        font-size: 14px;
    }
    .beta-tagging-links {
        display: none;
    }
    .beta-columns-menu {
        min-width: 180px;
    }

    /* Beta Pagination Styles */
    .beta-pagination-container {
        display: flex;
        align-items: center;
        justify-content: flex-start;
        flex-wrap: wrap;
        padding: 8px 0;
        margin-bottom: 8px;
        border-bottom: 1px solid #eef2f6;
        gap: 12px;
    }
    .beta-pagination-group {
        display: inline-flex;
        align-items: stretch;
        flex-wrap: wrap;
        border: 1px solid #e6edf3;
        border-radius: 6px;
        background: linear-gradient(180deg, #ffffff 0%, #fafcfe 100%);
        overflow: hidden;
    }
    .beta-pagination-info {
        display: inline-flex;
        align-items: center;
        gap: 0;
        min-width: 0;
        font-size: 12px;
        color: #6f7c88;
    }
    .beta-pagination-info .beta-page-item-info {
        display: inline-flex;
        align-items: center;
        min-height: 32px;
        padding: 0 12px;
        color: #7b8793;
        font-size: 12px;
        white-space: nowrap;
    }
    .beta-pagination-controls {
        display: flex;
        align-items: center;
        gap: 4px;
        padding: 0 10px;
        border-left: 1px solid #e6edf3;
    }
    .beta-pagination-controls .btn {
        min-width: 36px;
    }
    .beta-pagination-controls .beta-page-size-select {
        width: auto;
        display: inline-flex;
        align-items: center;
        padding: 0 8px;
        font-size: 12px;
        height: 32px;
        margin-bottom: 0;
        vertical-align: middle;
    }
    .beta-page-num-display {
        font-size: 12px;
        color: #768391;
        min-width: 48px;
        text-align: center;
        font-weight: 600;
    }
    .beta-pagination-bottom {
        margin-top: 10px;
        padding-top: 10px;
        border-top: 1px solid #eef2f6;
    }
    .beta-attr-toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        flex-wrap: wrap;
        margin-bottom: 10px;
    }
    .beta-attr-toolbar-main,
    .beta-attr-toolbar-actions,
    .beta-attr-toolbar-right {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
        min-width: 0;
    }
    .beta-attr-toolbar-main {
        gap: 0;
        flex: 1 1 auto;
    }
    .beta-attr-toolbar-actions {
        padding-left: 14px;
        margin-left: 14px;
        border-left: 1px solid #edf2f6;
    }
    .beta-attr-toolbar-right {
        justify-content: flex-end;
        padding-left: 14px;
        margin-left: auto;
        border-left: 1px solid #edf2f6;
        flex: 0 0 auto;
    }
    .beta-attr-toolbar .beta-pagination-container {
        padding: 0;
        margin: 0;
        border-bottom: 0;
    }
    .beta-attr-search-wrap {
        flex: 0 0 auto;
    }
    .beta-attr-search-wrap #beta-attr-search {
        width: 250px;
        margin-bottom: 0;
    }
    @media (max-width: 767px) {
        .beta-pagination-container {
            flex-direction: column;
            align-items: stretch;
        }
        .beta-pagination-group,
        .beta-pagination-controls {
            width: 100%;
        }
        .beta-pagination-group {
            display: flex;
            flex-direction: column;
        }
        .beta-pagination-controls {
            justify-content: space-between;
            flex-wrap: wrap;
            padding: 8px 10px;
            border-left: 0;
            border-top: 1px solid #d8e1eb;
        }
        .beta-attr-toolbar,
        .beta-attr-toolbar-main,
        .beta-attr-toolbar-actions,
        .beta-attr-toolbar-right {
            align-items: stretch;
        }
        .beta-attr-toolbar-actions,
        .beta-attr-toolbar-right {
            justify-content: flex-start;
            flex-basis: 100%;
            padding-left: 0;
            margin-left: 0;
            border-left: 0;
        }
        .beta-attr-search-wrap,
        .beta-attr-search-wrap #beta-attr-search {
            width: 100%;
        }
    }
    
    /* Tree Structure */
    .tree-cell {
        position: relative;
        padding-left: 0 !important;
        border-left: 0 !important;
    }
    .tree-cell::before {
        content: none;
    }
    .tree-cell::after {
        content: none;
    }
    .tree-cell.no-tick::after {
        display: none;
    }
    .tree-cell.last-item::before {
        content: none;
    }

    .standalone-attr-row {
        background-color: #fff;
    }

    /* New Card-like styles */
    .beta-attr-meta-block {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    .beta-attr-type-path {
        font-size: 11px;
        color: #9aa7b3;
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
        margin-bottom: 2px;
    }
    .beta-chevrons {
        display: inline-flex;
        align-items: stretch;
        flex-wrap: wrap;
        min-width: 0;
        overflow: hidden;
        border-radius: 999px;
    }
    .beta-chevron-segment {
        position: relative;
        display: inline-flex;
        align-items: center;
        min-height: 28px;
        padding: 0 14px 0 18px;
        margin-right: 0;
        border: 1px solid transparent;
        border-radius: 0;
        font-size: 10px;
        font-weight: 600;
        line-height: 1;
        white-space: nowrap;
        margin-left: 0;
    }
    .beta-chevron-segment::after {
        content: '';
        position: absolute;
        top: -1px;
        right: -14px;
        width: 28px;
        height: 28px;
        background: inherit;
        border-top: 1px solid currentColor;
        border-right: 1px solid currentColor;
        transform: rotate(45deg) scale(0.71);
        transform-origin: center;
        z-index: 1;
        opacity: 1;
    }
    .beta-chevron-segment::before {
        content: '';
        position: absolute;
        top: -1px;
        left: -14px;
        width: 28px;
        height: 28px;
        background: #f3f6f9;
        border-top: 1px solid #d9e1e8;
        border-right: 1px solid #d9e1e8;
        transform: rotate(45deg) scale(0.71);
        transform-origin: center;
        z-index: 0;
        opacity: 1;
    }
    .beta-chevron-segment > span {
        position: relative;
        z-index: 2;
    }
    .beta-chevron-segment:first-child {
        padding-left: 14px;
        margin-left: 0;
        border-top-left-radius: 999px;
        border-bottom-left-radius: 999px;
    }
    .beta-chevron-segment:first-child::before {
        display: none;
    }
    .beta-chevron-segment:last-child {
        padding-right: 14px;
    }
    .beta-chevron-segment:last-child::after {
        display: none;
    }
    .beta-chevron-segment.beta-chevron-category {
        background: #f3f6f9;
        border-color: #d9e1e8;
        color: #8b99a6;
    }
    .beta-chevron-segment.beta-chevron-relation {
        background: #edf4fb;
        border-color: #d1e1f0;
        color: #5c7fa2;
    }
    .beta-chevron-segment.beta-chevron-type {
        background: #f4f7fb;
        border-color: #d6e0ea;
        color: #566575;
    }
    .beta-category-label {
        font-size: inherit;
        color: inherit;
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }
    .beta-type-insight {
        background: transparent;
        padding: 0;
        border-radius: 0;
        font-weight: inherit;
        color: inherit;
        border: 0;
    }
    .beta-object-relation-insight {
        background: transparent;
        padding: 0;
        border-radius: 0;
        font-weight: inherit;
        color: inherit;
        border: 0;
    }
    .beta-attr-tags-inline {
        display: flex;
        flex-wrap: wrap;
        gap: 4px;
        margin-top: 2px;
        opacity: 0.5;
        transition: opacity 0.18s ease;
    }
    .beta-attr-row:hover .beta-attr-tags-inline,
    .beta-sub-row:hover .beta-attr-tags-inline {
        opacity: 1;
    }
    .beta-attr-value-container {
        display: flex;
        align-items: flex-start;
        gap: 8px;
        padding-top: 2px;
    }
    .beta-correlation-inline-indicator {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: 0 0 auto;
        width: 16px;
        color: #5b8bb5;
        opacity: 0.9;
        margin-top: 1px;
        font-size: 11px;
        cursor: pointer;
    }
    .beta-left-cell-stack {
        display: inline-flex;
        flex-direction: column;
        align-items: center;
        min-width: 26px;
    }
    .beta-attr-comment-inline {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        min-height: 24px;
        max-width: min(100%, 520px);
        padding: 3px 10px;
        border: 1px solid #dbe5ef;
        border-radius: 999px;
        background: #ffffff;
        color: #667686;
        font-size: 11px;
        font-weight: 500;
        line-height: 1.35;
        overflow-wrap: anywhere;
        box-shadow: 0 1px 2px rgba(31, 57, 83, 0.05), inset 0 1px 0 rgba(255, 255, 255, 0.8);
    }
    .beta-attr-comment-inline span {
        min-width: 0;
    }
    .beta-attr-comment-inline .fa,
    .beta-attr-comment-inline .fas {
        flex: 0 0 auto;
        color: #7d91a4;
        font-size: 10px;
        opacity: 0.95;
    }
    .beta-attr-table {
        width: 100%;
        background: #fff;
    }
    .beta-attr-table thead th {
        background: #f9fbfd;
        color: #758290;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.03em;
        border-bottom: 1px solid #e6edf3;
        padding-top: 10px;
        padding-bottom: 10px;
    }
    .beta-attr-table tbody td {
        border-top-color: #f1f5f8;
    }
    .beta-attr-table .btn.btn-default.btn-sm,
    .beta-attr-table .btn-group > .btn.btn-default.btn-sm,
    .beta-attr-toolbar .btn.btn-default.btn-sm,
    .beta-attr-toolbar .btn-group > .btn.btn-default.btn-sm {
        background: #fafcfe;
        border-color: #e4ebf2;
        color: #556473;
        box-shadow: none;
    }
    .beta-attr-toolbar .btn.btn-default.btn-sm:hover,
    .beta-attr-toolbar .btn-group > .btn.btn-default.btn-sm:hover {
        background: #f3f7fb;
        border-color: #d8e2ec;
        color: #415262;
    }
    .beta-attr-toolbar .btn.btn-primary.btn-sm {
        box-shadow: none;
    }
    .beta-related-count-badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 4px;
        min-width: 22px;
        height: 22px;
        padding: 0 7px;
        border: 1px solid #b7d5f0;
        border-radius: 999px;
        background: #eaf5ff;
        color: #3f78a8;
        font-size: 11px;
        font-weight: 600;
        cursor: pointer;
    }
    .beta-related-count-badge .fa {
        font-size: 10px;
    }
    .beta-attr-status-icon {
        color: #a8b4c0;
        transition: color 0.15s ease, opacity 0.15s ease;
    }
    .beta-attr-status-icon.is-active {
        color: #6f8398;
        opacity: 0.95;
    }
    .beta-attr-status-icon.is-alert {
        color: #d9534f;
    }
    .beta-attr-status-icon.is-ids-active {
        color: #b06f2f;
        opacity: 0.95;
    }
    .beta-attr-status-icon.is-sighting-active {
        color: #d9534f;
        opacity: 0.95;
    }
    .beta-attr-date-cell {
        font-size: 11px;
        color: #7e8b98;
    }
</style>

<div class="beta-attributes-list">
    <!-- Toolbar -->
    <div class="beta-attr-toolbar">
        <div class="beta-attr-toolbar-main">
            <div class="beta-pagination-container" id="beta-pagination-top">
                <div class="beta-pagination-group">
                    <div class="beta-pagination-info">
                        <span class="beta-page-item-info" id="beta-page-item-info-top"><?php echo __('Showing %s-%s of %s items', $betaShowStart, $betaShowEnd, $betaTotalAttributes); ?></span>
                    </div>
                    <div class="beta-pagination-controls">
                        <button type="button" class="btn btn-default btn-sm beta-page-btn" data-page-action="first" id="beta-page-first" title="<?php echo __('First page'); ?>" <?php if ($betaCurrentPage <= 1) echo 'disabled'; ?>><i class="fa fa-angle-double-left"></i></button>
                        <button type="button" class="btn btn-default btn-sm beta-page-btn" data-page-action="prev" id="beta-page-prev" title="<?php echo __('Previous page'); ?>" <?php if ($betaCurrentPage <= 1) echo 'disabled'; ?>><i class="fa fa-angle-left"></i></button>
                        <span class="beta-page-num-display" id="beta-page-num-display-top"><?php echo __('%s / %s', $betaCurrentPage, $betaTotalPages); ?></span>
                        <button type="button" class="btn btn-default btn-sm beta-page-btn" data-page-action="next" id="beta-page-next" title="<?php echo __('Next page'); ?>" <?php if ($betaCurrentPage >= $betaTotalPages) echo 'disabled'; ?>><i class="fa fa-angle-right"></i></button>
                        <button type="button" class="btn btn-default btn-sm beta-page-btn" data-page-action="last" id="beta-page-last" title="<?php echo __('Last page'); ?>" <?php if ($betaCurrentPage >= $betaTotalPages) echo 'disabled'; ?>><i class="fa fa-angle-double-right"></i></button>
                        <select class="form-control beta-page-size-select" id="beta-page-size" title="<?php echo __('Items per page'); ?>">
                            <option value="20" <?php echo $betaPageSize == 20 ? 'selected' : ''; ?>>20</option>
                            <option value="50" <?php echo $betaPageSize == 50 ? 'selected' : ''; ?>>50</option>
                            <option value="100" <?php echo $betaPageSize == 100 ? 'selected' : ''; ?>>100</option>
                            <option value="200" <?php echo $betaPageSize == 200 ? 'selected' : ''; ?>>200</option>
                        </select>
                    </div>
                </div>
            </div>
            <div class="beta-attr-toolbar-actions">
            <?php if ($mayModify): ?>
                <div class="btn-group">
                    <button type="button" class="btn btn-primary btn-sm dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        <i class="fa fa-plus"></i> <?php echo __('Add'); ?> <span class="caret"></span>
                    </button>
                    <ul class="dropdown-menu">
                        <li>
                            <a href="<?php echo $baseurl; ?>/attributes/add/<?php echo h($event['Event']['id']); ?>">
                                <i class="fa fa-plus"></i> <?php echo __('Attribute'); ?>
                            </a>
                        </li>
                        <li>
                            <a href="#" onclick="getPopup('<?php echo h($event['Event']['id']); ?>', 'objectTemplates', 'objectMetaChoice'); return false;">
                                <i class="fa fa-cube"></i> <?php echo __('Object'); ?>
                            </a>
                        </li>
                        <li>
                            <a href="<?php echo $baseurl; ?>/attributes/add_attachment/<?php echo h($event['Event']['id']); ?>">
                                <i class="fa fa-paperclip"></i> <?php echo __('Attachment'); ?>
                            </a>
                        </li>
                    </ul>
                </div>
                <div class="btn-group">
                    <button type="button" class="btn btn-default btn-sm dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        <i class="fa fa-download"></i> <?php echo __('Import'); ?> <span class="caret"></span>
                    </button>
                    <ul class="dropdown-menu">
                        <li>
                            <a href="#" onclick="getPopup('<?php echo h($event['Event']['id']); ?>', 'events', 'importChoice'); return false;">
                                <i class="fa fa-bars"></i> <?php echo __('Populate from...'); ?>
                            </a>
                        </li>
                        <li>
                            <a href="#" onclick="getPopup('<?php echo h($event['Event']['id']); ?>', 'events', 'freeTextImport'); return false;">
                                <i class="fa fa-align-left"></i> <?php echo __('Freetext Import'); ?>
                            </a>
                        </li>
                    </ul>
                </div>
                <a href="#" onclick="getPopup('<?php echo h($event['Event']['id']); ?>', 'attributes', 'attributeReplace'); return false;" class="btn btn-default btn-sm"><i class="fa fa-random"></i> <?php echo __('Replace Attributes'); ?></a>
            <?php endif; ?>
            
            <button id="btn-toggle-all" class="btn btn-default btn-sm" onclick="toggleAllObjectsAttributes()"><i class="fa fa-compress"></i> <span id="label-toggle-all"><?php echo __('Collapse objects'); ?></span></button>
            
            <div class="btn-group">
                <button type="button" class="btn btn-default btn-sm dropdown-toggle" data-toggle="dropdown">
                    <i class="fa fa-columns"></i> <?php echo __('Columns'); ?> <span class="caret"></span>
                </button>
                <ul class="dropdown-menu beta-columns-menu">
                    <?php 
                        $cols = [
                            'date' => __('Date'),
                            'sightings' => __('Sightings'),
                            'distribution' => __('Distribution'),
                            'correlation' => __('Correlation'),
                            'related' => __('Corr.'),
                        ];
                        foreach ($cols as $id => $label):
                    ?>
                        <li>
                            <a href="#" onclick="toggleBetaColumn('<?php echo h($id); ?>'); return false;">
                                <i class="fa fa-check col-check-<?php echo h($id); ?>"></i> <?php echo h($label); ?>
                            </a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
            </div>
        </div>
        <div class="beta-attr-toolbar-right">
            <div class="beta-attr-search-wrap">
                <input type="text" id="beta-attr-search" placeholder="Enter value to search..." class="form-control input-sm">
            </div>
        </div>
    </div>

    <table class="beta-attr-table" id="attributeList">
        <thead>
            <tr>
                <th style="width: 40px;"><?php if ($hasBulkAttributePermissions): ?><input type="checkbox" class="select-all select_all" title="<?php echo __('Select all');?>" role="button" tabindex="0" aria-label="<?php echo __('Select all attributes/proposals on current page');?>" onclick="toggleAllAttributeCheckboxes()"><?php endif; ?></th>
                <th colspan="2"><?php echo __('Attribute Details'); ?></th>
                <th class="col-related" style="width: 50px;"><?php echo __('Corr.'); ?></th>
                <th style="width: 30px;" title="<?php echo __('Recommend for blocking / alerting?'); ?>">IDS</th>
                <th class="col-correlation" style="width: 30px;" title="<?php echo __('Correlation'); ?>"><i class="fa fa-project-diagram"></i></th>
                <th class="col-sightings" style="width: 30px;" title="<?php echo __('Sightings'); ?>"><i class="fa fa-eye"></i></th>
                <th class="col-distribution" style="width: 40px;" title="<?php echo __('Distribution'); ?>"><i class="fa fa-share-alt"></i></th>
                <th class="col-date" style="width: 80px;"><?php echo __('Date'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($items as $item): ?>
                <?php
                    $isObject = $item['objectType'] === 'object';
                    $dataType = $isObject ? 'object' : 'attribute';
                    $dataName = $isObject ? $item['name'] : $item['type'];
                    $rowClass = $isObject ? 'object-header-row' : 'standalone-attr-row';
                    $objectAttributes = ($isObject && !empty($item['Attribute']) && is_array($item['Attribute'])) ? $item['Attribute'] : [];
                    $objectAttributeCount = $isObject ? count($objectAttributes) : 0;
                    
                    $isSighted = isset($sightingsData['data'][$item['id']]);
                    if (!$isObject && !$isSighted && isset($item['Sighting']) && !empty($item['Sighting'])) {
                        $isSighted = true;
                    }
                    $distColor = '#999';
                    $hasAttributeDownload = !$isObject && ($item['type'] == 'malware-sample' || $item['type'] == 'attachment');
                    $hasTagActions = !$isObject && ($canModifyGlobalTags || $canModifyLocalTags);
                    $hasRowActions = $mayModify || $canAddSighting || $canAdvancedSighting || $hasAttributeDownload || $hasTagActions;
                    if (isset($distributionLevels[$item['distribution']])) {
                        // Dist color mapping based on shortDist or similar
                        $distColors = [0 => '#555', 1 => '#428bca', 2 => '#f0ad4e', 3 => '#5cb85c', 4 => '#d9534f', 5 => '#333'];
                        $distColor = $distColors[$item['distribution']] ?? '#999';
                    }
                ?>
                <tr class="beta-attr-row <?php echo $rowClass; ?>"
                    id="<?php echo $isObject ? 'Object_' . h($item['id']) . '_tr' : 'Attribute_' . h($item['id']) . '_tr'; ?>"
                    data-object-type="<?php echo $dataType; ?>"
                    data-primary-id="<?php echo h($item['id']); ?>"
                    <?php if (!empty($item['uuid'])): ?>data-uuid="<?php echo h($item['uuid']); ?>"<?php endif; ?>
                    <?php if ($isObject): ?>data-object-name="<?php echo h($dataName); ?>" data-object-id="<?php echo h($item['id']); ?>"<?php else: ?>data-attribute-type="<?php echo h($dataName); ?>"<?php endif; ?>>
                    
                    <!-- Checkbox & Actions Dropdown -->
                    <td style="position: relative;" <?php if ($isObject) echo 'colspan="7"'; ?>>
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <div style="display: flex; align-items: center; min-width: 0; gap: 8px;">
                                <div class="beta-left-cell-stack">
                                    <div class="beta-row-actions beta-checkbox-actions-wrapper">
                            <?php if ($hasBulkAttributePermissions): ?><input type="checkbox" class="select-row select_attribute" value="<?php echo h($item['id']); ?>" data-id="<?php echo h($item['id']); ?>" aria-label="<?php echo __('Select attribute');?>" onchange="attributeListAnyAttributeCheckBoxesChecked()"><?php endif; ?>
                            <?php if ($hasRowActions): ?>
                            <div class="beta-row-menu-trigger beta-dropdown-toggle">
                                <i class="fa fa-chevron-down"></i>
                            </div>
                            <div class="beta-row-menu">
                                <ul>
                                <?php if ($mayModify || $hasTagActions || $canAddSighting || $canAdvancedSighting || $hasAttributeDownload): ?>
                                <!-- Edit -->
                                <?php if ($mayModify): ?>
                                <li><a href="<?php echo $baseurl; ?>/<?php echo $isObject ? 'objects' : 'attributes'; ?>/edit/<?php echo h($item['id']); ?>"><i class="fa fa-edit"></i> Edit</a></li>
                                
                                <!-- Proposals -->
                                <li><a href="#" onclick="event.preventDefault(); showMessage('fail', 'Proposal support not implemented in beta UI but coming soon');"><i class="fa fa-comment-dots"></i> Propose Edit</a></li>
                                <?php endif; ?>

                                <!-- Tagging / Galaxies -->
                                <?php if (!$isObject && $hasTagActions): ?>
                                    <li class="divider"></li>
                                    <?php if ($canModifyGlobalTags || $canModifyLocalTags): ?>
                                    <li class="dropdown-submenu">
                                        <a href="#"><i class="fa fa-tag"></i> Add tag</a>
                                        <ul class="dropdown-menu">
                                            <?php if ($canModifyLocalTags): ?>
                                            <li><a href="#" onclick="getPopup('local:1/<?php echo h($item['id']); ?>/attribute', 'tags', 'selectTaxonomy'); return false;"><i class="fa fa-user"></i> Local</a></li>
                                            <?php endif; ?>
                                            <?php if ($canModifyGlobalTags): ?>
                                            <li><a href="#" onclick="getPopup('<?php echo h($item['id']); ?>/attribute', 'tags', 'selectTaxonomy'); return false;"><i class="fa fa-globe"></i> Global</a></li>
                                            <?php endif; ?>
                                        </ul>
                                    </li>
                                    <?php endif; ?>
                                    <?php if ($canModifyGlobalTags || $canModifyLocalTags): ?>
                                    <li class="dropdown-submenu">
                                        <a href="#"><i class="fa fa-bahai"></i> Add Galaxy</a>
                                        <ul class="dropdown-menu">
                                            <?php if ($canModifyLocalTags): ?>
                                            <li><a href="#" onclick="getPopup('<?php echo h($item['id']); ?>/attribute/local:1', 'galaxies', 'selectGalaxyNamespace'); return false;"><i class="fa fa-user"></i> Local</a></li>
                                            <?php endif; ?>
                                            <?php if ($canModifyGlobalTags): ?>
                                            <li><a href="#" onclick="getPopup('<?php echo h($item['id']); ?>/attribute/local:0', 'galaxies', 'selectGalaxyNamespace'); return false;"><i class="fa fa-globe"></i> Global</a></li>
                                            <?php endif; ?>
                                        </ul>
                                    </li>
                                    <?php endif; ?>
                                <?php endif; ?>

                                <!-- Context Specific Actions -->
                                <?php if (!$isObject && ($item['type'] == 'malware-sample' || $item['type'] == 'attachment')): ?>
                                    <li class="divider"></li>
                                    <li><a href="<?php echo $baseurl; ?>/attributes/download/<?php echo h($item['id']); ?>"><i class="fa fa-download"></i> Download</a></li>
                                <?php endif; ?>
                                
                                <?php if ($canAddSighting || $canAdvancedSighting): ?>
                                <!-- Sightings Actions -->
                                <li class="divider"></li>
                                <?php if ($canAddSighting): ?>
                                <li><a href="#" onclick="simplePopup('<?php echo $baseurl; ?>/sightings/add/<?php echo h($item['id']); ?>');"><i class="fa fa-eye"></i> Add Sighting</a></li>
                                <?php endif; ?>
                                <?php if ($canAdvancedSighting): ?>
                                <li><a href="#" class="sightings_advanced_add" data-object-id="<?php echo h($item['id']); ?>" data-object-context="<?php echo $isObject ? 'object' : 'attribute'; ?>"><i class="fa fa-wrench"></i> Advanced Sightings</a></li>
                                <?php endif; ?>
                                <?php endif; ?>

                                <!-- Enrichment -->
                                <?php if (!$isObject): ?>
                                    <li class="divider"></li>
                                    <li><a href="#" onclick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?php echo h($item['id']); ?>/0/Enrichment/Attribute');"><i class="fa fa-magic"></i> Enrich</a></li>
                                <?php endif; ?>

                                <!-- Utilities -->
                                <li class="divider"></li>
                                <li><a href="#" onclick="return betaCopyUuid('<?php echo h($item['uuid']); ?>');"><i class="fa fa-copy"></i> Copy UUID</a></li>
                                <?php endif; ?>
                                <?php if ($mayModify): ?>
                                <!-- Delete -->
                                <li class="divider"></li>
                                <li><a href="#" class="text-danger" onclick="deleteObject('<?php echo $isObject ? 'objects' : 'attributes'; ?>', 'delete', '<?php echo h($item['id']); ?>')"><i class="fa fa-trash"></i> Delete</a></li>
                                <?php endif; ?>
                                </ul>
                            </div>
                            <?php endif; ?>
                                    </div>
                                    </div>
                                </div>
                                <?php if ($isObject): ?>
                                    <div class="object-summary-inline">
                                        <span class="object-label">Object</span>
                                        <div class="object-summary-text">
                                            <span class="object-title" title="<?php echo h($item['description']); ?>"><?php echo h($item['name']); ?></span>
                                            <span class="object-count-label"><?php echo h($objectAttributeCount); ?> <?php echo $objectAttributeCount === 1 ? __('attribute') : __('attributes'); ?></span>
                                        </div>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </td>
                    <?php if (!$isObject): ?>
                        <!-- Metadata (Category > Type + Tags) -->
                        <td colspan="2">
                            <div class="beta-attr-meta-block">
                                <div class="beta-attr-type-path">
                                    <span class="beta-chevrons">
                                        <span class="beta-chevron-segment beta-chevron-category"><span class="beta-category-label"><?php echo h($item['category']); ?></span></span>
                                        <span class="beta-chevron-segment beta-chevron-type"><span class="beta-type-insight"><?php echo h($item['type']); ?></span></span>
                                    </span>
                                    <?php if (!empty($item['comment'])): ?>
                                        <span class="beta-attr-comment-inline"><i class="fa fa-comment"></i><span><?php echo h($item['comment']); ?></span></span>
                                    <?php endif; ?>
                                </div>
                                
                                <?php
                                    $relatedCountForValue = $countDirectRelatedAttributes($item);
                                ?>
                                <div class="beta-attr-value-container">
                                    <?php if ($relatedCountForValue > 0): ?>
                                        <span class="attr-value attr-value-correlatable" style="cursor: pointer;" title="<?php echo __('Click to filter correlations by this attribute'); ?>" onclick="filterCorrelations('<?php echo h($item['id']); ?>'); return false;"><?php echo h($item['value']); ?></span>
                                        <span class="beta-correlation-inline-indicator" title="<?php echo __('Show correlations'); ?>" onclick="filterCorrelations('<?php echo h($item['id']); ?>'); return false;"><i class="fa fa-code-branch"></i></span>
                                    <?php else: ?>
                                        <span class="attr-value"><?php echo h($item['value']); ?></span>
                                    <?php endif; ?>
                                    <?= $renderWarningIcon($item['warnings'] ?? []) ?>
                                    <?php if ($mayModify): ?>
                                         <div class="beta-tagging-links"></div>
                                    <?php endif; ?>
                                </div>

                                <div class="beta-attr-tags-inline beta-attr-tags attributeTagContainer" data-attribute-id="<?php echo h($item['id']); ?>">
                                    <?php if (!empty($item['AttributeTag'])): ?>
                                        <?php echo $this->element('ajaxTags', [
                                            'attributeId' => $item['id'],
                                            'tags' => $item['AttributeTag'] ?? [],
                                            'tagAccess' => $canModifyGlobalTags,
                                            'localTagAccess' => $canModifyLocalTags,
                                            'scope' => 'attribute',
                                            'tagConflicts' => $item['tagConflicts'] ?? [],
                                            'static_tags_only' => true,
                                        ]); ?>
                                    <?php endif; ?>
                                </div>

                                <!-- Galaxies Inline -->
                                <div class="beta-attr-tags-inline beta-attr-galaxies" id="attribute_<?php echo $item['id']; ?>_galaxy" data-attribute-id="<?php echo h($item['id']); ?>" style="margin-top: 4px;">
                                    <?= $renderGalaxyElements($item['Galaxy'] ?? [], $item['id']) ?>
                                </div>
                            </div>
                        </td>

                        <!-- Related Events -->
                        <td class="col-related">
                            <?php
                                $relatedCount = $countRelatedEvents($item['RelatedAttribute'] ?? []);
                            ?>
                            <?php if ($relatedCount > 0): ?>
                                <?= $this->element('Events/correlation_badge', [
                                    'count' => $relatedCount,
                                    'title' => __('Show correlations'),
                                    'onclick' => "filterCorrelations('" . h($item['id']) . "'); return false;",
                                ]) ?>
                            <?php endif; ?>
                        </td>
                    <?php endif; ?>

                    <?php if (!$isObject): ?>
                        <!-- IDS Toggle -->
                        <td style="text-align: center;">
                            <i class="fa fa-shield-alt beta-ids-toggle beta-attr-status-icon <?= $item['to_ids'] ? 'is-ids-active' : '' ?>"
                               style="font-size: 1.5em; cursor: <?= ($mayModify ? 'pointer' : 'default') ?>; <?= ($item['to_ids'] ? '' : 'opacity: 0.22;') ?>"
                                data-id="<?= h($item['id']) ?>"
                                data-to-ids="<?= (int)$item['to_ids'] ?>"
                                title="<?= ($item['to_ids'] ? __('Recommended for blocking / alerting') : __('Not recommended for blocking / alerting')) ?>"></i>
                        </td>

                        <!-- Correlation Toggle -->
                        <td class="col-correlation" style="text-align: center;">
                            <i class="fa fa-project-diagram beta-correlation-toggle beta-attr-status-icon <?= $item['disable_correlation'] ? '' : 'is-active' ?>"
                               style="cursor: <?= ($canDisableCorrelation ? 'pointer' : 'default') ?>; <?= ($item['disable_correlation'] ? 'opacity: 0.22;' : '') ?>"
                                data-id="<?= h($item['id']) ?>"
                                data-disable-correlation="<?= (int)$item['disable_correlation'] ?>"
                                title="<?= ($item['disable_correlation'] ? __('Correlation disabled') : __('Correlation enabled')) ?>"></i>
                        </td>

                        <!-- Sightings -->
                        <td class="col-sightings" style="text-align: center;">
                            <?php if ($isSighted && $canAdvancedSighting): ?>
                                <i class="fa fa-eye sightings_advanced_add beta-attr-status-icon is-alert is-sighting-active" style="cursor: pointer;" title="<?php echo __('Sighted'); ?>" data-object-id="<?php echo h($item['id']); ?>" data-object-context="attribute"></i>
                            <?php elseif ($canAddSighting): ?>
                                <i class="fa fa-eye beta-attr-status-icon" style="cursor: pointer;" title="<?php echo __('Add Sighting'); ?>" onclick="simplePopup('<?php echo $baseurl; ?>/sightings/add/<?php echo h($item['id']); ?>');"></i>
                            <?php else: ?>
                                <i class="fa fa-eye beta-attr-status-icon" style="opacity: 0.24; cursor: default;" title="<?php echo __('Sightings unavailable'); ?>"></i>
                            <?php endif; ?>
                        </td>
                    <?php endif; ?>

                    <!-- Distribution -->
                    <td class="col-distribution" style="text-align: center;">
                        <div class="dist-widget dist-<?= intval($item['distribution']) ?> distributionNetworkToggle"
                             title="<?= $item['distribution'] == 4 ? h($item['SharingGroup']['name'] ?? '') : (isset($distributionLevels[$item['distribution']]) ? h($distributionLevels[$item['distribution']]) : '') ?>"
                             data-event-distribution="<?= intval($item['distribution']) ?>"
                             data-event-distribution-name="<?= $item['distribution'] == 4 ? h($item['SharingGroup']['name'] ?? '') : (isset($shortDist[$item['distribution']]) ? h($shortDist[$item['distribution']]) : '') ?>"
                             data-scope-id="<?= h($item['id']) ?>">
                        </div>
                    </td>

                    <!-- Date -->
                    <td class="col-date">
                        <?php 
                            $showDate = true;
                            if (isset($event['Event']['date']) && date('Y-m-d', $item['timestamp']) === $event['Event']['date']) {
                                $showDate = false;
                            }
                            $isNew = isset($event['Event']['publish_timestamp']) && $item['timestamp'] > $event['Event']['publish_timestamp'];
                        ?>
                        <div class="beta-attr-date-cell">
                            <?php if ($showDate): ?>
                                <?php echo date('Y-m-d', $item['timestamp']); ?>
                            <?php else: ?>
                                <?php echo date('H:i', $item['timestamp']); ?>
                            <?php endif; ?>
                            <?php if ($isNew): ?>
                                <span class="bold red" title="<?= __('Element or modification to an existing element has not been published yet.') ?>">*</span>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>

                <!-- No more sub-rows for Standalone Tags/Galaxies -->
                
                <!-- Expanded Object Attributes -->
                <?php if ($isObject && !empty($objectAttributes)): ?>
                    <?php 
                        $totalAttrs = count($objectAttributes);
                        $attrIndex = 0;
                    ?>
                    <?php foreach ($objectAttributes as $subAttr): ?>
                        <?php 
                            $attrIndex++;
                            $isLast = ($attrIndex === $totalAttrs);

                            $isSightedSub = isset($sightingsData['data'][$subAttr['id']]);
                            if (!$isSightedSub && isset($subAttr['Sighting']) && !empty($subAttr['Sighting'])) {
                                $isSightedSub = true;
                            }
                            $subDistColor = '#999';
                            $hasSubAttributeDownload = $subAttr['type'] == 'malware-sample' || $subAttr['type'] == 'attachment';
                            $hasSubTagActions = $canModifyGlobalTags || $canModifyLocalTags;
                            $hasSubRowActions = $mayModify || $canAddSighting || $canAdvancedSighting || $hasSubAttributeDownload || $hasSubTagActions;
                            if (isset($distributionLevels[$subAttr['distribution']])) {
                                $subDistColors = [0 => '#555', 1 => '#428bca', 2 => '#f0ad4e', 3 => '#5cb85c', 4 => '#d9534f', 5 => '#333'];
                                $subDistColor = $subDistColors[$subAttr['distribution']] ?? '#999';
                            }
                        ?>
                        <?php
                            $hasTags = !empty($subAttr['AttributeTag']);
                            $hasGalaxies = !empty($subAttr['Galaxy']);
                            $attributeIsLast = $isLast && !$hasTags && !$hasGalaxies;
                        ?>
                        <tr class="beta-attr-row object-attr-row" id="Attribute_<?php echo h($subAttr['id']); ?>_tr" data-object-type="attribute" data-primary-id="<?php echo h($subAttr['id']); ?>" data-uuid="<?php echo h($subAttr['uuid']); ?>" data-attribute-type="<?php echo h($subAttr['type']); ?>" data-parent-object-id="<?php echo h($item['id']); ?>" data-parent-object="<?php echo h($dataName); ?>">
                            <td class="tree-cell <?php echo $attributeIsLast ? 'last-item' : ''; ?>">
                                 <!-- Checkbox & Actions for Sub-Attribute -->
                                 <div class="beta-left-cell-stack">
                                     <div class="beta-row-actions beta-checkbox-actions-wrapper">
                                        <?php if ($hasBulkAttributePermissions): ?><input type="checkbox" class="select-row select_attribute" value="<?php echo h($subAttr['id']); ?>" data-id="<?php echo h($subAttr['id']); ?>" aria-label="<?php echo __('Select attribute');?>" onchange="attributeListAnyAttributeCheckBoxesChecked()"><?php endif; ?>
                                        <?php if ($hasSubRowActions): ?>
                                        <div class="beta-row-menu-trigger beta-dropdown-toggle">
                                            <i class="fa fa-chevron-down"></i>
                                        </div>
                                        <div class="beta-row-menu">
                                        <ul>
                                             <?php if ($mayModify || $hasSubTagActions || $canAddSighting || $canAdvancedSighting || $hasSubAttributeDownload): ?>
                                                <?php if ($mayModify): ?>
                                                <li><a href="<?php echo $baseurl; ?>/attributes/edit/<?php echo h($subAttr['id']); ?>"><i class="fa fa-edit"></i> Edit</a></li>
                                                <li><a href="#" onclick="event.preventDefault(); showMessage('fail', 'Proposal support not implemented in beta UI but coming soon');"><i class="fa fa-comment-dots"></i> Propose Edit</a></li>

                                                <?php endif; ?>
                                                <?php if ($hasSubTagActions): ?>
                                                <li class="divider"></li>
                                                <li class="dropdown-submenu">
                                                    <a href="#"><i class="fa fa-tag"></i> Add tag</a>
                                                    <ul class="dropdown-menu">
                                                        <?php if ($canModifyLocalTags): ?>
                                                        <li><a href="#" onclick="getPopup('local:1/<?php echo h($subAttr['id']); ?>/attribute', 'tags', 'selectTaxonomy'); return false;"><i class="fa fa-user"></i> Local</a></li>
                                                        <?php endif; ?>
                                                        <?php if ($canModifyGlobalTags): ?>
                                                        <li><a href="#" onclick="getPopup('<?php echo h($subAttr['id']); ?>/attribute', 'tags', 'selectTaxonomy'); return false;"><i class="fa fa-globe"></i> Global</a></li>
                                                        <?php endif; ?>
                                                    </ul>
                                                </li>
                                                <li class="dropdown-submenu">
                                                    <a href="#"><i class="fa fa-bahai"></i> Galaxies</a>
                                                    <ul class="dropdown-menu">
                                                        <?php if ($canModifyLocalTags): ?>
                                                        <li><a href="#" onclick="getPopup('<?php echo h($subAttr['id']); ?>/attribute/local:1', 'galaxies', 'selectGalaxyNamespace'); return false;"><i class="fa fa-user"></i> Local</a></li>
                                                        <?php endif; ?>
                                                        <?php if ($canModifyGlobalTags): ?>
                                                        <li><a href="#" onclick="getPopup('<?php echo h($subAttr['id']); ?>/attribute/local:0', 'galaxies', 'selectGalaxyNamespace'); return false;"><i class="fa fa-globe"></i> Global</a></li>
                                                        <?php endif; ?>
                                                    </ul>
                                                </li>
                                                <?php endif; ?>

                                                <?php if ($hasSubAttributeDownload): ?>
                                                <li class="divider"></li>
                                                <li><a href="<?php echo $baseurl; ?>/attributes/download/<?php echo h($subAttr['id']); ?>"><i class="fa fa-download"></i> Download</a></li>
                                                <?php endif; ?>
                                                <?php if ($canAddSighting || $canAdvancedSighting): ?>
                                                <li class="divider"></li>
                                                <?php if ($canAddSighting): ?>
                                                <li><a href="#" onclick="simplePopup('<?php echo $baseurl; ?>/sightings/add/<?php echo h($subAttr['id']); ?>');"><i class="fa fa-eye"></i> Add Sighting</a></li>
                                                <?php endif; ?>
                                                <?php if ($canAdvancedSighting): ?>
                                                <li><a href="#" class="sightings_advanced_add" data-object-id="<?php echo h($subAttr['id']); ?>" data-object-context="attribute"><i class="fa fa-wrench"></i> Advanced Sightings</a></li>
                                                <?php endif; ?>
                                                <?php endif; ?>
                                                <li class="divider"></li>
                                                <li><a href="#" onclick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?php echo h($subAttr['id']); ?>/0/Enrichment/Attribute');"><i class="fa fa-magic"></i> Enrich</a></li>
                                                <li class="divider"></li>
                                                <li><a href="#" onclick="return betaCopyUuid('<?php echo h($subAttr['uuid']); ?>');"><i class="fa fa-copy"></i> Copy UUID</a></li>
                                                <?php if ($mayModify): ?>
                                                <li class="divider"></li>
                                                <li><a href="#" class="text-danger" onclick="deleteObject('attributes', 'delete', '<?php echo h($subAttr['id']); ?>')"><i class="fa fa-trash"></i> Delete</a></li>
                                                <?php endif; ?>
                                             <?php endif; ?>
                                        </ul>
                                        </div>
                                        <?php endif; ?>
                                     </div>
                                 </div>
                                 </div>
                            </td>
                            
                            
                            <!-- Metadata (Category > Name (type) :: Description + Tags + Value) -->
                            <td colspan="2">
                                <div class="beta-attr-meta-block">
                                    <div class="beta-attr-type-path">
                                        <span class="beta-chevrons">
                                            <span class="beta-chevron-segment beta-chevron-category"><span class="beta-category-label"><?php echo h($subAttr['category']); ?></span></span>
                                            <span class="beta-chevron-segment beta-chevron-relation"><span class="beta-object-relation-insight"><?php echo h($subAttr['object_relation']); ?></span></span>
                                            <span class="beta-chevron-segment beta-chevron-type"><span class="beta-type-insight"><?php echo h($subAttr['type']); ?></span></span>
                                        </span>
                                        <?php if (!empty($subAttr['comment'])): ?>
                                            <span class="beta-attr-comment-inline"><i class="fa fa-comment"></i><span><?php echo h($subAttr['comment']); ?></span></span>
                                        <?php endif; ?>
                                    </div>

                                        <?php
                                            $subRelatedCountForValue = $countDirectRelatedAttributes($subAttr);
                                        ?>
                                    <div class="beta-attr-value-container">
                                        <?php if ($subRelatedCountForValue > 0): ?>
                                            <span class="attr-value attr-value-correlatable" style="cursor: pointer;" title="<?php echo __('Click to filter correlations by this attribute'); ?>" onclick="filterCorrelations('<?php echo h($subAttr['id']); ?>'); return false;"><?php echo h($subAttr['value']); ?></span>
                                            <span class="beta-correlation-inline-indicator" title="<?php echo __('Show correlations'); ?>" onclick="filterCorrelations('<?php echo h($subAttr['id']); ?>'); return false;"><i class="fa fa-code-branch"></i></span>
                                        <?php else: ?>
                                            <span class="attr-value"><?php echo h($subAttr['value']); ?></span>
                                        <?php endif; ?>
                                        <?= $renderWarningIcon($subAttr['warnings'] ?? []) ?>
                                        <?php if ($mayModify): ?>
                                             <div class="beta-tagging-links"></div>
                                        <?php endif; ?>
                                    </div>

                                    <div class="beta-attr-tags-inline beta-attr-tags attributeTagContainer" data-attribute-id="<?php echo h($subAttr['id']); ?>">
                                        <?php if (!empty($subAttr['AttributeTag'])): ?>
                                            <?php echo $this->element('ajaxTags', [
                                                'attributeId' => $subAttr['id'],
                                                'tags' => $subAttr['AttributeTag'] ?? [],
                                                'tagAccess' => $canModifyGlobalTags,
                                                'localTagAccess' => $canModifyLocalTags,
                                                'scope' => 'attribute',
                                                'tagConflicts' => $subAttr['tagConflicts'] ?? [],
                                                'static_tags_only' => true,
                                            ]); ?>
                                        <?php endif; ?>
                                    </div>

                                    <!-- Galaxies Inline -->
                                    <div class="beta-attr-tags-inline beta-attr-galaxies" data-attribute-id="<?php echo h($subAttr['id']); ?>" style="margin-top: 4px;">
                                        <?= $renderGalaxyElements($subAttr['Galaxy'] ?? [], $subAttr['id']) ?>
                                    </div>
                                </div>
                            </td>

                            <!-- Related -->
                            <td class="col-related">
                                <?php
                                    $subRelatedCount = $countRelatedEvents($subAttr['RelatedAttribute'] ?? []);
                                ?>
                                <?php if ($subRelatedCount > 0): ?>
                                <?= $this->element('Events/correlation_badge', [
                                    'count' => $subRelatedCount,
                                    'title' => __('Show correlations'),
                                    'onclick' => "filterCorrelations('" . h($subAttr['id']) . "'); return false;",
                                ]) ?>
                                <?php endif; ?>
                            </td>

                            <!-- IDS Toggle for Sub-Attribute -->
                            <td style="text-align: center;">
                                <i class="fa fa-shield-alt beta-ids-toggle beta-attr-status-icon <?= $subAttr['to_ids'] ? 'is-ids-active' : '' ?>"
                                   style="font-size: 1.5em; cursor: <?= ($mayModify ? 'pointer' : 'default') ?>; <?= ($subAttr['to_ids'] ? '' : 'opacity: 0.22;') ?>"
                                   data-id="<?= h($subAttr['id']) ?>"
                                   data-to-ids="<?= (int)$subAttr['to_ids'] ?>"
                                   title="<?= ($subAttr['to_ids'] ? __('Recommended for blocking / alerting') : __('Not recommended for blocking / alerting')) ?>"></i>
                            </td>

                            <!-- Correlation -->
                            <td class="col-correlation" style="text-align: center;">
                                <i class="fa fa-project-diagram beta-correlation-toggle beta-attr-status-icon <?= $subAttr['disable_correlation'] ? '' : 'is-active' ?>"
                                   style="cursor: <?= ($mayModify ? 'pointer' : 'default') ?>; <?= ($subAttr['disable_correlation'] ? 'opacity: 0.22;' : '') ?>"
                                   data-id="<?= h($subAttr['id']) ?>"
                                   data-disable-correlation="<?= (int)$subAttr['disable_correlation'] ?>"
                                   title="<?= ($subAttr['disable_correlation'] ? __('Correlation disabled') : __('Correlation enabled')) ?>"></i>
                            </td>

                            <!-- Sightings -->
                            <td class="col-sightings" style="text-align: center;">
                                <?php if ($isSightedSub && $canAdvancedSighting): ?>
                                    <i class="fa fa-eye sightings_advanced_add beta-attr-status-icon is-alert is-sighting-active" style="cursor: pointer;" title="<?php echo __('Sighted'); ?>" data-object-id="<?php echo h($subAttr['id']); ?>" data-object-context="attribute"></i>
                                <?php elseif ($canAddSighting): ?>
                                    <i class="fa fa-eye beta-attr-status-icon" style="cursor: pointer;" title="<?php echo __('Add Sighting'); ?>" onclick="simplePopup('<?php echo $baseurl; ?>/sightings/add/<?php echo h($subAttr['id']); ?>');"></i>
                                <?php else: ?>
                                    <i class="fa fa-eye beta-attr-status-icon" style="opacity: 0.24; cursor: default;" title="<?php echo __('Sightings unavailable'); ?>"></i>
                                <?php endif; ?>
                            </td>
                            <!-- Distribution -->
                            <td class="col-distribution" style="text-align: center;">
                                <div class="dist-widget dist-<?= intval($subAttr['distribution']) ?> distributionNetworkToggle"
                                     title="<?= $subAttr['distribution'] == 4 ? h($subAttr['SharingGroup']['name'] ?? '') : (isset($distributionLevels[$subAttr['distribution']]) ? h($distributionLevels[$subAttr['distribution']]) : '') ?>"
                                     data-event-distribution="<?= intval($subAttr['distribution']) ?>"
                                     data-event-distribution-name="<?= $subAttr['distribution'] == 4 ? h($subAttr['SharingGroup']['name'] ?? '') : (isset($shortDist[$subAttr['distribution']]) ? h($shortDist[$subAttr['distribution']]) : '') ?>"
                                     data-scope-id="<?= h($subAttr['id']) ?>">
                                </div>
                            </td>
                            <!-- Date -->
                            <td class="col-date">
                                <?php 
                                    $showSubDate = true;
                                    if (isset($event['Event']['date']) && date('Y-m-d', $subAttr['timestamp']) === $event['Event']['date']) {
                                        $showSubDate = false;
                                    }
                                    $isSubNew = isset($event['Event']['publish_timestamp']) && $subAttr['timestamp'] > $event['Event']['publish_timestamp'];
                                ?>
                                <div style="font-size: 10px; color:#999;">
                                    <?php if ($showSubDate): ?>
                                        <?php echo date('Y-m-d', $subAttr['timestamp']); ?>
                                    <?php else: ?>
                                        <?php echo date('H:i', $subAttr['timestamp']); ?>
                                    <?php endif; ?>
                                    <?php if ($isSubNew): ?>
                                        <span class="bold red" title="<?= __('Element or modification to an existing element has not been published yet.') ?>">*</span>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>

                    <?php endforeach; ?>
                <?php endif; ?>

            <?php endforeach; ?>
        </tbody>
    </table>

    <!-- Beta Pagination Controls (Bottom) -->
    <div class="beta-pagination-container beta-pagination-bottom" id="beta-pagination-bottom">
        <div class="beta-pagination-group">
            <div class="beta-pagination-info">
                <span class="beta-page-item-info" id="beta-page-item-info-bottom"><?php echo __('Showing %s-%s of %s items', $betaShowStart, $betaShowEnd, $betaTotalAttributes); ?></span>
            </div>
            <div class="beta-pagination-controls">
                <button type="button" class="btn btn-default btn-sm beta-page-btn" data-page-action="first" title="<?php echo __('First page'); ?>" <?php if ($betaCurrentPage <= 1) echo 'disabled'; ?>><i class="fa fa-angle-double-left"></i></button>
                <button type="button" class="btn btn-default btn-sm beta-page-btn" data-page-action="prev" title="<?php echo __('Previous page'); ?>" <?php if ($betaCurrentPage <= 1) echo 'disabled'; ?>><i class="fa fa-angle-left"></i></button>
                <span class="beta-page-num-display" id="beta-page-num-display-bottom"><?php echo __('%s / %s', $betaCurrentPage, $betaTotalPages); ?></span>
                <button type="button" class="btn btn-default btn-sm beta-page-btn" data-page-action="next" title="<?php echo __('Next page'); ?>" <?php if ($betaCurrentPage >= $betaTotalPages) echo 'disabled'; ?>><i class="fa fa-angle-right"></i></button>
                <button type="button" class="btn btn-default btn-sm beta-page-btn" data-page-action="last" title="<?php echo __('Last page'); ?>" <?php if ($betaCurrentPage >= $betaTotalPages) echo 'disabled'; ?>><i class="fa fa-angle-double-right"></i></button>
            </div>
        </div>
    </div>
</div>
    <script>
    var currentUri = "<?php echo isset($currentUri) ? h($currentUri) : $baseurl . '/events/viewEventAttributes/' . h($event['Event']['id']); ?>";

    // ===== Beta Pagination Logic (Server-Side via AJAX) =====
    // Use window-level object so it persists across AJAX reloads and isn't duplicated
    window.paginationState = {
        currentPage: <?php echo $betaCurrentPage; ?>,
        pageSize: <?php echo $betaPageSize; ?>,
        totalPages: <?php echo $betaTotalPages; ?>,
        totalAttributes: <?php echo $betaTotalAttributes; ?>,
        eventId: <?php echo (int)$event['Event']['id']; ?>,
        baseUrl: "<?php echo $baseurl; ?>",
        attributeType: "<?php echo isset($filters['attributeType']) ? h($filters['attributeType']) : ''; ?>",
        activeXhr: null,
        loading: false
    };

    function getAttributesContainer() {
        var $container = $('#beta-attributes-list');
        if (!$container.length) {
            $container = $('#beta-attributes-container');
        }
        return $container;
    }

    function abortActiveRequest() {
        if (window.paginationState.activeXhr) {
            window.paginationState.activeXhr.abort();
            window.paginationState.activeXhr = null;
        }
    }

    function setAttributesLoadingState(isLoading) {
        var $container = getAttributesContainer();
        $container.css('opacity', isLoading ? '0.5' : '1');
        if (isLoading) {
            $('.beta-page-btn').prop('disabled', true);
        }
        return $container;
    }

    function buildAttributesUrl(params) {
        var rawUrl = currentUri || (window.paginationState.baseUrl + '/events/viewEventAttributes/' + window.paginationState.eventId);
        if (/^https?:\/\//i.test(rawUrl)) {
            try {
                rawUrl = new URL(rawUrl).pathname + (new URL(rawUrl).search || '');
            } catch (e) {
                rawUrl = rawUrl.replace(/^https?:\/\/[^/]+/i, '');
            }
        }
        var parts = rawUrl.split('?');
        var path = parts[0] || '';
        var query = parts.length > 1 ? '?' + parts.slice(1).join('?') : '';

        var segments = path.split('/');
        var preservedSegments = [];
        for (var i = 0; i < segments.length; i++) {
            var segment = segments[i];
            if (!segment) {
                continue;
            }
            if (
                segment.indexOf('page:') === 0 ||
                segment.indexOf('limit:') === 0 ||
                segment.indexOf('sort:') === 0 ||
                segment.indexOf('direction:') === 0 ||
                segment.indexOf('searchFor:') === 0 ||
                segment.indexOf('attributeType:') === 0 ||
                segment.indexOf('beta:') === 0
            ) {
                continue;
            }
            preservedSegments.push(segment);
        }

        if (params.searchFor) {
            preservedSegments.push('searchFor:' + encodeURIComponent(params.searchFor));
        }
        if (window.paginationState.attributeType) {
            preservedSegments.push('attributeType:' + encodeURIComponent(window.paginationState.attributeType));
        }
        preservedSegments.push('page:' + params.page);
        preservedSegments.push('limit:' + params.limit);
        preservedSegments.push('sort:timestamp');
        preservedSegments.push('direction:desc');
        preservedSegments.push('beta:1');

        return (path.charAt(0) === '/' ? '/' : '') + preservedSegments.join('/') + query;
    }

    function renderAttributesResponse($container, data, shouldScroll) {
        $container.html(data);
        $container.css('opacity', '1');
        if (typeof window.initBetaBulkActions === 'function') {
            window.initBetaBulkActions();
        }
        if (typeof window.clearBetaSelectedAttributes === 'function') {
            window.clearBetaSelectedAttributes();
        } else {
            $('.select_attribute, .select_all, input[class^="select_all_object_attributes_"]').prop('checked', false);
        }
        if (typeof window.updateBetaBulkActionBar === 'function') {
            window.updateBetaBulkActionBar();
        } else if (typeof attributeListAnyAttributeCheckBoxesChecked === 'function') {
            attributeListAnyAttributeCheckBoxesChecked();
        }
        if (shouldScroll) {
            var offset = $container.offset();
            if (offset) {
                $('html, body').animate({ scrollTop: offset.top - 60 }, 200);
            }
        }
        initAttributeWidgets();
    }

    function initAttributeWidgets() {
        $('.distributionNetworkToggle').each(function() {
            $(this).distributionNetwork({
                distributionData: <?= json_encode($this->DistributionGraph->getGraphData($event['Event']['id']), JSON_UNESCAPED_UNICODE); ?>,
            });
        });
        if (typeof popoverStartup === 'function') {
            popoverStartup();
        }
    }

    function restoreMovedMenu(activeMenu) {
        var $menu = activeMenu && activeMenu.length ? activeMenu : $('.beta-row-menu.active-moved');
        if (!$menu.length) {
            return false;
        }
        var oldTrigger = $menu.data('trigger');
        $menu.hide().removeClass('active-moved').css({top: '', left: '', position: '', zIndex: ''});
        if (oldTrigger && oldTrigger[0].parentNode) {
            oldTrigger.after($menu);
        } else {
            $menu.remove();
        }
        return true;
    }

    function parseToggleResponse(data) {
        if (typeof data !== 'string') {
            return data;
        }
        try {
            return JSON.parse(data);
        } catch (e) {
            return null;
        }
    }

    function buildToggleErrorMessage(defaultMessage, errors) {
        var message = defaultMessage;
        if (!errors) {
            return message;
        }
        if (typeof errors === 'string') {
            return message + ' ' + errors;
        }
        if (typeof errors === 'object') {
            for (var key in errors) {
                message += ' ' + errors[key];
            }
        }
        return message;
    }

    function updateCorrelationToggleState($icon, isDisabled) {
        $icon.data('disable-correlation', isDisabled ? 1 : 0);
        if (isDisabled) {
            $icon.css({ 'opacity': '0.2', 'color': '' });
            $icon.attr('title', '<?= __('Correlation disabled') ?>');
        } else {
            $icon.css({ 'opacity': '1', 'color': '#428bca' });
            $icon.attr('title', '<?= __('Correlation enabled') ?>');
        }
    }

    function updateIdsToggleState($icon, isEnabled) {
        $icon.data('to-ids', isEnabled ? 1 : 0);
        if (isEnabled) {
            $icon.removeClass('text-muted');
            $icon.css({
                'color': '#ff8c00',
                'opacity': '1'
            });
            $icon.attr('title', '<?= __('Recommended for blocking / alerting') ?>');
        } else {
            $icon.addClass('text-muted');
            $icon.css({
                'color': '',
                'opacity': '0.2'
            });
            $icon.attr('title', '<?= __('Not recommended for blocking / alerting') ?>');
        }
    }

    function postAttributeFieldToggle(id, field, value, onSuccess, defaultErrorMessage, onError) {
        var payload = {
            'Attribute': {}
        };
        payload.Attribute[field] = value;
        xhr({
            url: '/attributes/editField/' + id,
            type: 'POST',
            data: payload,
            success: function(data) {
                data = parseToggleResponse(data);
                if (!data) {
                    showMessage('fail', 'Invalid response from server.');
                    return;
                }
                if (data.saved) {
                    onSuccess(data);
                    return;
                }
                showMessage('fail', buildToggleErrorMessage(defaultErrorMessage, data.errors));
            },
            error: function(jqXHR, textStatus) {
                if (typeof onError === 'function') {
                    onError(jqXHR, textStatus);
                    return;
                }
                showMessage('fail', 'An error occurred while updating the setting: ' + textStatus);
            }
        });
    }

    window.paginationLoadPage = function(page, limit) {
        if (typeof page === 'undefined') page = window.paginationState.currentPage;
        if (typeof limit === 'undefined') limit = window.paginationState.pageSize;

        abortActiveRequest();

        // Prevent duplicate requests while loading
        if (window.paginationState.loading) return;
        window.paginationState.loading = true;

        // When limit is 0 ("All"), pass page:0 to disable server-side pagination
        var effectivePage = (limit === 0) ? 0 : page;

        var url = buildAttributesUrl({
            page: effectivePage,
            limit: (limit === 0 ? 0 : limit)
        });
        var $container = setAttributesLoadingState(true);

        window.paginationState.activeXhr = $.ajax({
            url: url,
            type: 'GET',
            success: function(data) {
                renderAttributesResponse($container, data, true);
            },
            error: function(jqXHR, textStatus) {
                if (textStatus === 'abort') return; // Intentional abort, ignore
                $container.css('opacity', '1');
                $('.beta-page-btn').prop('disabled', false);
                if (typeof showMessage === 'function') {
                    showMessage('fail', 'Failed to load page.');
                }
            },
            complete: function() {
                window.paginationState.activeXhr = null;
                window.paginationState.loading = false;
            }
        });
    };

    window.paginationGo = function(target) {
        var page = window.paginationState.currentPage;
        if (target === 'prev') {
            page = Math.max(1, page - 1);
        } else if (target === 'next') {
            page = Math.min(window.paginationState.totalPages, page + 1);
        } else if (target === 'last') {
            page = window.paginationState.totalPages;
        } else if (target === 'first') {
            page = 1;
        } else {
            page = parseInt(target, 10) || 1;
        }
        window.paginationLoadPage(page, window.paginationState.pageSize);
    };

    window.paginationChangeSize = function(newSize) {
        var limit = parseInt(newSize, 10);
        window.paginationLoadPage(1, limit);
    };
    // ===== End Beta Pagination Logic =====

    // Column state (preserve across AJAX reloads)
    if (typeof window.columnVisibility === 'undefined') {
        window.columnVisibility = {
            date: true,
            sightings: true,
            distribution: true,
            correlation: true,
            related: true,
        };
    }

    function toggleBetaColumn(col) {
        window.columnVisibility[col] = !window.columnVisibility[col];
        $('.col-' + col).toggle(window.columnVisibility[col]);
        $('.col-' + col + '-row').toggle(window.columnVisibility[col]);
        $('.col-check-' + col).toggleClass('fa-check fa-times');
    }

    if (typeof window.allExpanded === 'undefined') {
        window.allExpanded = true;
    }

    function updateExpandAllUi() {
        if (window.allExpanded) {
            $('#btn-toggle-all i').removeClass('fa-expand').addClass('fa-compress');
            $('#label-toggle-all').text('Collapse objects');
        } else {
            $('#btn-toggle-all i').removeClass('fa-compress').addClass('fa-expand');
            $('#label-toggle-all').text('Expand objects');
        }
    }

    function toggleAllObjectsAttributes() {
        window.allExpanded = !window.allExpanded;
        $('.object-attr-row, .col-tags-row, .col-galaxies-row').toggle(window.allExpanded);
        updateExpandAllUi();
    }

    function showRelatedMenu(el, attributeId) {
        getPopup(attributeId, 'attributes', 'relatedAttributes', '', '#confirmation_box');
    }

    function scheduleSearch(callback) {
        if (window._betaSearchTimer) {
            clearTimeout(window._betaSearchTimer);
        }
        window._betaSearchTimer = setTimeout(callback, 400);
    }

    $(function() {
        if (typeof window.initBetaBulkActions === 'function') {
            window.initBetaBulkActions();
        }

        Object.keys(window.columnVisibility).forEach(function(col) {
            $('.col-' + col).toggle(window.columnVisibility[col]);
            if (window.columnVisibility[col]) {
                $('.col-check-' + col).addClass('fa-check').removeClass('fa-times');
            } else {
                $('.col-check-' + col).addClass('fa-times').removeClass('fa-check');
            }
        });

        if (window._betaAttributeHandlersInitialized) {
            return;
        }
        window._betaAttributeHandlersInitialized = true;

        // Pagination button click handlers (namespaced to allow clean removal)
        $(document).on('click.betaAttr', '.beta-page-btn', function(e) {
            e.preventDefault();
            e.stopPropagation();
            if ($(this).prop('disabled')) return;
            var action = $(this).data('page-action');
            window.paginationGo(action);
        });

        // Page size change handler
        $(document).on('change.betaAttr', '#beta-page-size', function() {
            window.paginationChangeSize($(this).val());
        });

        // Search filtering uses server-side search via viewEventAttributes
        $(document).on('keyup.betaAttr', '#beta-attr-search', function() {
            var val = $(this).val();

            if (val.length > 0) {
                scheduleSearch(function() {
                    abortActiveRequest();
                    var url = buildAttributesUrl({
                        searchFor: val,
                        page: 1,
                        limit: window.paginationState.pageSize
                    });
                    var $container = setAttributesLoadingState(true);
                    window.paginationState.activeXhr = $.ajax({
                        url: url,
                        type: 'GET',
                        success: function(data) {
                            renderAttributesResponse($container, data, false);
                        },
                        error: function(jqXHR, textStatus) {
                            if (textStatus === 'abort') return;
                            $container.css('opacity', '1');
                        },
                        complete: function() {
                            window.paginationState.activeXhr = null;
                        }
                    });
                });
            } else {
                scheduleSearch(function() {
                    window.paginationLoadPage(1, window.paginationState.pageSize);
                });
            }
        });

        // Individual Object Toggle
        $(document).on('click.betaAttr', '.object-header-row', function(e) {
            if ($(e.target).closest('.beta-row-actions, .beta-row-menu, .beta-row-menu-trigger, a, button, input, label').length) {
                return;
            }
            var objectId = $(this).data('object-id');
            $('.object-attr-row[data-parent-object-id="' + objectId + '"]').toggle();
        });

        // Correlation Toggle handling
        $(document).on('click.betaAttr', '.beta-correlation-toggle', function() {
            <?php if (!$mayModify): ?>
                return false;
            <?php else: ?>
                var $this = $(this);
                var id = $this.data('id');
                var newStatus = $this.data('disable-correlation') === 1 ? 0 : 1;

                postAttributeFieldToggle(
                    id,
                    'disable_correlation',
                    newStatus,
                    function() {
                        updateCorrelationToggleState($this, newStatus === 1);
                        showMessage('success', 'Correlation flag updated.');
                    },
                    'Failed to update correlation flag.'
                );
            <?php endif; ?>
        });

        // Dropdown handling
        // Cleanup orphans from previous executions
        $('.beta-row-menu.active-moved').remove();

        $(document).on('click.betaAttr', '.beta-row-menu-trigger', function(e) {
            e.stopPropagation();
            var trigger = $(this);
            
            // Check for existing active menu
            var activeMenu = $('.beta-row-menu.active-moved');
            if (activeMenu.length) {
                var oldTrigger = activeMenu.data('trigger');
                restoreMovedMenu(activeMenu);
                
                if (oldTrigger && oldTrigger[0] === trigger[0]) return; // Toggle off
            }

            var menu = trigger.next('.beta-row-menu');
            $('.beta-row-menu').not(menu).hide();

            // Move to body
            menu.addClass('active-moved').appendTo('body');
            menu.data('trigger', trigger);
            
            var offset = trigger.offset();
            var triggerHeight = trigger.outerHeight();
            
            menu.css({
                display: 'block',
                position: 'absolute',
                top: (offset.top + triggerHeight) + 'px',
                left: offset.left + 'px',
                zIndex: 10000
            });
            
            var rect = menu[0].getBoundingClientRect();
            var viewportHeight = window.innerHeight || document.documentElement.clientHeight;
            
            if (rect.bottom > viewportHeight) {
                 menu.css({
                    top: (offset.top - menu.outerHeight()) + 'px'
                 });
            }
        });

        $(document).on('click.betaAttr', function(e) {
            var activeMenu = $('.beta-row-menu.active-moved');
            if (activeMenu.length) {
                if ($(e.target).closest('.beta-row-menu.active-moved').length) return;
                restoreMovedMenu(activeMenu);
            }
        });

        // Prevent closing when clicking inside the menu
        $(document).on('click.betaAttr', '.beta-row-menu', function(e) {
            e.stopPropagation();
        });

        // Close dropdown after selecting an action so dialogs are visible
        $(document).on('click.betaAttr', '.beta-row-menu a', function() {
            var activeMenu = $('.beta-row-menu.active-moved');
            if (!activeMenu.length) {
                return;
            }
            restoreMovedMenu(activeMenu);
        });
        
        // Select All checkboxes
        $(document).on('change.betaAttr', '.select-all', function() {
            var checked = $(this).prop('checked');
            $('.select-row').prop('checked', checked);
        });

        // IDS Toggle handling
        $(document).on('click.betaAttr', '.beta-ids-toggle', function() {
            <?php if (!$mayModify): ?>
                return false;
            <?php else: ?>
                var $this = $(this);
                var id = $this.data('id');
                var newStatus = $this.data('to-ids') === 1 ? 0 : 1;

                postAttributeFieldToggle(
                    id,
                    'to_ids',
                    newStatus,
                    function() {
                        updateIdsToggleState($this, newStatus === 1);
                        showMessage('success', 'IDS flag updated.');
                        if (typeof eventUnpublish === 'function') {
                            eventUnpublish();
                        }
                    },
                    'Failed to update IDS flag.',
                    function(jqXHR, textStatus) {
                        showMessage('fail', 'An error occurred while updating the IDS flag: ' + textStatus);
                    }
                );
            <?php endif; ?>
        });

        <?php
            if (isset($focus)):
        ?>
        focusObjectByUuid('<?= h($focus); ?>');
        <?php
            endif;
        ?>
        updateExpandAllUi();
        initAttributeWidgets();
    });
    </script>
