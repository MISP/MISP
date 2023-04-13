<?php
// When viewing remote server or feed event
if (isset($preview) && $preview) {
    $static_tags_only = true;
} else {
    $preview = false;
}

if ($target_type === 'event' || $target_type === 'attribute') {
    $tagAccess = $this->Acl->canModifyTag($event);
    if (empty($local_tag_off) || !empty($event)) {
        $localTagAccess = $this->Acl->canModifyTag($event, true);
    } else {
        $localTagAccess = false;
    }
}

$editButtonsEnabled = empty($static_tags_only) && $tagAccess;
$editButtonsLocalEnabled = empty($static_tags_only) && $localTagAccess && empty($local_tag_off);

$sortClusters = function (array $clusters) {
    usort($clusters, function (array $a, array $b) {
        $aExternalId = $a['meta']['external_id'][0] ?? null;
        $bExternalId = $b['meta']['external_id'][0] ?? null;
        if ($aExternalId && $bExternalId) {
            return strcmp($aExternalId, $bExternalId);
        }
        return strcmp($a['value'], $b['value']);
    });
    return $clusters;
};

$normalizeKey = function ($key) {
    $key = str_replace('-', '_', $key);
    $key = Inflector::humanize($key);
    $key = str_replace('Id', 'ID', $key);
    $key = str_replace('Mitre', 'MITRE', $key);
    $key = str_replace('Cfr', 'CFR', $key);
    return $key;
};

$generatePopover = function (array $cluster) use ($normalizeKey) {
    $clusterFields = [];
    if (!empty($cluster['description'])) {
        $clusterFields[] = ['key' => 'description', 'value' => $this->Markdown->toText($cluster['description'])];
    }
    if (isset($cluster['meta']['synonyms'])) {
        $clusterFields[] = ['key' => 'synonyms', 'value' => $cluster['meta']['synonyms']];
    }
    if (isset($cluster['source'])) {
        $clusterFields[] = ['key' => 'source', 'value' => $cluster['source']];
    }
    if (!empty($cluster['meta'])) {
        foreach ($cluster['meta'] as $metaKey => $metaField) {
            if (!in_array($metaKey, ['synonyms', 'refs'], true)) {
                $clusterFields[] = ['key' => $metaKey, 'value' => $metaField];
            }
        }
    }
    $popover = '<h4 class="blue" style="white-space: nowrap">' . h($cluster['value']) . '</h4>';
    foreach ($clusterFields as $clusterField) {
        $key = '<b class="blue">' . h($normalizeKey($clusterField['key'])) . '</b>';
        if (is_array($clusterField['value'])) {
            if ($clusterField['key'] === 'country') {
                $value = [];
                foreach ($clusterField['value'] as $v) {
                    $value[] = $this->Icon->countryFlag($v) . '&nbsp;' . h($v);
                }
                $valueContents = implode("<br>", $value);
            } else {
                if (count($clusterField['value']) < 4) {
                    $valueContents = h(implode(", ", $clusterField['value']));
                } else {
                    $valueContents = nl2br("\n" . h(implode("\n", $clusterField['value'])), false);
                }
            }
        } else {
            $valueContents = h($clusterField['value']);
        }
        $popover .= "$key: $valueContents<br>";
    }
    return $popover;
}
?>
<?php if (!empty($data)): ?>
<div class="galaxyQuickView">
<?php foreach ($data as $galaxy): ?>
    <h3 title="<?= isset($galaxy['description']) ? h($galaxy['description']) : h($galaxy['name']) ?>">
        <?= h($galaxy['name']) ?>
        <?php if (!$preview): ?>
        <a href="<?= $baseurl ?>/galaxies/view/<?= h($galaxy['id']) ?>" class="black fa fa-search" title="<?= __('View details about this galaxy') ?>" aria-label="<?= __('View galaxy') ?>"></a>
        <?php endif ;?>
    </h3>
    <ul>
    <?php 
        foreach ($sortClusters($galaxy['GalaxyCluster']) as $cluster) {
            $action_html = '';
            if (!$preview) {
                $action_items = [
                    [
                        'url' => $baseurl . '/galaxy_clusters/view/' . h($cluster['id']),
                        'onClick' => false,
                        'class' => 'black fa fa-search',
                        'title' => __('View details about this cluster')
                    ],
                    [
                        'url' => $baseurl . '/events/index/searchtag:' . h($cluster['tag_id']),
                        'onClick' => false,
                        'class' => 'black fa fa-list',
                        'title' => __('View all events containing this cluster')
                    ]
                ];
                if ($editButtonsEnabled || ($editButtonsLocalEnabled && $cluster['local'])) {
                    if ($target_type !== 'tag_collection') {
                        $action_items[] = [
                            'url' => sprintf(
                                "%s/tags/modifyTagRelationship/%s/%s",
                                $baseurl,
                                h($target_type),
                                h($cluster[$target_type . '_tag_id'])
                            ),
                            'onClick' => false,
                            'class' => 'useCursorPointer black fas fa-project-diagram modal-open',
                            'title' => __('Modify tag relationship')
                        ];
                    }
                    $action_items[] = [
                        'url' => $baseurl . '/galaxy_clusters/detach/' . intval($target_id) . '/' . h($target_type) . '/' . h($cluster['tag_id']),
                        'onClick' => sprintf(
                            "confirmClusterDetach(this, '%s', %s)",
                            h($target_type),
                            intval($target_id)
                        ),
                        'class' => 'black fas fa-trash',
                        'aria_label' => __('Detach'),
                        'title' => __('Are you sure you want to detach %s from this %s?', h($cluster['value']), $target_type),
                    ];
                }
                foreach ($action_items as $action_item) {
                    $action_html .= sprintf(
                        '<a %s %s title="%s" aria-label="%s" class="%s" role="button" tabindex="0"></a> ',
                        empty($action_item['url']) ? '' : 'href="' . $action_item['url'] . '"',
                        $action_item['onClick'] ? 'onClick="' . $action_item['onClick'] . '"' : '',
                        $action_item['title'],
                        empty($action_item['aria_label']) ? $action_item['title'] : $action_item['aria_label'],
                        $action_item['class']
                    );
                }
            }
            echo sprintf(
                '<li>%s %s</li>',
                sprintf(
                    '%s<b %s data-content="%s"><i class="fas fa-%s" title="%s"></i> %s</b>',
                    empty($cluster['relationship_type']) ?  '' : sprintf(
                        '<span class="tagComplete white" style="background-color:black">%s:</span> ',
                        h($cluster['relationship_type'])
                    ),
                    $preview ? '' : 'class="useCursorPointer" data-clusterid="' . h($cluster['id']) . '"',
                    h($generatePopover($cluster)),
                    $cluster['local'] ? 'user' : 'globe-americas',
                    $cluster['local'] ? __('Local galaxy') : __('Global galaxy'),

                    h($cluster['value'])
                ),
                $action_html
            );
        }
    ?>
    </ul>
<?php endforeach; ?>
</div>
<?php endif; ?>
<?php
if ($editButtonsEnabled) {
    $link = "$baseurl/galaxies/selectGalaxyNamespace/" . h($target_id) . "/" . h($target_type) . "/local:0";
    echo sprintf(
        '<button class="%s" data-popover-popup="%s" role="button" tabindex="0" aria-label="' . __('Add new cluster') . '" title="' . __('Add new cluster') . '">%s</button>',
        'useCursorPointer addButton btn btn-inverse',
        $link,
        '<i class="fas fa-globe-americas"></i> <i class="fas fa-plus"></i>'
    );
}

if ($editButtonsLocalEnabled) {
    $link = "$baseurl/galaxies/selectGalaxyNamespace/" . h($target_id) . "/" . h($target_type) . "/local:1";
    echo sprintf(
        '<button class="%s" data-popover-popup="%s" role="button" tabindex="0" aria-label="' . __('Add new local cluster') . '" title="' . __('Add new local cluster') . '">%s</button>',
        'useCursorPointer addButton btn btn-inverse',
        $link,
        '<i class="fas fa-user"></i> <i class="fas fa-plus"></i>'
    );
}
