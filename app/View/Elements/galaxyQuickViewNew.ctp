<?php
// When viewing remote server or feed event
if (isset($preview) && $preview) {
    $mayModify = false;
    $isAclTagger = false;
    $static_tags_only = true;
} else {
    $preview = false;
}
$tagAccess = ($isSiteAdmin || ($mayModify && $isAclTagger));
if (empty($local_tag_off) || !empty($event)) {
    $localTagAccess = ($isSiteAdmin || ($mayModify || $me['org_id'] == $event['Event']['org_id'] || (int)$me['org_id'] === Configure::read('MISP.host_org_id'))) && $isAclTagger;
} else {
    $localTagAccess = false;
}

$editButtonsEnabled = empty($static_tags_only) && $tagAccess;
$editButtonsLocalEnabled = empty($static_tags_only) && $localTagAccess && empty($local_tag_off);

$sortClusters = function (array $clusters) {
    usort($clusters, function (array $a, array $b) {
        $aExternalId = isset($a['meta']['external_id'][0]) ? $a['meta']['external_id'][0] : null;
        $bExternalId = isset($b['meta']['external_id'][0]) ? $b['meta']['external_id'][0] : null;
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
        $key = '<span class="blue bold">' . h($normalizeKey($clusterField['key'])) . '</span>';
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
    <?php foreach ($sortClusters($galaxy['GalaxyCluster']) as $cluster): ?>
        <li>
            <b <?php if (!$preview): ?>class="useCursorPointer" data-clusterid="<?= h($cluster['id']) ?>"<?php endif; ?> data-content="<?= h($generatePopover($cluster)) ?>">
                <i class="fas fa-<?= $cluster['local'] ? 'user' : 'globe-americas' ?>" title="<?= $cluster['local'] ? __('Local galaxy') : __('Global galaxy') ?>"></i>
                <?= h($cluster['value']) ?>
            </b>
            <?php if (!$preview): ?>
            <a href="<?= $baseurl ?>/galaxy_clusters/view/<?= h($cluster['id']) ?>" class="black fa fa-search" title="<?= __('View details about this cluster') ?>" aria-label="<?= __('View cluster') ?>"></a>
            <a href="<?= $baseurl ?>/events/index/searchtag:<?= h($cluster['tag_id']) ?>" class="black fa fa-list" title="<?= __('View all events containing this cluster') ?>" aria-label="<?= __('View all events containing this cluster') ?>"></a>
            <?php endif ;?>
            <?php if ($editButtonsEnabled || ($editButtonsLocalEnabled && $cluster['local'])) {
echo $this->Form->create(false, [
    'id' => false, // prevent duplicate ids
    'url' => $baseurl . '/galaxy_clusters/detach/' . ucfirst(h($target_id)) . '/' . h($target_type) . '/' . $cluster['tag_id'],
    'style' => 'display: inline-block; margin: 0px;'
]);
echo sprintf(
    '<a href="#" class="black fa fa-trash useCursorPointer" role="button" tabindex="0" aria-label="%s" title="%s" onclick="popoverConfirm(this);"></a>',
    __('Detach'),
    __('Are you sure you want to detach %s from this event?', h($cluster['value']))
);
echo $this->Form->end();
}
?>
        </li>
    <?php endforeach; ?>
    </ul>
<?php endforeach; ?>
</div>
<?php endif; ?>
<?php
if ($editButtonsEnabled) {
    echo sprintf(
        '<button class="%s" data-target-type="%s" data-target-id="%s" data-local="false" role="button" tabindex="0" aria-label="' . __('Add new cluster') . '" title="' . __('Add new cluster') . '">%s</button>',
        'useCursorPointer btn btn-inverse addGalaxy',
        h($target_type),
        h($target_id),
        '<i class="fas fa-globe-americas"></i> <i class="fas fa-plus"></i>'
    );
}

if ($editButtonsLocalEnabled) {
    echo sprintf(
        '<button class="%s" data-target-type="%s" data-target-id="%s" data-local="true" role="button" tabindex="0" aria-label="' . __('Add new local cluster') . '" title="' . __('Add new local cluster') . '">%s</button>',
        'useCursorPointer btn btn-inverse addGalaxy',
        h($target_type),
        h($target_id),
        '<i class="fas fa-user"></i> <i class="fas fa-plus"></i>'
    );
}
