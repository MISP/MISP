<?php
/**
 * Beta version of Events/eventIndexTable element
 * 
 * This demonstrates the beta UI pattern by reordering columns:
 * Column 1: ID
 * Column 2: Info
 * Column 3: Publish Status
 * 
 * All other columns follow after these three.
 * 
 * @since 2.5.x (beta)
 */

$buildVisibleTagFamilies = function (array $tags) {
    $tagFamilies = [];
    foreach ($tags as $tag) {
        $tagName = $tag['Tag']['name'] ?? '';
        if ($tagName === '') {
            continue;
        }
        $tagFamily = strpos($tagName, ':') !== false ? explode(':', $tagName, 2)[0] : $tagName;
        if (!isset($tagFamilies[$tagFamily])) {
            $tagFamilies[$tagFamily] = [];
        }
        $tagFamilies[$tagFamily][] = $tag;
    }

    $visibleTags = [];
    foreach ($tagFamilies as $familyTags) {
        $visibleTags[] = reset($familyTags);
    }
    return $visibleTags;
};

$buildGalaxyCardsFromTags = function (array $galaxyTags) use ($baseurl) {
    if (empty($galaxyTags)) {
        return [];
    }
    $galaxies = [];
    foreach ($galaxyTags as $galaxyTag) {
        $tagName = $galaxyTag['Tag']['name'] ?? '';
        if (strpos($tagName, 'misp-galaxy:') !== 0) {
            continue;
        }
        $parts = explode(':', $tagName);
        if (count($parts) < 2) {
            continue;
        }
        $galaxyName = $parts[1];
        $clusterValue = '';
        if (count($parts) >= 3) {
            $clusterValue = trim($parts[2], '"');
            $clusterValue = explode('=', $clusterValue);
            $clusterValue = end($clusterValue);
            $clusterValue = trim($clusterValue, '"');
        }
        if (!isset($galaxies[$galaxyName])) {
            $galaxies[$galaxyName] = [];
        }
        $galaxies[$galaxyName][] = [
            'value' => $clusterValue,
            'local' => $galaxyTag['local'],
            'relationship_type' => $galaxyTag['relationship_type'],
            'tag_id' => $galaxyTag['Tag']['id'],
        ];
    }

    $galaxyCards = [];
    foreach ($galaxies as $galaxyName => $clusters) {
        $galaxyCards[] = $this->element('Events/View/galaxy_compact_beta', [
            'galaxyName' => $galaxyName,
            'clusters' => $clusters,
            'baseurl' => $baseurl,
        ]);
    }
    return $galaxyCards;
};

$buildRecencyMeta = function ($timestamp, $scaleLabel, $ageType = 'date') {
    $hasDateOnlyPrecision = $ageType === 'date';
    $normalisedTimestamp = is_numeric($timestamp) ? (int)$timestamp : strtotime((string)$timestamp);
    if (empty($normalisedTimestamp)) {
        return [
            'class' => 'is-unknown',
            'title' => __('unavailable'),
            'filled' => 0,
            'band' => __('Unknown'),
        ];
    }

    $nowTs = time();
    if ($hasDateOnlyPrecision) {
        $normalisedTimestamp = strtotime(date('Y-m-d', $normalisedTimestamp) . ' 00:00:00');
        $nowTs = strtotime(date('Y-m-d', $nowTs) . ' 00:00:00');
    }

    $ageDays = max(0, (int)floor(($nowTs - $normalisedTimestamp) / 86400));
    if ($ageDays <= 3) {
        return [
            'class' => 'is-hot',
            'title' => __('within last 3 days (%s days old)', $ageDays),
            'filled' => 6,
            'band' => __('0-3d'),
        ];
    }
    if ($ageDays <= 14) {
        return [
            'class' => 'is-week',
            'title' => __('within last 14 days (%s days old)', $ageDays),
            'filled' => 5,
            'band' => __('4-14d'),
        ];
    }
    if ($ageDays <= 90) {
        return [
            'class' => 'is-month',
            'title' => __('within last 90 days (%s days old)', $ageDays),
            'filled' => 4,
            'band' => __('15-90d'),
        ];
    }
    if ($ageDays <= 180) {
        return [
            'class' => 'is-quarter',
            'title' => __('within last 6 months (%s days old)', $ageDays),
            'filled' => 3,
            'band' => __('3-6mo'),
        ];
    }
    if ($ageDays <= 730) {
        return [
            'class' => 'is-year',
            'title' => __('within last 2 years (%s days old)', $ageDays),
            'filled' => 2,
            'band' => __('6-24mo'),
        ];
    }

    return [
        'class' => 'is-older',
        'title' => __('older than 2 years (%s days old)', $ageDays),
        'filled' => 1,
        'band' => __('2y+'),
    ];
};

?>
<style>
    .beta-event-date-stack {
        display: flex;
        align-items: center;
        gap: 4px;
        margin-top: 0.35em;
        flex-wrap: wrap;
    }

    .beta-event-freshness-pair {
        display: inline-flex;
        align-items: center;
        gap: 3px;
        box-sizing: border-box;
        opacity: 0.72;
        transition: opacity 120ms ease;
        cursor: default;
    }

    .beta-event-freshness-pair:hover,
    .beta-event-freshness-pair:focus {
        opacity: 0.92;
    }

    .beta-event-freshness-icon {
        color: #a8b1bc;
        font-size: 10px;
        line-height: 1;
        width: 10px;
        text-align: center;
        flex: 0 0 10px;
    }

    .beta-event-freshness-grid {
        display: inline-flex;
        flex-direction: column;
        gap: 1px;
    }

    .beta-event-recency-row {
        display: inline-flex;
        align-items: center;
        gap: 0;
        min-width: 0;
    }

    .beta-event-date-label {
        color: #7b8593;
        font-size: 12px;
        line-height: 1.3;
        white-space: nowrap;
    }

    .beta-event-freshness-scale {
        display: inline-flex;
        align-items: center;
        gap: 0;
        padding: 0;
        border: 0;
        border-radius: 0;
        background: transparent;
        white-space: nowrap;
        overflow: hidden;
    }

    .beta-event-freshness-rail {
        display: inline-flex;
        align-items: center;
        gap: 0;
        padding: 0;
    }

    .beta-event-freshness-segment {
        width: 7px;
        height: 6px;
        border-radius: 0;
        background: #e5e9ee;
        transition: background-color 120ms ease, opacity 120ms ease;
        opacity: 0.5;
    }

    .beta-event-freshness-segment:first-child {
        border-radius: 2px 0 0 2px;
    }

    .beta-event-freshness-segment:last-child {
        border-radius: 0 2px 2px 0;
    }

    .beta-event-freshness-scale.is-hot .beta-event-freshness-segment:nth-child(-n+6),
    .beta-event-freshness-scale.is-week .beta-event-freshness-segment:nth-child(-n+5),
    .beta-event-freshness-scale.is-month .beta-event-freshness-segment:nth-child(-n+4),
    .beta-event-freshness-scale.is-quarter .beta-event-freshness-segment:nth-child(-n+3),
    .beta-event-freshness-scale.is-year .beta-event-freshness-segment:nth-child(-n+2),
    .beta-event-freshness-scale.is-older .beta-event-freshness-segment:nth-child(-n+1) {
        opacity: 1;
    }

    .beta-event-freshness-scale.is-hot .beta-event-freshness-segment:nth-child(-n+6) {
        background: linear-gradient(180deg, #86ef8c 0%, #2db13f 100%);
        box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.22);
    }

    .beta-event-freshness-scale.is-week .beta-event-freshness-segment:nth-child(-n+5) {
        background: linear-gradient(180deg, #72c96a 0%, #538f49 100%);
    }

    .beta-event-freshness-scale.is-month .beta-event-freshness-segment:nth-child(-n+4) {
        background: linear-gradient(180deg, #9ec86b 0%, #748f4e 100%);
    }

    .beta-event-freshness-scale.is-quarter .beta-event-freshness-segment:nth-child(-n+3) {
        background: linear-gradient(180deg, #b4c66e 0%, #8a8d53 100%);
    }

    .beta-event-freshness-scale.is-year .beta-event-freshness-segment:nth-child(-n+2) {
        background: linear-gradient(180deg, #c3be74 0%, #9a8656 100%);
    }

    .beta-event-freshness-scale.is-older .beta-event-freshness-segment:nth-child(-n+1) {
        background: linear-gradient(180deg, #c8b47a 0%, #8e7755 100%);
    }

    .beta-event-freshness-scale.is-unknown .beta-event-freshness-segment {
        background: #e7eaee;
        opacity: 0.65;
    }

    .beta-events-table .beta-info-link {
        font-weight: 700;
    }

    .beta-freshness-popover {
        text-align: left;
        line-height: 1.35;
        width: 420px;
    }

    .beta-freshness-popover-row {
        display: flex;
        align-items: flex-start;
        gap: 8px;
    }

    .beta-freshness-popover-row + .beta-freshness-popover-row {
        margin-top: 6px;
        padding-top: 6px;
        border-top: 1px solid rgba(255, 255, 255, 0.12);
    }

    .beta-freshness-popover-meta {
        min-width: 0;
        flex: 1 1 auto;
        display: flex;
        align-items: baseline;
        gap: 8px;
        flex-wrap: wrap;
    }

    .beta-freshness-popover-label {
        display: inline-block;
        font-weight: 700;
        color: #2f3338;
        margin-bottom: 0;
        flex: 0 0 88px;
    }

    .beta-freshness-popover-copy {
        color: #2f3338;
        min-width: 0;
        flex: 1 1 180px;
        white-space: normal;
        overflow-wrap: anywhere;
    }

    .beta-freshness-popover-scale {
        display: inline-flex;
        align-items: center;
        flex: 0 0 auto;
        margin-top: 2px;
    }

    .beta-freshness-popover-scale .beta-event-freshness-segment {
        width: 9px;
        height: 8px;
        opacity: 0.3;
    }

    .beta-freshness-popover-scale.is-hot .beta-event-freshness-segment:nth-child(-n+6),
    .beta-freshness-popover-scale.is-week .beta-event-freshness-segment:nth-child(-n+5),
    .beta-freshness-popover-scale.is-month .beta-event-freshness-segment:nth-child(-n+4),
    .beta-freshness-popover-scale.is-quarter .beta-event-freshness-segment:nth-child(-n+3),
    .beta-freshness-popover-scale.is-year .beta-event-freshness-segment:nth-child(-n+2),
    .beta-freshness-popover-scale.is-older .beta-event-freshness-segment:nth-child(-n+1) {
        opacity: 1;
    }

    .beta-freshness-popover-scale.is-hot .beta-event-freshness-segment:nth-child(-n+6) {
        background: linear-gradient(180deg, #86ef8c 0%, #2db13f 100%);
        box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.22);
    }

    .beta-freshness-popover-scale.is-week .beta-event-freshness-segment:nth-child(-n+5) {
        background: linear-gradient(180deg, #72c96a 0%, #538f49 100%);
    }

    .beta-freshness-popover-scale.is-month .beta-event-freshness-segment:nth-child(-n+4) {
        background: linear-gradient(180deg, #9ec86b 0%, #748f4e 100%);
    }

    .beta-freshness-popover-scale.is-quarter .beta-event-freshness-segment:nth-child(-n+3) {
        background: linear-gradient(180deg, #b4c66e 0%, #8a8d53 100%);
    }

    .beta-freshness-popover-scale.is-year .beta-event-freshness-segment:nth-child(-n+2) {
        background: linear-gradient(180deg, #c3be74 0%, #9a8656 100%);
    }

    .beta-freshness-popover-scale.is-older .beta-event-freshness-segment:nth-child(-n+1) {
        background: linear-gradient(180deg, #c8b47a 0%, #8e7755 100%);
    }

    .beta-freshness-popover-scale.is-unknown .beta-event-freshness-segment {
        background: #e7eaee;
        opacity: 0.5;
    }

    .beta-events-table .beta-org-link,
    .beta-events-table .beta-org-link span {
        font-weight: 400;
    }

</style>
<table class="table table-striped table-hover table-condensed beta-events-table">
    <tr>
        <th>
            <input class="select_all select" type="checkbox" title="<?php echo __('Select all');?>" role="button" tabindex="0" aria-label="<?php echo __('Select all events on current page');?>" onclick="toggleAllCheckboxes();">
        </th>
        <!-- BETA: Column 1 - ID -->
        <th><?= $this->Paginator->sort('id', __('ID'), ['direction' => 'desc']) ?></th>
        <!-- BETA: Column 2 - Info -->
        <th class="filter"><?= $this->Paginator->sort('info');?></th>
        <!-- BETA: Column 3 - Publish Status -->
        <th class="filter" title="<?= __('Published') ?>"><?= $this->Paginator->sort('published', '<i class="fa fa-upload"></i>', ['escape' => false]) ?></th>
        <?php
            if (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg')):
        ?>
            <th class="filter"><?php echo $this->Paginator->sort('Orgc.name', __('Source org')); ?></th>
            <th class="filter"><?php echo $this->Paginator->sort('Orgc.name', __('Member org')); ?></th>
        <?php
            elseif (Configure::read('MISP.showorg') || $isAdmin):
        ?>
            <th class="filter col-creator-org"><?php echo $this->Paginator->sort('Orgc.name', __('Creator org')); ?></th>
        <?php
                endif;
            $date = time();
            $day = 86400;
        ?> 
        <?php if (in_array('owner_org', $columns, true)): ?><th class="filter col-owner-org" data-beta-column="owner_org"><?= $this->Paginator->sort('Org.name', __('Owner org')) ?></th><?php endif; ?>
        <?php if (in_array('clusters', $columns, true)): ?><th class="col-clusters" data-beta-column="clusters"><?= __('Clusters') ?></th><?php endif; ?>
        <?php if (in_array('tags', $columns, true)): ?><th class="col-tags" data-beta-column="tags"><?= __('Tags') ?></th><?php endif; ?>
        <?php if (in_array('highlights', $columns, true)): ?><th class="col-highlights" data-beta-column="highlights"><?= __('Highlight tags') ?></th><?php endif; ?>
        <?php if (in_array('attribute_count', $columns, true)): ?><th class="col-attr-count" data-beta-column="attribute_count" title="<?= __('Attribute Count') ?>"><?= $this->Paginator->sort('attribute_count', __('#Attr.')) ?></th><?php endif; ?>
        <?php if (in_array('correlations', $columns, true)): ?><th class="col-corr-count" data-beta-column="correlations" title="<?= __('Correlation Count')  ?>"><?= __('#Corr.') ?></th><?php endif; ?>
        <?php if (in_array('report_count', $columns, true)): ?><th class="col-report-count" data-beta-column="report_count" title="<?= __('Report Count') ?>"><?= $this->Paginator->sort('report_count', __('#Reports')) ?></th><?php endif; ?>
        <?php if (in_array('sightings', $columns, true)): ?><th class="col-sightings-count" data-beta-column="sightings" title="<?= __('Sighting Count')?>"><?= __('#Sightings') ?></th><?php endif; ?>
        <?php if (in_array('proposals', $columns, true)): ?><th class="col-prop-count" data-beta-column="proposals" title="<?= __('Proposal Count') ?>"><?= __('#Prop') ?></th><?php endif; ?>
        <?php if (in_array('discussion', $columns, true)): ?><th class="col-post-count" data-beta-column="discussion" title="<?= __('Post Count') ?>"><?= __('#Posts') ?></th><?php endif; ?>
        <?php if (in_array('creator_user', $columns, true)): ?><th class="col-creator-user" data-beta-column="creator_user"><?= $this->Paginator->sort('user_id', __('Creator user')) ?></th><?php endif; ?>
        <th class="filter col-date"><?= $this->Paginator->sort('date', null, array('direction' => 'desc'));?></th>
        <?php if (in_array('timestamp', $columns, true)): ?><th class="col-timestamp" data-beta-column="timestamp" title="<?= __('Last mod') ?>"><?= $this->Paginator->sort('timestamp', __('Last mod')) ?></th><?php endif; ?>
        <?php if (in_array('publish_timestamp', $columns, true)): ?><th class="col-publish-timestamp" data-beta-column="publish_timestamp" title="<?= __('Pub time') ?>"><?= $this->Paginator->sort('publish_timestamp', __('Pub time')) ?></th><?php endif; ?>
    </tr>
    <?php foreach ($events as $event):
        $eventId = (int)$event['Event']['id'];
        $eventDateTimestamp = !empty($event['Event']['date']) ? strtotime($event['Event']['date'] . ' 00:00:00') : null;
        $dateRecencyMeta = $buildRecencyMeta($eventDateTimestamp, __('Event date'), 'date');
        $updateRecencyMeta = $buildRecencyMeta($event['Event']['timestamp'] ?? null, __('MISP update'), 'timestamp');
    ?>
    <tr id="event_<?= $eventId ?>">
        <td style="width:10px" class="beta-checkbox-actions-cell">
            <div class="beta-checkbox-actions-wrapper">
                <input class="select" type="checkbox" data-id="<?= $eventId ?>" data-can-modify="<?= $this->Acl->canModifyEvent($event) ? 1 : 0 ?>">
                <div class="btn-group beta-actions-dropdown">
                    <a class="beta-dropdown-toggle" data-toggle="dropdown" href="#" title="<?= __('Actions') ?>" aria-label="<?= __('Actions') ?>">
                        <i class="fa fa-chevron-down"></i>
                    </a>
                    <ul class="dropdown-menu beta-actions-menu" role="menu">
                        <li><a href="<?= $baseurl."/events/view/".$eventId ?>" title="<?= __('View') ?>"><i class="fa fa-eye"></i> <?= __('View') ?></a></li>
                        <?php if ($this->Acl->canModifyEvent($event)): ?>
                            <li><a href="<?= $baseurl."/events/edit/".$eventId ?>" title="<?= __('Edit') ?>"><i class="fa fa-edit"></i> <?= __('Edit') ?></a></li>
                            <li><a href="#" class="beta-delete-action" onclick="event.preventDefault();deleteEventPopup(<?= $eventId ?>)" title="<?= __('Delete') ?>"><i class="fa fa-trash"></i> <?= __('Delete') ?></a></li>
                        <?php endif; ?>
                        <li class="divider"></li>
                        <li><a href="#" onclick="event.preventDefault();return copyEventIndexUuid(this, '<?= h($event['Event']['uuid']) ?>');" title="<?= __('Copy UUID') ?>"><i class="fa fa-copy"></i> <?= __('Copy UUID') ?></a></li>
                        <?php if ($this->Acl->canAccess('collectionElements', 'addElementToCollection')): ?>
                            <li><a href="#" onclick="event.preventDefault();openAddToCollectionModal('<?= h($event['Event']['uuid']) ?>', <?= $eventId ?>)" title="<?= __('Add to Collection') ?>"><i class="fa fa-folder-plus"></i> <?= __('Add to Collection') ?></a></li>
                        <?php endif; ?>
                        <?php if (0 == $event['Event']['published'] && $this->Acl->canPublishEvent($event)): ?>
                            <li class="divider"></li>
                            <li><a href="#" class="beta-publish-action" onclick="event.preventDefault();publishPopup(<?= $eventId ?>)" title="<?= __('Publish Event') ?>"><i class="fa fa-upload"></i> <?= __('Publish Event') ?></a></li>
                        <?php endif; ?>
                    </ul>
                </div>
            </div>
        </td>
        <!-- BETA: Column 1 - ID -->
        <td class="short">
            <span><a href="<?= $baseurl."/events/view/".$eventId ?>" class="dblclickActionElement threat-level-<?= strtolower(h($event['ThreatLevel']['name'])) ?>" title="<?= h($event['Event']['info']) ?>"><?= $eventId ?></a> <?= !empty($event['Event']['protected']) ? sprintf('<i class="fas fa-lock" title="%s"></i>', __('Protected event')) : ''?></span>
        </td>
        <!-- BETA: Column 2 - Info -->
        <?php
            $extends_uuid = $event['Event']['extends_uuid'] ?? null;
            $extendedEventsInfoByUuid = array_column($extendedEvents, 'info', 'uuid');
            $extendedEventsIdByUuid = array_column($extendedEvents, 'id', 'uuid');
            $extends_info = $extendedEventsInfoByUuid[$extends_uuid] ?? null;
        ?>
        <td class="dblclickElement beta-info-cell<?= $extends_info && in_array('is_extension', $columns, true) ? ' col-is-extension' : '' ?>"<?= $extends_info && in_array('is_extension', $columns, true) ? ' data-beta-column="is_extension"' : '' ?>>
            <div class="beta-info-wrapper">
                <div class="dist-widget dist-<?= intval($event['Event']['distribution']) ?> distributionNetworkToggle"
                     title="<?= $event['Event']['distribution'] == 4 ? h($event['SharingGroup']['name']) : h($distributionLevels[$event['Event']['distribution']]) ?>"
                     data-event-distribution="<?= intval($event['Event']['distribution']) ?>"
                     data-event-distribution-name="<?= $event['Event']['distribution'] == 4 ? h($event['SharingGroup']['name']) : h($shortDist[$event['Event']['distribution']]) ?>"
                     data-scope-id="<?= $eventId ?>">
                    <i class="fa fa-share-alt" aria-hidden="true"></i>
                </div>
                <div class="beta-info-content">
                    <div class="beta-info-title-row">
                        <a href="<?= $baseurl."/events/view/".$eventId ?>" class="beta-info-link" title="<?= h($event['Event']['info']) ?>">
                            <?= nl2br(h($event['Event']['info']), false) ?>
                        </a>
                        <?php if (!empty($event['Event']['report_count'])): ?>
                            <a href="<?= "$baseurl/events/view/$eventId#summary-reports-section" ?>" title="<?= __n('1 report available', '%s reports available', $event['Event']['report_count'], $event['Event']['report_count']) ?>">
                                <i class="fas fa-file-alt" style="margin-left: 5px; color: #428bca;"></i>
                            </a>
                        <?php endif; ?>
                    </div>

                    <div class="beta-event-date-stack">
                        <time class="beta-event-date-label" datetime="<?= h($event['Event']['date']) ?>"><?= h($event['Event']['date']) ?></time>
                        <?php
                            $freshnessAriaLabel = __('Event date: %s. Last update: %s.', $dateRecencyMeta['title'], $updateRecencyMeta['title']);
                            $buildPopoverScale = function ($recencyMeta) {
                                $segments = '';
                                for ($segment = 1; $segment <= 6; $segment++) {
                                    $segments .= '<span class="beta-event-freshness-segment"></span>';
                                }
                                return '<span class="beta-freshness-popover-scale beta-event-freshness-scale ' . h($recencyMeta['class']) . '"><span class="beta-event-freshness-rail">' . $segments . '</span></span>';
                            };
                            $freshnessPopover = sprintf(
                                '<div class="beta-freshness-popover"><div class="beta-freshness-popover-row">%s<div class="beta-freshness-popover-meta"><span class="beta-freshness-popover-label">%s</span><div class="beta-freshness-popover-copy">%s</div></div></div><div class="beta-freshness-popover-row">%s<div class="beta-freshness-popover-meta"><span class="beta-freshness-popover-label">%s</span><div class="beta-freshness-popover-copy">%s</div></div></div></div>',
                                $buildPopoverScale($dateRecencyMeta),
                                h(__('Event date')),
                                h($dateRecencyMeta['title']),
                                $buildPopoverScale($updateRecencyMeta),
                                h(__('MISP last update')),
                                h($updateRecencyMeta['title'])
                            );
                        ?>
                        <span class="beta-event-freshness-pair" data-original-title="<?= h(__('Event freshness')) ?>" aria-label="<?= h($freshnessAriaLabel) ?>" data-toggle="popover" data-trigger="hover focus" data-placement="top" data-html="true" data-container="body" data-content="<?= h($freshnessPopover) ?>" data-title="<?= h(__('Event freshness')) ?>">
                            <i class="fa fa-seedling beta-event-freshness-icon" aria-hidden="true"></i>
                            <span class="beta-event-freshness-grid" aria-hidden="true">
                            <span class="beta-event-recency-row">
                                <span class="beta-event-freshness-scale <?= h($dateRecencyMeta['class']) ?>">
                                    <span class="beta-event-freshness-rail" aria-hidden="true">
                                        <?php for ($segment = 1; $segment <= 6; $segment++): ?>
                                            <span class="beta-event-freshness-segment<?= $segment <= (int)$dateRecencyMeta['filled'] ? ' is-filled' : '' ?>"></span>
                                        <?php endfor; ?>
                                    </span>
                                </span>
                            </span>
                            <span class="beta-event-recency-row">
                                <span class="beta-event-freshness-scale <?= h($updateRecencyMeta['class']) ?>">
                                    <span class="beta-event-freshness-rail" aria-hidden="true">
                                        <?php for ($segment = 1; $segment <= 6; $segment++): ?>
                                            <span class="beta-event-freshness-segment<?= $segment <= (int)$updateRecencyMeta['filled'] ? ' is-filled' : '' ?>"></span>
                                        <?php endfor; ?>
                                    </span>
                                </span>
                            </span>
                            </span>
                        </span>
                    </div>

                    <div id="event-collections-container-<?= $eventId ?>" class="beta-index-event-collections" data-event-uuid="<?= h($event['Event']['uuid']) ?>" style="margin-top: 0.35em;">
                        <div class="beta-event-collections-placeholder"></div>
                    </div>
                </div>
            </div>

            <?php if ($extends_info): ?>
                <?php if (in_array('is_extension', $columns, true)): ?>
                    <div style="padding-left: 1em;">
                        <span class="apply_css_arrow">
                            <p style="display: inline;">
                                Extends 
                                <a href="<?= h($baseurl) ?>/events/view/<?= h($extends_id) ?>" 
                                title="<?= __('See extended event') ?>" 
                                aria-label="<?= __('See extended event') ?>">
                                    <?= h($extends_id)?>
                                </a>
                                : <?= h($extends_info) ?>
                            </p>
                        </span>
                    </div>
                <?php else: ?>
                    <a href="<?= h($baseurl) ?>/events/view/<?= h($extends_id) ?>" 
                    title="<?= __('Extends event %s', h($extends_id)) ?>"
                    aria-label="<?= __('Extends event %s', h($extends_id)) ?>">
                        <i class="fas fa-external-link-square-alt"></i>
                    </a>
                <?php endif; ?>
            <?php endif; ?>
        </td>
        <!-- BETA: Column 3 - Publish Status -->
        <td class="dblclickElement" style="width:30px">
            <a href="<?= "$baseurl/events/view/$eventId" ?>" title="<?= __('View') ?>" aria-label="<?= __('View') ?>">
                <i class="fa <?= $event['Event']['published'] ? 'fa-check green' : 'fa-times grey' ?>"></i>
            </a>
        </td>
        <?php if (Configure::read('MISP.showorg') || $isAdmin): ?>
        <td class="short col-creator-org" ondblclick="document.location.href ='<?php echo $baseurl . "/events/index/searchorg:" . $event['Orgc']['id'];?>'">
            <a href="<?= $baseurl ?>/organisations/view/<?= (int)$event['Orgc']['id'] ?>" class="beta-org-link" title="<?= h($event['Orgc']['name']) ?>">
                <img 
                    src="<?= $baseurl ?>/organisations/getOrgLogo/<?= h($event['Orgc']['id']) ?>.json"
                    title="<?= h($event['Org']['name']) ?>"
                    onError="this.onerror=null; this.outerHTML='';"
                    width=24
                    height=24
                >
                <span>
                    <?= h($event['Orgc']['name']) ?>
                </span>
            </a>
        </td>
        <?php endif;?>
        <?php if (in_array('owner_org', $columns, true) || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'))): ?>
        <td class="short col-owner-org" data-beta-column="owner_org" ondblclick="document.location.href ='<?php echo $baseurl . "/events/index/searchorg:" . $event['Org']['id'];?>'">
            <a href="<?= $baseurl ?>/organisations/view/<?= (int)$event['Org']['id'] ?>" class="beta-org-link" title="<?= h($event['Org']['name']) ?>">
                <img 
                    src="<?= $baseurl ?>/organisations/getOrgLogo/<?= h($event['Org']['id']) ?>.json"
                    title="<?= h($event['Org']['name']) ?>"
                    onError="this.onerror=null; this.outerHTML='';"
                    width=24
                    height=24
                >
                <span>
                    <?= h($event['Org']['name']) ?>
                </span>
            </a>
        </td>
        <?php endif; ?>
        <?php if (in_array('clusters', $columns, true)): ?>
        <td class="col-clusters" data-beta-column="clusters" title="<?= __('Galaxy clusters attached to this event') ?>">
            <?php
                $galaxyCards = [];
                if (!empty($event['Galaxy'])) {
                    foreach ($event['Galaxy'] as $galaxy) {
                        if (empty($galaxy['GalaxyCluster']) || empty($galaxy['name'])) {
                            continue;
                        }
                        $galaxyCards[] = $this->element('Events/View/galaxy_compact_beta', array(
                            'galaxyName' => $galaxy['name'],
                            'clusters' => $galaxy['GalaxyCluster'],
                            'baseurl' => $baseurl
                        ));
                    }
                } elseif (!empty($event['GalaxyCluster'])) {
                    $galaxies = array();
                    foreach ($event['GalaxyCluster'] as $galaxy_cluster) {
                        $galaxy_name = $galaxy_cluster['Galaxy']['name'];
                        if (!isset($galaxies[$galaxy_name])) {
                            $galaxies[$galaxy_name] = array();
                        }
                        $galaxies[$galaxy_name][] = $galaxy_cluster;
                    }
                    foreach ($galaxies as $galaxyName => $clusters) {
                        $galaxyCards[] = $this->element('Events/View/galaxy_compact_beta', array(
                            'galaxyName' => $galaxyName,
                            'clusters' => $clusters,
                            'baseurl' => $baseurl
                        ));
                    }
                }

                if (empty($galaxyCards)) {
                    $eventGalaxyTags = [];
                    if (!empty($event['EventTag'])) {
                        $eventGalaxyTags = array_filter($event['EventTag'], function ($tag) {
                            return !empty($tag['Tag']['is_galaxy']);
                        });
                    } elseif (!empty($event['Tag'])) {
                        $eventGalaxyTags = array_map(function ($tag) {
                            return [
                                'Tag' => $tag,
                                'local' => $tag['local'] ?? false,
                                'relationship_type' => $tag['relationship_type'] ?? false,
                            ];
                        }, array_filter($event['Tag'], function ($tag) {
                            return !empty($tag['is_galaxy']);
                        }));
                    }

                    if (!empty($eventGalaxyTags)) {
                        $galaxyCards = array_merge($galaxyCards, $buildGalaxyCardsFromTags($eventGalaxyTags));
                    }
                }

                if (!empty($galaxyCards)) {
                    echo '<div class="beta-galaxies-container" title="' . __('Galaxy clusters attached to this event') . '">';
                    foreach ($galaxyCards as $galaxyCard) {
                        echo $galaxyCard;
                    }
                    echo '</div>';
                }
            ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('tags', $columns, true)): ?>
        <td class="shortish col-tags" data-beta-column="tags">
            <?php
                $highlightedTags = $event['Event']['highlightedTags'] ?? [];
                $tags = $event['EventTag'];
                foreach ($tags as $k => $tag) {
                    if ($tag['Tag']['is_galaxy']) {
                        unset($tags[$k]);
                    }
                }

                if (!empty($highlightedTags)) {
                    $highlightedTagNames = [];
                    foreach ($highlightedTags as $highlightedTaxonomy) {
                        if (empty($highlightedTaxonomy['tags'])) {
                            continue;
                        }

                        foreach ($highlightedTaxonomy['tags'] as $highlightedTag) {
                            if (!empty($highlightedTag['Tag']['name'])) {
                                $highlightedTagNames[$highlightedTag['Tag']['name']] = true;
                            }
                        }
                    }
                    if (!empty($highlightedTagNames)) {
                        foreach ($tags as $k => $tag) {
                            $tagName = $tag['Tag']['name'] ?? null;
                            if ($tagName !== null && isset($highlightedTagNames[$tagName])) {
                                unset($tags[$k]);
                            }
                        }
                    }
                }

                $totalRegularTagCount = count($tags);
                $visibleTags = $buildVisibleTagFamilies($tags);

                $maxVisibleTags = 3;
                if (count($visibleTags) > $maxVisibleTags) {
                    $visibleTags = array_slice($visibleTags, 0, $maxVisibleTags);
                }
                $hiddenTagCount = max(0, $totalRegularTagCount - count($visibleTags));

            ?>
            <?php
                $tagElementOptions = [
                    'event' => $event,
                    'tagAccess' => false,
                    'localTagAccess' => false,
                    'missingTaxonomies' => false,
                    'columnised' => true,
                    'static_tags_only' => 1,
                    'tag_display_style' => Configure::check('MISP.full_tags_on_event_index') ? Configure::read('MISP.full_tags_on_event_index') : 1,
                    'highlightedTags' => $highlightedTags
                ];

                echo $this->element('ajaxTags', $tagElementOptions + ['tags' => $visibleTags]);
                if ($hiddenTagCount > 0) {
                    echo '<span class="beta-context-more-count" title="' . h(__n('%s additional tag', '%s additional tags', $hiddenTagCount, $hiddenTagCount)) . '">(+'. (int)$hiddenTagCount .')</span>';
                }
            ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('highlights', $columns, true)): ?>
        <td class="shortish col-highlights" data-beta-column="highlights">
            <?php
                // Display only highlighted tags using the standard rich_tag element
                $highlightedTags = $event['Event']['highlightedTags'] ?? [];
                if (!empty($highlightedTags)) {
                    foreach ($highlightedTags as $hTaxonomy) {
                        if (isset($hTaxonomy['tags'])) {
                            foreach ($hTaxonomy['tags'] as $hTag) {
                                echo $this->element('rich_tag', [
                                    'tag' => $hTag,
                                    'tagAccess' => false,
                                    'localTagAccess' => false,
                                    'searchUrl' => '/events/index/searchtag:',
                                    'scope' => 'event',
                                    'id' => $event['Event']['id'],
                                    'tag_display_style' => 1 // Use full tag style as requested
                                ]);
                            }
                        }
                    }
                }
            ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('attribute_count', $columns, true)): ?>
        <td class="dblclickElement col-attr-count" data-beta-column="attribute_count" style="width:30px">
            <?= $event['Event']['attribute_count']; ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('correlations', $columns, true)): ?>
        <td class="col-corr-count" data-beta-column="correlations" style="width:30px">
            <?php if (!empty($event['Event']['correlation_count'])): ?>
                <?= $this->element('Events/correlation_badge', [
                    'tag' => 'a',
                    'href' => "$baseurl/events/view/$eventId/correlation:1",
                    'count' => (int)$event['Event']['correlation_count'],
                    'title' => __n('%s correlation', '%s correlations', $event['Event']['correlation_count'], $event['Event']['correlation_count']),
                ]) ?>
            <?php endif; ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('report_count', $columns, true)): ?>
        <td class="bold col-report-count" data-beta-column="report_count" style="width:30px">
            <?= $event['Event']['report_count']; ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('sightings', $columns, true)): ?>
        <td class="bold col-sightings-count" data-beta-column="sightings" style="width:30px">
            <?php if (!empty($event['Event']['sightings_count'])): ?>
                <a href="<?= "$baseurl/events/view/$eventId/sighting:1" ?>" title="<?= __n("1 sighting. Show filtered event with sighting only.", "%s sightings. Show filtered event with sightings only.", $event['Event']['sightings_count'], intval($event['Event']['sightings_count'])) ?>">
                    <?= intval($event['Event']['sightings_count']) ?>
                </a>
            <?php endif; ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('proposals', $columns, true)): ?>
        <td class="bold dblclickElement col-prop-count" data-beta-column="proposals" style="width:30px" title="<?= __n('%s proposal', '%s proposals', $event['Event']['proposals_count'], $event['Event']['proposals_count']) ?>">
            <?= !empty($event['Event']['proposals_count']) ? intval($event['Event']['proposals_count']) : ''; ?>
        </td>
        <?php endif;?>
        <?php if (in_array('discussion', $columns, true)): ?>
        <td class="bold dblclickElement col-post-count" data-beta-column="discussion" style="width:30px">
            <?php
                if (!empty($event['Event']['post_count'])) {
                    $post_count = h($event['Event']['post_count']);
                    if (($date - $event['Event']['last_post']) < $day) {
                        $post_count .=  ' (<span class="red bold">' . __('NEW') . '</span>)';
                    }
                } else {
                    $post_count = '';
                }
            ?>
            <span style=" white-space: nowrap;"><?php echo $post_count?></span>
        </td>
        <?php endif;?>
        <?php if (in_array('creator_user', $columns, true)): ?>
        <td class="short dblclickElement col-creator-user" data-beta-column="creator_user">
            <?php echo h($event['User']['email']); ?>
        </td>
        <?php endif; ?>
        <td class="short dblclickElement col-date">
            <time><?= h($event['Event']['date']) ?></time>
        </td>
        <?php if (in_array('timestamp', $columns, true)): ?>
        <td class="short dblclickElement col-timestamp beta-relative-timestamp" data-beta-column="timestamp"
            data-timestamp="<?= h($event['Event']['timestamp']) ?>" 
            data-absolute="<?= h(date('Y-m-d H:i:s', $event['Event']['timestamp'])) ?>" 
            title="<?= h(date('Y-m-d H:i:s', $event['Event']['timestamp'])) ?> (click to copy)" 
            style="cursor: pointer;">
            <?= preg_replace('/\s+/', '<br>', $this->Time->time($event['Event']['timestamp'])) ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('publish_timestamp', $columns, true)): ?>
        <td class="short dblclickElement col-publish-timestamp beta-relative-timestamp" data-beta-column="publish_timestamp"
            <?php if (!empty($event['Event']['publish_timestamp'])): ?>
            data-timestamp="<?= h($event['Event']['publish_timestamp']) ?>" 
            data-absolute="<?= h(date('Y-m-d H:i:s', $event['Event']['publish_timestamp'])) ?>" 
            title="<?= h(date('Y-m-d H:i:s', $event['Event']['publish_timestamp'])) ?> (click to copy)" 
            style="cursor: pointer;"
            <?php endif; ?>
        >
            <?= !empty($event['Event']['publish_timestamp']) ? preg_replace('/\s+/', '<br>', $this->Time->time($event['Event']['publish_timestamp'])) : '' ?>
        </td>
        <?php endif; ?>
    </tr>
    <?php endforeach; ?>
</table>
<script>
    var lastSelected = false;

    function copyEventIndexUuid(linkElement, uuid) {
        var textArea = document.createElement('textarea');
        textArea.value = uuid;
        textArea.setAttribute('readonly', 'readonly');
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        textArea.setSelectionRange(0, textArea.value.length);

        var copied = false;
        try {
            copied = document.execCommand('copy');
        } catch (err) {
            copied = false;
        }

        document.body.removeChild(textArea);

        if (!copied && navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
            navigator.clipboard.writeText(uuid).then(function() {
                showMessage('success', 'UUID copied');
            }).catch(function() {
                showMessage('fail', 'Could not copy UUID');
            });
            return false;
        }

        showMessage(copied ? 'success' : 'fail', copied ? 'UUID copied' : 'Could not copy UUID');
        return false;
    }

    $(function() {
        // Prevent checkbox clicks from toggling the dropdown menu
        $('.beta-checkbox-actions-wrapper input.select').on('click', function(e) {
            e.stopPropagation();
        });

        $('.select').on('change', function() {
            listCheckboxesCheckedEventIndex();
        }).click(function(e) {
            if ($(this).is(':checked')) {
                if (e.shiftKey) {
                    selectAllInbetween(lastSelected, this);
                }
                lastSelected = this;
            }
        });

        $('.distributionNetworkToggle').each(function() {
            $(this).distributionNetwork({
                distributionData: <?= json_encode($this->DistributionGraph->getGraphData(-1), JSON_UNESCAPED_UNICODE); ?>,
            });
        });

        if (typeof popoverStartup === 'function') {
            popoverStartup();
        }

    });
</script>
