<?php

/**
 * Available template block that can be overriden using $this->assign('table-overview', ' ');
 *  - `prepend-html`
 *  - `table-overview`
 *  - `detailed-summary-full`
 *  - `detailed-summary-mitre-attack`
 *  - `detailed-summary-type`
 *  - `detailed-summary-tags`
 *  - `detailed-summary-events`
 *  - `detailed-summary-correlations`
 *  - `aggregated-context`
 * 
 * Additional variables:
 *  - `event-table-include-basescore`: bool
 */

if (empty($this->__vars)) {
    $this->__vars = [];
}
$default_vars = [
    'event_table_include_basescore' => true,
    'event_table_max_event_count' => 30,
    'correlation_table_advanced_ui' => 10,
    'correlation_table_max_count' => 50,
    'additional_taxonomy_event_list' => [
        'PAP' => 'PAP:'
    ],
];
$vars = array_merge($default_vars, $this->__vars);

$now = new DateTime();
$start_date = new DateTime($period_days . ' days ago');
$event_number = count($events);
$attribute_number = 0;
$object_number = 0;
$event_report_number = 0;
$proposal_number = 0;

$attribute_types = [];
$object_types = [];
$all_event_report = [];

$all_tag_amount = [];
$unique_tag_number = 0;
$tag_color_mapping = [];

$mitre_attack_techniques = [];
$mitre_galaxy_tag_prefix = 'misp-galaxy:mitre-attack-pattern="';

$reportLink = sprintf('%s/users/viewPeriodicSummary/%s', $baseurl, $period);
$eventLink = sprintf('%s/events/index/searchpublished:1/searchPublishTimestamp:%s/searchPublishTimestamp:%s', $baseurl, h($start_date->format('Y-m-d H:i:s')), h($now->format('Y-m-d H:i:s')));

$newCorrelationExplanationText = implode('&#13;', [
    __('Correlations for the current set of Events are considered as `new` if their matching attribute has been modified during the chosen period.'),
    '',
    __('Example for a selected period of 7 days:'),
    __(' Events from the past 7 days           Any other Events'),
    __('• Attribute(  3 days ago)  →  Attribute(  1 days ago)  ✓'),
    __('• Attribute(  3 days ago)  →  Attribute(  9 days ago)  ✓'),
    __('• Attribute(12 days ago)  →  Attribute(  3 days ago)  ⨉'),
    __('• Attribute(  9 days ago)  →  Attribute(11 days ago)  ⨉'),
]);
$processed_correlations = [];
$new_correlations = [];
foreach ($events as $event) {
    $unique_tag_per_event = [];
    $attribute_number += count($event['Attribute']);
    $object_number += count($event['Object']);
    $event_report_number += count($event['EventReport']);
    $proposal_number += count($event['ShadowAttribute']);

    foreach ($event['EventTag'] as $event_tag) {
        $tag = $event_tag['Tag'];

        if (isset($unique_tag_per_event[$tag['name']])) {
            continue; // Only one instance of tag per event
        }
        $unique_tag_per_event[$tag['name']] = true;

        if (!isset($all_tag_amount[$tag['name']])) {
            $all_tag_amount[$tag['name']] = 1;
            $tag_color_mapping[$tag['name']] = $tag['colour'];
        } else {
            $all_tag_amount[$tag['name']]++;
        }

        if ($tag['is_galaxy'] && substr($tag['name'], 0, strlen($mitre_galaxy_tag_prefix)) === $mitre_galaxy_tag_prefix) {
            $technique = substr($tag['name'], strlen($mitre_galaxy_tag_prefix), strlen($tag['name']) - strlen($mitre_galaxy_tag_prefix) - 1);
            $mitre_attack_techniques[$technique] = $event_tag;
        }
    }

    $attribute_light_by_id = [];
    foreach ($event['Attribute'] as $attribute) {
        $attribute_light_by_id[$attribute['id']] = [
            'timestamp' => $attribute['timestamp'],
            'type' => $attribute['type'],
        ];
        if (empty($attribute_types[$attribute['type']])) {
            $attribute_types[$attribute['type']] = 0;
        }
        $attribute_types[$attribute['type']]++;

        foreach ($attribute['AttributeTag'] as $attribute_tag) {
            $tag = $attribute_tag['Tag'];

            if (isset($unique_tag_per_event[$tag['name']])) {
                continue; // Only one instance of tag per event
            }
            $unique_tag_per_event[$tag['name']] = true;

            if (!isset($all_tag_amount[$tag['name']])) {
                $all_tag_amount[$tag['name']] = 1;
                $tag_color_mapping[$tag['name']] = $tag['colour'];
            } else {
                $all_tag_amount[$tag['name']]++;
            }

            if ($tag['is_galaxy'] && substr($tag['name'], 0, strlen($mitre_galaxy_tag_prefix)) === $mitre_galaxy_tag_prefix) {
                $technique = substr($tag['name'], strlen($mitre_galaxy_tag_prefix), strlen($tag['name']) - strlen($mitre_galaxy_tag_prefix) - 1);
                $mitre_attack_techniques[$technique] = $attribute_tag;
            }
        }
    }

    foreach ($event['Object'] as $object) {
        if (empty($object_types[$object['name']])) {
            $object_types[$object['name']] = 0;
        }
        $object_types[$object['name']]++;

        $attribute_number += count($object['Attribute']);
        foreach ($object['Attribute'] as $attribute) {
            $attribute_light_by_id[$attribute['id']] = [
                'timestamp' => $attribute['timestamp'],
                'type' => $attribute['type'],
            ];
            if (empty($attribute_types[$attribute['type']])) {
                $attribute_types[$attribute['type']] = 0;
            }
            $attribute_types[$attribute['type']]++;

            foreach ($attribute['AttributeTag'] as $attribute_tag) {
                $tag = $attribute_tag['Tag'];

                if (isset($unique_tag_per_event[$tag['name']])) {
                    continue; // Only one instance of tag per event
                }
                $unique_tag_per_event[$tag['name']] = true;

                if (!isset($all_tag_amount[$tag['name']])) {
                    $all_tag_amount[$tag['name']] = 1;
                    $tag_color_mapping[$tag['name']] = $tag['colour'];
                } else {
                    $all_tag_amount[$tag['name']]++;
                }

                if ($tag['is_galaxy'] && substr($tag['name'], 0, strlen($mitre_galaxy_tag_prefix)) === $mitre_galaxy_tag_prefix) {
                    $technique = substr($tag['name'], strlen($mitre_galaxy_tag_prefix), strlen($tag['name']) - strlen($mitre_galaxy_tag_prefix) - 1);
                    $mitre_attack_techniques[$technique] = $attribute_tag;
                }
            }
        }
    }

    foreach ($event['EventReport'] as $event_report) {
        $all_event_report[] = [
            'uuid' => $event_report['uuid'],
            'name' => $event_report['name'],
            'event_id' => $event_report['event_id'],
            'event_info' => $event['Event']['info'],
        ];
    }

    if (!empty($event['RelatedEvent'])) {
        $related_event_by_id = [];
        foreach ($event['RelatedEvent'] as $related_event) {
            $related_event_by_id[$related_event['Event']['id']] = $related_event['Event'];
        }

        foreach ($event['RelatedAttribute'] as $attribute_id => $related_attributes) {
            $has_attribute_been_modified_since_last_period = intval($attribute_light_by_id[$attribute_id]['timestamp']) >= intval($start_date->format('U'));
            foreach ($related_attributes as $related_attribute) {
                $correlation_id = sprintf('%s-%s', $related_attribute['attribute_id'], $attribute_id);
                $reversed_correlation_id = sprintf('%s-%s', $attribute_id, $related_attribute['attribute_id']);
                $has_correlation_been_processed = isset($processed_correlations[$correlation_id]); // We already added the correlation the other way around
                if ($has_attribute_been_modified_since_last_period && !$has_correlation_been_processed) {
                    $source_event = $event['Event'];
                    $source_event['Orgc'] = $event['Orgc'];
                    $new_correlations[] = [
                        'source_event' => $source_event,
                        'target_event' => $related_event_by_id[$related_attribute['id']],
                        'attribute_value' => $related_attribute['value'],
                        'attribute_type' => $attribute_light_by_id[$attribute_id]['type'],
                    ];
                    $processed_correlations[$reversed_correlation_id] = true;
                }
            }
        }
    }
}

if (!function_exists('findAndBuildTag')) {
    function findAndBuildTag($tag_list, $tag_prefix, $that)
    {
        foreach ($tag_list as $tag) {
            if (substr($tag['Tag']['name'], 0, strlen($tag_prefix)) == $tag_prefix) {
                return $that->element('tag', ['tag' => $tag]);
            }
        }
        return '';
    }
}

$unique_tag_number = count($all_tag_amount);

arsort($attribute_types);
arsort($object_types);
arsort($all_tag_amount);
uasort($mitre_attack_techniques, function ($tag1, $tag2) use ($all_tag_amount) {
    return ($all_tag_amount[$tag1['Tag']['name']] < $all_tag_amount[$tag2['Tag']['name']]) ? 1 : -1;
});

$top_attribute_types = array_slice($attribute_types, 0, 10);
$top_object_types = array_slice($object_types, 0, 10);
$top_all_tag_amount = array_slice($all_tag_amount, 0, 10);
$top_mitre_attack_techniques = array_slice($mitre_attack_techniques, 0, 10);
?>

<?php if ($this->fetch('prepend-html')) : ?>
    <?= $this->fetch('prepend-html') ?>
<?php endif; ?>

<?php if ($this->fetch('table-overview')) : ?>
    <?= $this->fetch('table-overview'); ?>
<?php else : ?>
    <div class="panel">
        <div class="panel-header">
            <?= __('Data at a glance') ?>
        </div>
        <div class="panel-body">
            <table class="table table-condensed mw-50">
                <tbody>
                    <tr>
                        <td><?= __('Summary period') ?></td>
                        <td><?= h(ucfirst($period)) ?></td>
                    </tr>
                    <tr>
                        <td><?= __('Summary for dates') ?></td>
                        <td>
                            <?= __(
                                '<strong>%s</strong> (Week %s) ➞ <strong>%s</strong> (Week %s)',
                                $start_date->format('M d, o'),
                                $start_date->format('W'),
                                $now->format('M d, o'),
                                $now->format('W')
                            )
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <td><?= __('Generation date') ?></td>
                        <td><?= date("c"); ?></td>
                    </tr>
                    <tr>
                        <td><?= __('Published Events #') ?></td>
                        <td><?= $event_number ?></td>
                    </tr>
                    <tr>
                        <td><?= __('Attributes #') ?></td>
                        <td><?= $attribute_number ?></td>
                    </tr>
                    <tr>
                        <td><?= __('Objects #') ?></td>
                        <td><?= $object_number ?></td>
                    </tr>
                    <tr>
                        <td><?= __('Event Report #') ?></td>
                        <td><?= $event_report_number ?></td>
                    </tr>
                    <tr>
                        <td><?= __('Proposals #') ?></td>
                        <td><?= $proposal_number ?></td>
                    </tr>
                    <tr>
                        <td><?= __('Unique tags #') ?></td>
                        <td><?= $unique_tag_number ?></td>
                    </tr>
                    <?php if (!empty($periodicSettings['include_correlations'])) : ?>
                        <tr>
                            <td><?= __('New correlation #') ?></td>
                            <td><?= count($new_correlations) ?></td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
            ⮞ <a href="<?= h($reportLink) ?>"><?= __('View this report in MISP') ?></a>
        </div>
    </div>
<?php endif; ?>

<?php if ($this->fetch('detailed-summary-full')) : ?>
    <?= $this->fetch('detailed-summary-full'); ?>
<?php else : ?>
    <div class="panel">
        <div class="panel-header">
            <?= __('Detailed summary') ?>
        </div>
        <div class="panel-body">
            <?php if ($this->fetch('detailed-summary-mitre-attack')) : ?>
                <?= $this->fetch('detailed-summary-mitre-attack'); ?>
            <?php else : ?>
                <?php if (!empty($top_mitre_attack_techniques)) : ?>
                    <h4><?= __('Top 10 MITRE ATT&CK techniques') ?></h4>
                    <ul>
                        <?php foreach ($top_mitre_attack_techniques as $technique => $tag) : ?>
                            <li>
                                <span class="tag" style="background-color: #999; color: #fff; border-radius: 9px; padding: 2px 8px;">
                                    <?= $all_tag_amount[$tag['Tag']['name']] ?>
                                </span>
                                <?php
                                $tag['Tag']['name'] = $technique;
                                echo $this->element('tag', ['tag' => $tag])
                                ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($this->fetch('detailed-summary-type')) : ?>
                <?= $this->fetch('detailed-summary-type'); ?>
            <?php else : ?>
                <?php if (!empty($top_attribute_types)) : ?>
                    <h4><?= __('Top 10 Attribute types') ?></h4>
                    <ul>
                        <?php foreach ($top_attribute_types as $type => $amount) : ?>
                            <li><strong><?= h($type) ?></strong>: <?= $amount ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>

                <?php if (!empty($top_object_types)) : ?>
                    <h4><?= __('Top 10 MISP Object names') ?></h4>
                    <ul>
                        <?php foreach ($top_object_types as $name => $amount) : ?>
                            <li><strong><?= h($name) ?></strong>: <?= $amount ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>

                <?php if (!empty($all_event_report)) : ?>
                    <h4><?= __('All Event Reports') ?></h4>
                    <ul>
                        <?php foreach ($all_event_report as $report) : ?>
                            <li>
                                <a href="<?= sprintf('%s/eventReports/view/%s', $baseurl, h($report['uuid'])) ?>">
                                    <?= sprintf('%s :: %s', h($report['event_info']), h($report['name'])); ?>
                                </a>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($this->fetch('detailed-summary-tags')) : ?>
                <?= $this->fetch('detailed-summary-tags'); ?>
            <?php else : ?>
                <h4><?= __('Top 10 Tags') ?></h4>
                <ul>
                    <?php foreach ($top_all_tag_amount as $tag_name => $amount) : ?>
                        <li>
                            <span class="tag" style="background-color: #999; color: #fff; border-radius: 9px; padding: 2px 8px;">
                                <?= $amount ?>
                            </span>
                            <?= $this->element('tag', ['tag' => ['Tag' => ['name' => $tag_name, 'colour' => $tag_color_mapping[$tag_name]]]]) ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>

            <?php if ($this->fetch('detailed-summary-events')) : ?>
                <?= $this->fetch('detailed-summary-events'); ?>
            <?php else : ?>
                <?php if (!empty($events)) : ?>
                    <h4><?= __('Event list') ?> <small style="color: #999999;"><?= sprintf(' (%s)', count($events)) ?></small></h4>
                    <table class="table table-condensed">
                        <thead>
                            <tr>
                                <th><?= __('Publish date') ?></th>
                                <th><?= __('Creator Org.') ?></th>
                                <th><?= __('Distribution') ?></th>
                                <th><?= __('State') ?></th>
                                <th><?= __('Threat Level') ?></th>
                                <?php foreach ($vars['additional_taxonomy_event_list'] as $taxonomy_name => $taxonomy_prefix) : ?>
                                    <th><?= h($taxonomy_name) ?></th>
                                <?php endforeach; ?>
                                <?php if (!empty($vars['event_table_include_basescore'])) : ?>
                                    <th><?= __('Decaying Event Score') ?></th>
                                <?php endif; ?>
                                <th><?= __('Event Info') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($events as $i => $event) : ?>
                                <?php
                                if ($i > $vars['event_table_max_event_count'] - 1) {
                                    break;
                                }
                                $workflowTag = findAndBuildTag($event['EventTag'], 'workflow:', $this);
                                $analysisHtml = !empty($workflowTag) ? $workflowTag : '';
                                $tlpTag = findAndBuildTag($event['EventTag'], 'tlp:', $this);
                                $tlpHtml = !empty($tlpTag) ? $tlpTag : '';
                                ?>
                                <tr>
                                    <td><?= DateTime::createFromFormat('U', h($event['Event']['publish_timestamp']))->format('Y-m-d') ?></td>
                                    <td><?= h($event['Orgc']['name']) ?></td>
                                    <td>
                                        <<?= !empty($tlpHtml) ? 'small' : 'span' ?>><?= h($distributionLevels[$event['Event']['distribution']]) ?></<?= !empty($tlpHtml) ? 'small' : 'span' ?>>
                                        <span style="margin-left: 3px;"><?= $tlpHtml ?></span>
                                    </td>
                                    <td>
                                        <<?= !empty($analysisHtml) ? 'small' : 'span' ?>><?= h($analysisLevels[$event['Event']['analysis']]) ?></<?= !empty($analysisHtml) ? 'small' : 'span' ?>>
                                        <span style="margin-left: 3px;"><?= $analysisHtml ?></span>
                                    </td>
                                    <td><?= h($event['ThreatLevel']['name']); ?></td>
                                    <?php foreach ($vars['additional_taxonomy_event_list'] as $taxonomy_name => $taxonomy_prefix) : ?>
                                        <td><?= findAndBuildTag($event['EventTag'], $taxonomy_prefix, $this) ?></td>
                                    <?php endforeach; ?>
                                    <?php if (!empty($vars['event_table_include_basescore'])) : ?>
                                        <td>
                                            <?php if (isset($event['event_scores'])) : ?>
                                                <table class="table-xcondensed no-border">
                                                    <?php foreach ($event['event_scores'] as $score) : ?>
                                                        <tr>
                                                            <td style="line-height: 14px;"><i class="no-overflow" style="max-width: 12em;" title="<?= h($score['DecayingModel']['name']); ?>"><?= h($score['DecayingModel']['name']); ?>:</i></td>
                                                            <td style="line-height: 14px;"><b style="color: <?= !empty($score['decayed']) ? '#b94a48' : '#468847' ?>;"><?= round($score['score'], 2) ?></b></td>
                                                        </tr>
                                                    <?php endforeach; ?>
                                                </table>
                                            <?php else : ?>
                                                &nbsp;
                                            <?php endif; ?>
                                        </td>
                                    <?php endif; ?>
                                    <td><a href="<?= sprintf('%s/events/view/%s', $baseurl, h($event['Event']['uuid'])) ?>"><?= h($event['Event']['info']) ?></a></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else : ?>
                    <p><?= __('No events.') ?></p>
                <?php endif; ?>
                <?php if (count($events) > $vars['event_table_max_event_count']) : ?>
                    ⮞ <?=
                        __n(
                            '%s event not displayed.',
                            '%s events not displayed.',
                            count($events) - $vars['event_table_max_event_count'],
                            sprintf('<strong>%s</strong>', count($events) - $vars['event_table_max_event_count'])
                        )
                        ?>
                    <a href="<?= h($eventLink) ?>"><?= __('View all events in MISP') ?></a>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($this->fetch('detailed-summary-correlations')) : ?>
            <?php else : ?>
                <?php if (!empty($new_correlations)) : ?>
                    <h4>
                        <?= __('New correlations for event list') ?>
                        <i class="fas fa-question-circle" title="<?= $newCorrelationExplanationText ?>"></i>
                        <small style="color: #999999;"><?= sprintf(' (%s)', count($new_correlations)) ?></small>
                    </h4>
                    <div>
                        <?php if (count($new_correlations) < $vars['correlation_table_advanced_ui']) : ?>
                            <?php foreach ($new_correlations as $correlation) : ?>
                                <div style="display: flex; flex-wrap: nowrap; align-items: center; margin-top: 0.5em;">
                                    <span>
                                        <span class="correlating-event-container">
                                            <span>
                                                <a href="<?= sprintf('%s/events/view/%s', $baseurl, h($correlation['source_event']['id'])) ?>"><?= h($correlation['source_event']['info']) ?></a>
                                            </span>
                                            <span class="org-date">
                                                <span><?= h($correlation['source_event']['date']) ?></span>
                                                <span><?= h($correlation['source_event']['Orgc']['name']) ?></span>
                                            </span>
                                        </span>
                                    </span>
                                    <span class="correlating-attribute-container">
                                        <span class="correlating-attribute">
                                            <?= h($correlation['attribute_type']); ?> :: <b><?= h($correlation['attribute_value']) ?></b>
                                        </span>
                                    </span>
                                    <span>
                                        <span class="correlating-event-container">
                                            <span>
                                                <a href="<?= sprintf('%s/events/view/%s', $baseurl, h($correlation['target_event']['id'])) ?>"><?= h($correlation['target_event']['info']) ?></a>
                                            </span>
                                            <span class="org-date">
                                                <span><?= h($correlation['target_event']['date']) ?></span>
                                                <span><?= h($correlation['target_event']['Orgc']['name']) ?></span>
                                            </span>
                                        </span>
                                    </span>
                                </div>
                            <?php endforeach; ?>
                        <?php else : ?>
                            <table class="table table-xcondensed">
                                <thead>
                                    <tr>
                                        <th><?= __('First event info') ?></th>
                                        <th><?= __('Value') ?></th>
                                        <th><?= __('Second event info') ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach (array_slice($new_correlations, 0, $vars['correlation_table_max_count']) as $correlation) : ?>
                                        <tr>
                                            <td><a href="<?= sprintf('%s/events/view/%s', $baseurl, h($correlation['source_event']['id'])) ?>"><?= h($correlation['source_event']['info']) ?></a></td>
                                            <td><b><?= h($correlation['attribute_value']) ?></b></td>
                                            <td><a href="<?= sprintf('%s/events/view/%s', $baseurl, h($correlation['target_event']['id'])) ?>"><?= h($correlation['target_event']['info']) ?></a></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                            <?php
                            if (count($new_correlations) > $vars['correlation_table_max_count']) {
                                echo '⮞ ' . __n(
                                    '%s correlation not displayed.',
                                    '%s correlations not displayed.',
                                    count($new_correlations) - $vars['correlation_table_max_count'],
                                    sprintf('<strong>%s</strong>', count($new_correlations) - $vars['correlation_table_max_count'])
                                );
                            }
                            ?>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>

<?php if ($this->fetch('trending-summary')) : ?>
    <?= $this->fetch('trending-summary'); ?>
<?php else : ?>
    <div class="panel">
        <div class="panel-header">
            <?= __('Tag trendings') ?>
        </div>
        <div class="panel-body">
            <?= $trending_summary; ?>
        </div>
    </div>
<?php endif; ?>

<?php if ($this->fetch('aggregated-context')) : ?>
    <?= $this->fetch('aggregated-context'); ?>
<?php else : ?>
    <div class="panel">
        <div class="panel-header">
            <?= __('Context summary') ?>
        </div>
        <div class="panel-body">
            <?= $aggregated_context; ?>
        </div>
    </div>
<?php endif; ?>

<?php if ($this->fetch('security-recommendations')) : ?>
    <?= $this->fetch('security-recommendations'); ?>
<?php else : ?>
    <div class="panel">
        <div class="panel-header">
            <?= __('Security Recommendations') ?>
        </div>
        <div class="panel-body">
            <?= $security_recommendations; ?>
        </div>
    </div>
<?php endif; ?>

<?= $this->fetch('content'); ?>

<style>
    .mw-50 {
        max-width: 50%;
    }

    .panel {
        border: 1px solid #ccc;
        border-radius: 3px;
        margin-bottom: 20px;
        box-shadow: 0 5px 10px 0 #00000033;
    }

    .panel-header {
        border-bottom: 1px solid #ccc;
        padding: 4px 10px;
        background-color: #cccccc22;
        font-weight: bold;
        font-size: 25px;
        clear: both;
        line-height: 40px;
    }

    .panel-body {
        padding: 15px;
        position: relative;
    }

    .panel h4 {
        margin-top: 0.75em;
    }

    .panel h4::before {
        content: '▲';
        transform: rotate(90deg);
        display: inline-block;
        margin-right: 0.25em;
        color: #ccc;
        text-shadow: 0 0 #999;
    }

    .tag {
        display: inline-block;
        padding: 2px 4px;
        font-size: 12px;
        font-weight: bold;
        line-height: 14px;
        margin-right: 2px;
        border-radius: 3px;
    }

    .correlating-attribute {
        padding: 3px 5px;
        border: 1px solid #ccc;
        border-radius: 3px;
        white-space: nowrap;
    }

    .correlating-attribute-container {
        display: flex;
        box-sizing: border-box;
        margin: 0 0;
        align-items: center;
        min-width: 400px;
    }

    .correlating-attribute-container::before,
    .correlating-attribute-container::after {
        display: inline-block;
        content: ' ';
        height: 2px;
        width: 100%;
        background-color: #ccc;
    }

    .correlating-event-container {
        display: flex;
        flex-direction: column;
        min-width: 180px;
        border: 1px solid #ccc;
        border-radius: 3px;
        padding: 3px 5px;
    }

    .correlating-event-container>.org-date {
        display: flex;
        justify-content: space-between;
    }

    .no-overflow {
        display: inline-block;
        white-space: nowrap;
        text-overflow: ellipsis;
        overflow: hidden
    }

    .table {
        width: 100%;
        margin-bottom: 20px;
    }

    .table.table-condensed td,
    .table.table-condensed th {
        padding: 4px 5px;
    }

    .table-xcondensed td,
    .table-xcondensed th {
        padding: 0 2px !important;
    }

    .table th,
    .table td {
        padding: 8px;
        line-height: 20px;
        text-align: left;
        vertical-align: top;
        border-top: 1px solid #dddddd;
    }

    .table thead th {
        vertical-align: bottom;
    }

    .table caption+thead tr:first-child th,
    .table caption+thead tr:first-child td,
    .table colgroup+thead tr:first-child th,
    .table colgroup+thead tr:first-child td,
    .table thead:first-child tr:first-child th,
    .table thead:first-child tr:first-child td {
        border-top: 0;
    }

    table.no-border td {
        border-top: 0;
    }

    .table.no-border tbody+tbody {
        border-top: 0;
    }
</style>