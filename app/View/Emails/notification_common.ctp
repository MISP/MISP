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
    'additional_taxonomy_event_list' => [
        'PAP' => 'PAP:'
    ],
];
$vars = array_merge($default_vars, $this->__vars);

$now = new DateTime();
$start_date = new DateTime('7 days ago');
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

foreach ($events as $event) {
    $unique_tag_per_event = [];
    $attribute_number += count($event['Attribute']);
    $object_number += count($event['Object']);
    $event_report_number += count($event['EventReport']);
    $proposal_number += count($event['ShadowAttribute']);


    foreach ($event['EventTag'] as $event_tag) {
        $tag = $event_tag['Tag'];

        if (!empty($unique_tag_per_event[$tag['name']])) {
            continue; // Only one instance of tag per event
        }
        $unique_tag_per_event[$tag['name']] = true;

        if (empty($all_tag_amount[$tag['name']])) {
            $all_tag_amount[$tag['name']] = 0;
            $tag_color_mapping[$tag['name']] = $tag['colour'];
        }
        $all_tag_amount[$tag['name']] += 1;

        if (!empty($tag['is_galaxy']) && substr($tag['name'], 0, strlen($mitre_galaxy_tag_prefix)) === $mitre_galaxy_tag_prefix) {
            $technique = substr($tag['name'], strlen($mitre_galaxy_tag_prefix), strlen($tag['name']) - strlen($mitre_galaxy_tag_prefix) - 1);
            $mitre_attack_techniques[$technique] = $event_tag;
        }
    }

    foreach ($event['Attribute'] as $attribute) {
        if (empty($attribute_types[$attribute['type']])) {
            $attribute_types[$attribute['type']] = 0;
        }
        $attribute_types[$attribute['type']] += 1;

        foreach ($attribute['AttributeTag'] as $attribute_tag) {
            $tag = $attribute_tag['Tag'];

            if (!empty($unique_tag_per_event[$tag['name']])) {
                continue; // Only one instance of tag per event
            }
            $unique_tag_per_event[$tag['name']] = true;

            if (empty($all_tag_amount[$tag['name']])) {
                $all_tag_amount[$tag['name']] = 0;
                $tag_color_mapping[$tag['name']] = $tag['colour'];
            }
            $all_tag_amount[$tag['name']] += 1;

            if (!empty($tag['is_galaxy']) && substr($tag['name'], 0, strlen($mitre_galaxy_tag_prefix)) === $mitre_galaxy_tag_prefix) {
                $technique = substr($tag['name'], strlen($mitre_galaxy_tag_prefix), strlen($tag['name']) - strlen($mitre_galaxy_tag_prefix) - 1);
                $mitre_attack_techniques[$technique] = $attribute_tag;
            }
        }
    }

    foreach ($event['Object'] as $object) {
        if (empty($object_types[$object['name']])) {
            $object_types[$object['name']] = 0;
        }
        $object_types[$object['name']] += 1;

        $attribute_number += count($object['Attribute']);
        foreach ($object['Attribute'] as $attribute) {
            if (empty($attribute_types[$attribute['type']])) {
                $attribute_types[$attribute['type']] = 0;
            }
            $attribute_types[$attribute['type']] += 1;

            foreach ($attribute['AttributeTag'] as $attribute_tag) {
                $tag = $attribute_tag['Tag'];

                if (!empty($unique_tag_per_event[$tag['name']])) {
                    continue; // Only one instance of tag per event
                }
                $unique_tag_per_event[$tag['name']] = true;

                if (empty($all_tag_amount[$tag['name']])) {
                    $all_tag_amount[$tag['name']] = 0;
                    $tag_color_mapping[$tag['name']] = $tag['colour'];
                }
                $all_tag_amount[$tag['name']] += 1;

                if (!empty($tag['is_galaxy']) && substr($tag['name'], 0, strlen($mitre_galaxy_tag_prefix)) === $mitre_galaxy_tag_prefix) {
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

$unique_tag_number = count(array_keys($all_tag_amount));

arsort($attribute_types);
arsort($object_types);
arsort($all_tag_amount);

array_splice($attribute_types, 10);
array_splice($object_types, 10);
array_splice($all_tag_amount, 10);
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
                        <td><?= h($period) ?></td>
                    </tr>
                    <tr>
                        <td><?= __('Summary for dates') ?></td>
                        <td>
                            <?=
                            sprintf('<strong>%s</strong> (Week %s) ➞ <strong>%s</strong> (Week %s)',
                                $start_date->format('M d, o'),
                                $start_date->format('W'),
                                $now->format('M d, o'),
                                $now->format('W'),
                                $start_date->format('M d, o')
                            )
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <td><?= __('Generation date') ?></td>
                        <td><?= date("c"); ?></td>
                    </tr>
                    <tr>
                        <td><?= __('Events #') ?></td>
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
                </tbody>
            </table>
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
                <?php if (!empty($mitre_attack_techniques)) : ?>
                    <h4><?= __('Mitre Att&ck techniques') ?></h4>
                    <ul>
                        <?php foreach ($mitre_attack_techniques as $technique => $tag) : ?>
                            <li>
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
                <?php if (!empty($attribute_types)) : ?>
                    <h4><?= __('Top 10 Attribute types') ?></h4>
                    <ul>
                        <?php foreach ($attribute_types as $type => $amount) : ?>
                            <li><strong><?= h($type) ?></strong>: <?= $amount ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>

                <?php if (!empty($object_types)) : ?>
                    <h4><?= __('Top 10 MISP Object names') ?></h4>
                    <ul>
                        <?php foreach ($object_types as $name => $amount) : ?>
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
                    <?php foreach ($all_tag_amount as $tag_name => $amount) : ?>
                        <li>
                            <span style="padding: 2px 9px; margin-right: 5px; border-radius: 9px; font-weight: bold; background-color: #999; color: #fff;">
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
                    <h4><?= __('Event list') ?></h4>
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
                                    <th><?= __('Decaying Base Score') ?></th>
                                <?php endif; ?>
                                <th><?= __('Event Info') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($events as $event) : ?>
                                <?php
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
                                            <?php if (isset($event['event_base_score'])) : ?>
                                                <table class="table-xcondensed no-border">
                                                    <?php foreach ($event['event_base_score'] as $bs) : ?>
                                                        <tr>
                                                            <td style="line-height: 14px;"><i class="no-overflow" style="max-width: 12em;" title="<?= h($bs['DecayingModel']['name']); ?>"><?= h($bs['DecayingModel']['name']); ?>:</i></td>
                                                            <td style="line-height: 14px;"><b style="color: <?= !empty($bs['decayed']) ? '#b94a48' : '#468847' ?>;"><?= round($bs['base_score'], 2) ?></b></td>
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
            <?php endif; ?>
        </div>
    </div>
    <?php endif; // detailed-summary-full 
    ?>

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

    <?= $this->fetch('content'); ?>

    <style>
        .mw-50 {
            max-width: 50%;
        }

        .panel {
            border: 1px solid #ccc;
            border-radius: 3px;
            margin-bottom: 20px;
            box-shadow: 0px 5px 10px 0 #00000033;
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
            text-shadow: 0px 0px #999;
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
            padding: 0px 2px !important;
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