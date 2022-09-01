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
 */

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
$additional_taxonomy_event_list = [
    'PAP' => 'PAP:',
];

foreach ($events as $event) {
    $attribute_number += count($event['Attribute']);
    $object_number += count($event['Object']);
    $event_report_number += count($event['EventReport']);
    $proposal_number += count($event['ShadowAttribute']);


    foreach ($event['EventTag'] as $event_tag) {
        $tag = $event_tag['Tag'];
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
    function findAndBuildTag($tag_list, $tag_prefix, $that) {
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

<h2><?= !empty($filters['published']) ? __('Summary of published Events') : __('Summary of Events') ?></h2>
<?php if ($this->fetch('prepend-html')): ?>
    <?= $this->fetch('prepend-html') ?>
<?php endif; ?>

<?php if ($this->fetch('table-overview')): ?>
    <?= $this->fetch('table-overview'); ?>
<?php else: ?>
    <table class="table table-condensed" style="max-width: 500px;">
        <tbody>
            <tr>
                <td><?= __('Summary period') ?></td>
                <td><?= h($period) ?></td>
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
<?php endif; ?>
<br>

<?php if ($this->fetch('detailed-summary-full')): ?>
    <?= $this->fetch('detailed-summary-full'); ?>
<?php else: ?>
    <h2><?= __('Detailed summary') ?></h2>
    <?php if ($this->fetch('detailed-summary-mitre-attack')): ?>
        <?= $this->fetch('detailed-summary-mitre-attack'); ?>
    <?php else: ?>
        <?php if (!empty($mitre_attack_techniques)): ?>
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

    <?php if ($this->fetch('detailed-summary-type')): ?>
        <?= $this->fetch('detailed-summary-type'); ?>
    <?php else: ?>
        <?php if (!empty($attribute_types)): ?>
            <h4><?= __('Top 10 Attribute types') ?></h4>
            <ul>
            <?php foreach ($attribute_types as $type => $amount) : ?>
                <li><strong><?= h($type) ?></strong>: <?= $amount ?></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <?php if (!empty($object_types)): ?>
            <h4><?= __('Top 10 MISP Object names') ?></h4>
            <ul>
            <?php foreach ($object_types as $name => $amount) : ?>
                <li><strong><?= h($name) ?></strong>: <?= $amount ?></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <?php if (!empty($all_event_report)): ?>
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

    <?php if ($this->fetch('detailed-summary-tags')): ?>
        <?= $this->fetch('detailed-summary-tags'); ?>
    <?php else: ?>
        <h4><?= __('Top 10 Tags') ?></h4>
        <ul>
        <?php foreach ($all_tag_amount as $tag_name => $amount) : ?>
            <li>
                <?= $this->element('tag', ['tag' => ['Tag' => ['name' => $tag_name, 'colour' => $tag_color_mapping[$tag_name]]]]) ?>
                <?= $amount ?>
            </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>

    <?php if ($this->fetch('detailed-summary-events')): ?>
        <?= $this->fetch('detailed-summary-events'); ?>
    <?php else: ?>
        <?php if (!empty($events)): ?>
            <h3><?= __('Event list') ?></h3>
            <table>
                <thead>
                    <tr>
                        <th style="padding: 0 0.5em;">Creator Org.</th>
                        <th style="padding: 0 0.5em;">TLP</th>
                        <th style="padding: 0 0.5em;"><?= __('State') ?></th>
                        <th style="padding: 0 0.5em;"><?= __('Threat Level') ?></th>
                        <?php foreach ($additional_taxonomy_event_list as $taxonomy_name => $taxonomy_prefix): ?>
                            <th style="padding: 0 0.5em;"><?= h($taxonomy_name) ?></th>
                        <?php endforeach; ?>
                        <th style="padding: 0 0.5em;"><?= __('Event Info') ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($events as $event) : ?>
                        <?php
                            $workflowTag = findAndBuildTag($event['EventTag'], 'workflow:', $this);
                            $analysisHtml = !empty($workflowTag) ? $workflowTag : h($analysisLevels[$event['Event']['analysis']]);
                            $tlpTag = findAndBuildTag($event['EventTag'], 'tlp:', $this);
                            $tlpHtml = !empty($tlpTag) ? $tlpTag : h($distributionLevels[$event['Event']['distribution']]);
                        ?>
                        <tr>
                            <td><?= h($event['Orgc']['name']) ?></td>
                            <td><?= $tlpHtml ?></td>
                            <td><?= $analysisHtml ?></td>
                            <td><?= h($event['ThreatLevel']['name']); ?></td>
                            <?php foreach ($additional_taxonomy_event_list as $taxonomy_name => $taxonomy_prefix): ?>
                                <td><?= findAndBuildTag($event['EventTag'], $taxonomy_prefix, $this) ?></td>
                            <?php endforeach; ?>
                            <td><a href="<?= sprintf('%s/events/view/%s', $baseurl, h($event['Event']['uuid'])) ?>"><?= h($event['Event']['info']) ?></a></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <p><?= __('No events.') ?></p>
        <?php endif; ?>
    <?php endif; ?>
<?php endif; // detailed-summary-full ?>

<?php if ($this->fetch('aggregated-context')): ?>
    <?= $this->fetch('aggregated-context'); ?>
<?php else: ?>
    <div>
        <?= $aggregated_context; ?>
    </div>
<?php endif; ?>

<?= $this->fetch('content'); ?>