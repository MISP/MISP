<?php
/**
 * The site admin's enrichment card: what the enabled profiles ask for that
 * this instance cannot do, grouped by what fixes it.
 *
 * @var array $card From IndexCardsTool::diagnostic()
 * @var array $org_names Organisation id => name, for reserved modules
 */
App::uses('CakeTime', 'Utility');
$settingsUrl = $this->Html->url(array(
    'controller' => 'servers', 'action' => 'serverSettings', 'Plugin'));
$settingLink = function ($setting, $label) use ($settingsUrl) {
    return '<a class="btn btn-sm btn-outline-secondary ap-fix" href="'
        . h($settingsUrl . '#setting=' . $setting) . '">' . h($label) . '</a>';
};
$fixButton = function ($kind, $name, $label, $title) {
    return '<button type="button" class="btn btn-sm btn-outline-primary ap-fix"'
        . ' data-ap-fix="' . h($kind) . '" data-ap-name="' . h($name) . '"'
        . ' title="' . h($title) . '">' . h($label) . '</button>';
};
// "SOC Triage" when one profile asks, "3 profiles" otherwise, every name on hover.
$who = function (array $profiles) {
    $text = count($profiles) === 1
        ? $profiles[0]
        : __n('%s profile', '%s profiles', count($profiles), count($profiles));
    return '<span title="' . h(implode(', ', $profiles)) . '">' . h($text) . '</span>';
};
$what = function (array $types) {
    $text = count($types) === 1
        ? $types[0]
        : __n('%s type', '%s types', count($types), count($types));
    return '<span title="' . h(implode(', ', $types)) . '">' . h($text) . '</span>';
};
$groups = array(
    IndexCardsTool::MODULE_OFF => array(
        __('Switched off'), __('installed, one switch away')),
    IndexCardsTool::MODULE_SETTINGS => array(
        __('Needs settings'), __('a required setting is empty')),
    IndexCardsTool::MODULE_FAILING => array(
        __('Keeps failing'), __('every recent answer is the same error')),
    IndexCardsTool::MODULE_UNSTABLE => array(
        __('Times out or crashes'), __('since misp-modules started')),
    IndexCardsTool::MODULE_MISSING => array(
        __('Not installed'), __('this misp-modules does not have it')),
    IndexCardsTool::MODULE_RESTRICTED => array(
        __('Reserved'), __('one organisation only')),
);
$seconds = function ($value) {
    if ($value === null) {
        return '–';
    }
    if ($value < 1) {
        return __('%s ms', max(1, (int)round($value * 1000)));
    }
    return __('%s s', $value < 10 ? number_format($value, 1) : number_format($value));
};
$activity = $card['activity'];
$taxonomyOff = $card['taxonomies']['off'];
$taxonomyMissing = $card['taxonomies']['missing'];

if ($card['service'] === IndexCardsTool::SERVICE_OFF) {
    $status = array('text' => __('service off'), 'tone' => 't-over');
} elseif ($card['attention'] > 0) {
    $status = array('text' => __n('%s needs you', '%s need you',
        $card['attention'], $card['attention']), 'tone' => 't-over');
} elseif ($card['service'] === IndexCardsTool::SERVICE_ON && $card['asked'] > 0
    && empty($card['groups']) && empty($taxonomyMissing)
) {
    $status = array('text' => __('all ready'), 'tone' => 't-plain');
} else {
    $status = null;
}
?>
<section class="ap-card ap-card-enrich" data-ap-card="enrichment">
    <?= $this->element('AnalystProfiles/cards/head', array(
        'icon' => 'puzzle-piece',
        'title' => __('What the profiles ask for'),
        'status' => $status,
    )) ?>

    <?php if ($card['service'] === IndexCardsTool::SERVICE_OFF): ?>
        <div class="ap-card-alert">
            <p class="mb-0">
                <?= h(__('The enrichment modules service is switched off, so'
                    . ' none of the %s modules the profiles ask for can run.',
                    $card['asked'])) ?>
            </p>
            <?= $fixButton('services', '', __('Turn on'),
                __('Set Plugin.Enrichment_services_enable')) ?>
        </div>
    <?php elseif ($card['service'] === IndexCardsTool::SERVICE_UNREACHABLE): ?>
        <div class="ap-card-alert">
            <p class="mb-0">
                <?= h(__('misp-modules is not answering, so which of the %s'
                    . ' modules the profiles ask for are installed cannot be'
                    . ' checked.', $card['asked'])) ?>
            </p>
            <a class="btn btn-sm btn-outline-secondary ap-fix" href="<?= h(
                $settingsUrl . '#setting=Plugin.Enrichment_services_url') ?>"><?= h(
                __('Service settings')) ?></a>
        </div>
    <?php elseif ($card['asked'] === 0): ?>
        <p class="ap-card-line"><?= h(__('No enabled profile asks for an'
            . ' enrichment module.')) ?></p>
    <?php else: ?>
        <div class="ap-card-fig">
            <span class="ap-card-n"><?= h($card['ready']) ?></span>
            <span class="ap-card-of"><?= h(__n(
                'of the %s module the profiles ask for is ready',
                'of the %s modules the profiles ask for are ready',
                $card['asked'], $card['asked'])) ?></span>
        </div>
    <?php endif; ?>

    <?php if (!empty($card['groups']) || !empty($taxonomyOff) || !empty($taxonomyMissing)): ?>
        <div class="ap-grps">
            <?php foreach ($card['groups'] as $key => $items): ?>
                <div class="ap-grp" data-ap-group="<?= h($key) ?>">
                    <div class="ap-grp-h">
                        <span><?= h($groups[$key][0]) ?></span>
                        <span class="ap-grp-why"><?= h($groups[$key][1]) ?></span>
                    </div>
                    <ul class="ap-items">
                        <?php foreach ($items as $item): ?>
                            <li class="ap-item">
                                <span class="ap-item-main">
                                    <span class="ap-item-name"><?= h($item['name']) ?></span>
                                    <?php if ($item['auto']): ?>
                                        <span class="pill t-force" title="<?= h(__(
                                            'A profile marks it to run without a'
                                            . ' press')) ?>"><?= h(__('auto')) ?></span>
                                    <?php endif; ?>
                                    <span class="ap-item-meta">
                                        <?php if ($key === IndexCardsTool::MODULE_SETTINGS): ?>
                                            <?= h(implode(', ', $item['unset'])) ?>
                                            <?= $item['enabled'] ? '' : h(__('· and switched off')) ?>
                                        <?php elseif ($key === IndexCardsTool::MODULE_FAILING): ?>
                                            <span title="<?= h($item['failing']['message']) ?>">&ldquo;<?= h(
                                                $item['failing']['message']) ?>&rdquo;</span>
                                            &middot; <?= h(__n('%s answer', '%s answers',
                                                $item['failing']['count'],
                                                $item['failing']['count'])) ?>
                                        <?php elseif ($key === IndexCardsTool::MODULE_UNSTABLE): ?>
                                            <?php $faults = array();
                                            if ($item['unstable']['timeouts'] > 0) {
                                                $faults[] = __('%s timed out', number_format($item['unstable']['timeouts']));
                                            }
                                            if ($item['unstable']['exceptions'] > 0) {
                                                $faults[] = __('%s crashed', number_format($item['unstable']['exceptions']));
                                            } ?>
                                            <?= h(__('%s of %s queries', implode(', ', $faults),
                                                number_format($item['unstable']['completed']))) ?>
                                        <?php elseif ($key === IndexCardsTool::MODULE_RESTRICTED): ?>
                                            <?= h(isset($org_names[$item['restrict']])
                                                ? $org_names[$item['restrict']]
                                                : __('organisation %s', $item['restrict'])) ?>
                                            &middot; <?= $who($item['profiles']) ?>
                                        <?php else: ?>
                                            <?= $who($item['profiles']) ?> &middot; <?= $what($item['types']) ?>
                                        <?php endif; ?>
                                    </span>
                                </span>
                                <span class="ap-item-act">
                                    <?php if ($key === IndexCardsTool::MODULE_OFF): ?>
                                        <?= $fixButton('module', $item['name'], __('Enable'),
                                            __('Set Plugin.Enrichment_%s_enabled', $item['name'])) ?>
                                    <?php elseif ($key === IndexCardsTool::MODULE_SETTINGS): ?>
                                        <?= $settingLink('Plugin.Enrichment_' . $item['name']
                                            . '_' . $item['unset'][0], __('Set up')) ?>
                                    <?php elseif ($key === IndexCardsTool::MODULE_FAILING): ?>
                                        <?= $settingLink('Plugin.Enrichment_' . $item['name']
                                            . '_enabled', __('Settings')) ?>
                                    <?php elseif ($key === IndexCardsTool::MODULE_UNSTABLE): ?>
                                        <?php if ($item['unstable']['timeouts'] > 0): ?>
                                            <?= $settingLink('Plugin.Enrichment_timeout', __('Timeout')) ?>
                                        <?php else: ?>
                                            <span class="ap-item-hint"><?= h(__('misp-modules log')) ?></span>
                                        <?php endif; ?>
                                    <?php elseif ($key === IndexCardsTool::MODULE_RESTRICTED): ?>
                                        <?= $settingLink('Plugin.Enrichment_' . $item['name']
                                            . '_restrict', __('Settings')) ?>
                                    <?php endif; ?>
                                </span>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endforeach; ?>

            <?php if (!empty($taxonomyOff)): ?>
                <div class="ap-grp" data-ap-group="taxonomy-off">
                    <div class="ap-grp-h">
                        <span><?= h(__('Taxonomies off')) ?></span>
                        <span class="ap-grp-why"><?= h(__('a profile pins or prefers them')) ?></span>
                    </div>
                    <ul class="ap-items">
                        <?php foreach ($taxonomyOff as $item): ?>
                            <li class="ap-item">
                                <span class="ap-item-main">
                                    <span class="ap-item-name"><?= h($item['namespace']) ?></span>
                                    <span class="ap-item-meta">
                                        <?= h(in_array(ValueLabelPriority::PINNED, $item['tiers'], true)
                                            ? __('pinned') : __('preferred')) ?>
                                        &middot; <?= $who($item['profiles']) ?>
                                    </span>
                                </span>
                                <span class="ap-item-act">
                                    <?= $fixButton('taxonomy', $item['namespace'], __('Enable'),
                                        __('Enable the %s taxonomy', $item['namespace'])) ?>
                                </span>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <?php if (!empty($taxonomyMissing)): ?>
                <div class="ap-grp" data-ap-group="taxonomy-missing">
                    <div class="ap-grp-h">
                        <span><?= h(__('Taxonomies missing')) ?></span>
                        <span class="ap-grp-why"><?= h(__('not on this instance')) ?></span>
                    </div>
                    <ul class="ap-items">
                        <?php foreach ($taxonomyMissing as $item): ?>
                            <li class="ap-item">
                                <span class="ap-item-main">
                                    <span class="ap-item-name"><?= h($item['namespace']) ?></span>
                                    <span class="ap-item-meta"><?= $who($item['profiles']) ?></span>
                                </span>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
        </div>
    <?php elseif ($card['service'] === IndexCardsTool::SERVICE_ON && $card['asked'] > 0): ?>
        <p class="ap-card-line">
            <i class="fas fa-check ap-card-ok" aria-hidden="true"></i>
            <?= h(__('Every module the profiles ask for is installed, switched'
                . ' on and answering.')) ?>
        </p>
    <?php endif; ?>

    <?php if ($activity !== null): ?>
        <?php
        $since = $activity['uptime'] === null ? null : CakeTime::timeAgoInWords(
            time() - (int)$activity['uptime'], array(
                'end' => '+10 years',
                'accuracy' => array('year' => 'month', 'month' => 'day',
                    'week' => 'day', 'day' => 'hour', 'hour' => 'minute'),
            ));
        ?>
        <?php if ($activity['queries'] === 0): ?>
            <p class="ap-card-line ap-activity-none">
                <i class="fas fa-chart-simple" aria-hidden="true"></i>
                <?= h($since === null
                    ? __('No module the profiles ask for has been queried since'
                        . ' misp-modules started.')
                    : __('No module the profiles ask for has been queried since'
                        . ' misp-modules started %s.', $since)) ?>
            </p>
        <?php else: ?>
            <details class="ap-activity">
                <summary>
                    <span class="ap-activity-h"><?= h(__('Service activity')) ?></span>
                    <span class="ap-activity-sum">
                        <?= h(__n('%s query', '%s queries', $activity['queries'],
                            number_format($activity['queries']))) ?>
                        <?php if ($activity['timeouts'] > 0): ?>
                            &middot; <span class="ap-activity-bad"><?= h(__('%s timed out',
                                number_format($activity['timeouts']))) ?></span>
                        <?php endif; ?>
                        <?php if ($activity['exceptions'] > 0): ?>
                            &middot; <span class="ap-activity-bad"><?= h(__('%s crashed',
                                number_format($activity['exceptions']))) ?></span>
                        <?php endif; ?>
                        <?php if ($activity['average'] !== null): ?>
                            &middot; <?= h(__('%s on average', $seconds($activity['average']))) ?>
                        <?php endif; ?>
                    </span>
                </summary>
                <div class="ap-activity-body">
                    <table class="ap-activity-table">
                        <thead>
                            <tr>
                                <th scope="col"><?= h(__('Module')) ?></th>
                                <th scope="col" class="n"><?= h(__('Queries')) ?></th>
                                <th scope="col" class="n ap-activity-wide" title="<?= h(__(
                                    'The module answered with an error. Most modules'
                                    . ' say so when a value has no answer.')) ?>"><?= h(__('Errors')) ?></th>
                                <th scope="col" class="n" title="<?= h(__(
                                    'MISP stopped waiting: Plugin.Enrichment_timeout')) ?>"><?= h(__('Timed out')) ?></th>
                                <th scope="col" class="n" title="<?= h(__(
                                    'The module raised an exception; misp-modules'
                                    . ' logs why')) ?>"><?= h(__('Crashed')) ?></th>
                                <th scope="col" class="n"><?= h(__('Average')) ?></th>
                                <th scope="col" class="n ap-activity-wide"><?= h(__('Slowest')) ?></th>
                                <th scope="col" class="n ap-activity-wide"><?= h(__('Last query')) ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($activity['modules'] as $row): ?>
                                <?php $last = $row['last_query_at'] === null ? false
                                    : strtotime($row['last_query_at']); ?>
                                <tr>
                                    <th scope="row"><span class="ap-item-name"><?= h($row['name']) ?></span></th>
                                    <td class="n"><?= h(number_format($row['queries'])) ?></td>
                                    <td class="n ap-activity-wide<?= $row['module_errors'] ? '' : ' z' ?>"<?php
                                        if ($row['completed'] > 0): ?> title="<?= h(__('%s%% of completed queries',
                                            round(100 * $row['module_errors'] / $row['completed']))) ?>"<?php
                                        endif; ?>><?= h(number_format($row['module_errors'])) ?></td>
                                    <td class="n<?= $row['timeouts'] ? ' bad' : ' z' ?>"><?= h(number_format($row['timeouts'])) ?></td>
                                    <td class="n<?= $row['exceptions'] ? ' bad' : ' z' ?>"><?= h(number_format($row['exceptions'])) ?></td>
                                    <td class="n"><?= h($seconds($row['average'])) ?></td>
                                    <td class="n ap-activity-wide"><?= h($seconds($row['max'])) ?></td>
                                    <td class="n ap-activity-wide"<?php if ($last): ?> title="<?= h(
                                        date('Y-m-d H:i:s', $last)) ?>"<?php endif; ?>><?= h($last
                                        ? CakeTime::timeAgoInWords($last, array(
                                            'end' => '+10 years',
                                            'accuracy' => array('year' => 'month', 'month' => 'day',
                                                'week' => 'day', 'day' => 'hour', 'hour' => 'minute')))
                                        : '–') ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php if (!empty($activity['idle'])): ?>
                        <p class="ap-activity-idle">
                            <?= h(__('Not queried since it started:')) ?>
                            <?php foreach ($activity['idle'] as $i => $name): ?><?= $i > 0 ? ', ' : ''
                                ?><span class="ap-item-name"><?= h($name) ?></span><?php endforeach; ?>
                        </p>
                    <?php endif; ?>
                    <p class="ap-activity-note"><?= h($since === null
                        ? __('Counted by misp-modules for every client it serves,'
                            . ' and reset when it restarts.')
                        : __('Counted by misp-modules since it started %s, for every'
                            . ' client it serves, and reset when it restarts.', $since)) ?></p>
                </div>
            </details>
        <?php endif; ?>
    <?php endif; ?>

    <footer class="ap-card-foot">
        <?php if ($card['auto'] > 0 && $card['gate'] !== ValueEnrichmentTool::GATE_ON): ?>
            <?= h(__n(
                '%s module is marked to run without a press, which this instance %s.',
                '%s modules are marked to run without a press, which this instance %s.',
                $card['auto'], $card['auto'],
                $card['gate'] === ValueEnrichmentTool::GATE_SITE_ADMIN
                    ? __('allows for site admins only')
                    : __('holds back'))) ?>
        <?php endif; ?>
        <a href="<?= h($settingsUrl) ?>"><?= h(__('All module settings')) ?></a>
    </footer>
</section>
