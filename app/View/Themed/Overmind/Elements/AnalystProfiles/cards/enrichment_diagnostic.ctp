<?php
/**
 * The site admin's enrichment card: what the enabled profiles ask for that
 * this instance cannot do, grouped by what fixes it.
 *
 * @var array $card From IndexCardsTool::diagnostic()
 * @var array $org_names Organisation id => name, for reserved modules
 */
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
    IndexCardsTool::MODULE_MISSING => array(
        __('Not installed'), __('this misp-modules does not have it')),
    IndexCardsTool::MODULE_RESTRICTED => array(
        __('Reserved'), __('one organisation only')),
);
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
