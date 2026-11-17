<?php
App::uses('GalaxyMatrixLayout', 'Tools');
App::uses('EventMatrixTool', 'Tools/EventOverview');
$iconClass = !empty($data['icon']) ? $this->FontAwesome->getClass($data['icon']) : 'fas fa-shapes';
$palette = $this->GalaxyColour->palette($data['name'] ?? '');
$connectorPrefix = 'misp-galaxy:' . ($data['type'] ?? '') . '=';
$killChains = [];
foreach (is_array($data['kill_chain_order'] ?? null) ? $data['kill_chain_order'] : [] as $chain => $phases) {
    $phases = array_values(array_filter((array)$phases, function ($phase) {
        return is_string($phase) && trim($phase) !== '';
    }));
    if (!empty($phases)) {
        $killChains[$chain] = $phases;
    }
}
$kcId = 'gx-kc-' . (int)($data['id'] ?? 0);
// Columns per row for each width tier of misp-matrix.css, rows balanced
$kcColumns = function ($count) {
    $vars = [];
    foreach ([2, 3, 4, 5, 6, 7, 8, 10] as $max) {
        $vars[] = sprintf('--kc-c%d:%d', $max, (int)ceil($count / ceil($count / $max)));
    }
    return implode(';', $vars);
};

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$flags = [
    [
        'on' => !empty($data['enabled']),
        'colour' => 'success',
        'icon' => 'fas fa-power-off',
        'label' => [__('Enabled'), __('Disabled')],
        'sub' => [__('Its clusters can be attached'), __('Its clusters cannot be attached')],
    ],
    [
        'on' => !empty($data['default']),
        'colour' => 'primary',
        'icon' => 'fas fa-box',
        'label' => [__('Default'), __('Custom')],
        'sub' => [__('Shipped with MISP, updated from the galaxy library'), __('Created on a MISP instance')],
    ],
    [
        'on' => !empty($data['local_only']),
        'colour' => 'warning',
        'icon' => 'fas fa-house-lock',
        'label' => [__('Local only'), __('Shareable')],
        'sub' => [__('Never leaves this instance'), __('Synchronised with its distribution')],
    ],
];
?>
<div class="card mb-3 shadow-sm" data-tour="galaxy-general">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                    <i class="<?= h($iconClass) ?> me-1" style="color:<?= h($palette['tintIcon']) ?>;"></i><?= __('Galaxy') ?>
                </span>
                <span class="d-flex flex-wrap align-items-center gap-1">
                    <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle">
                        v<?= h((int)($data['version'] ?? 0)) ?>
                    </span>
                </span>
            </div>
            <?php if (trim($data['description'] ?? '') !== ''): ?>
                <div class="border-start border-3 rounded-end px-3 py-2 text-break"
                     style="border-color:<?= h($palette['tintIcon']) ?> !important;background:<?= h($palette['sectionBg']) ?>;">
                    <?= nl2br(h($data['description'])) ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
            <?php endif; ?>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Tagging') ?></div>
            <div class="d-flex flex-wrap align-items-center gap-2">
                <span class="d-inline-flex align-items-stretch border rounded-pill bg-body-tertiary font-monospace overflow-hidden lh-base mw-100">
                    <span class="d-inline-flex align-items-center gap-1 px-2 text-body-secondary" title="<?= h(__('Type')) ?>">
                        <i class="fas fa-shapes opacity-50"></i><?= h($data['type'] ?? '') ?>
                    </span>
                    <span class="vr my-1"></span>
                    <button type="button" class="ov-copy-target focus-ring d-inline-flex align-items-center gap-1 border-0 bg-transparent text-body-secondary px-2 mb-0 text-truncate"
                            title="<?= h(__('Clusters of this galaxy are attached as tags of this form — click to copy')) ?>"
                            data-copy-value="<?= h($connectorPrefix) ?>"
                            data-copy-msg="<?= h(__('Connector copied to clipboard')) ?>"
                            onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">
                        <i class="fas fa-tag opacity-50"></i><?= h($connectorPrefix) ?><span class="opacity-50">"&hellip;"</span><i class="fas fa-copy fa-xs"></i>
                    </button>
                </span>
            </div>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Category') ?></div>
            <?php if (empty($data['category'])): ?>
                <span class="text-body-secondary fst-italic small"><?= __('Not classified') ?></span>
            <?php else: ?>
                <div class="d-inline-flex align-items-center gap-2">
                    <span class="badge rounded-pill bg-body-tertiary text-body border fw-normal"><?= h($data['category']) ?></span>
                    <?php if (!empty($data['sub_category'])): ?>
                        <span class="text-body-secondary small"><?= h($data['sub_category']) ?></span>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Settings') ?></div>
            <div class="d-flex flex-wrap row-gap-2 column-gap-3">
                <?php foreach ($flags as $flag): ?>
                    <?php $state = $flag['on'] ? 0 : 1; ?>
                    <div class="d-flex align-items-center gap-2 min-w-0<?= $flag['on'] ? '' : ' opacity-75' ?>" style="flex:1 1 13rem;">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 <?= $flag['on']
                            ? 'bg-' . $flag['colour'] . '-subtle text-' . $flag['colour'] . '-emphasis'
                            : 'bg-body-secondary text-body-secondary' ?>"
                              style="<?= $tileStyle ?>">
                            <i class="<?= h($flag['icon']) ?>"></i>
                        </span>
                        <div class="min-w-0">
                            <div class="fw-semibold lh-sm<?= $flag['on'] ? '' : ' text-body-secondary' ?>"><?= h($flag['label'][$state]) ?></div>
                            <div class="small text-body-secondary text-truncate" title="<?= h($flag['sub'][$state]) ?>"><?= h($flag['sub'][$state]) ?></div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <?php if (!empty($killChains)): ?>
            <div class="gx-kc-set">
                <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-2">
                    <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>"><?= __('Kill chain') ?></span>
                    <?php if (!empty($isMatrixGalaxy)): ?>
                        <a href="#tab-matrix" class="gx-kc-open">
                            <i class="fas fa-table-cells" aria-hidden="true"></i><?= __('Open the matrix') ?><i class="fas fa-arrow-right fa-xs" aria-hidden="true"></i>
                        </a>
                    <?php endif; ?>
                </div>
                <?php if (count($killChains) > 1): ?>
                    <?php
                    $kcFront = count($killChains) > 7 ? 6 : count($killChains);
                    $kcPick = function ($c, $chain, $phases, $inMenu) use ($kcId, $data) {
                        $name = EventMatrixTool::tabLabel($chain, $data['type'] ?? '');
                        return sprintf(
                            '<button type="button" class="%s"%s data-kc-pick="%d" data-kc-name="%s" aria-controls="%s">%s<span class="gx-kc-pick-n">%d</span></button>',
                            $inMenu ? 'dropdown-item d-flex justify-content-between gap-3' : 'mx-full-tab',
                            $inMenu ? '' : sprintf(' role="tab" aria-selected="%s"', $c === 0 ? 'true' : 'false'),
                            $c, h($name), h($kcId . '-' . $c), h($name), count($phases)
                        );
                    };
                    ?>
                    <div class="gx-kc-pick" role="tablist" aria-label="<?= h(__('Kill chains')) ?>">
                        <?php $c = 0; ?>
                        <?php foreach (array_slice($killChains, 0, $kcFront, true) as $chain => $phases): ?>
                            <?= $kcPick($c++, $chain, $phases, false) ?>
                        <?php endforeach; ?>
                        <?php if ($kcFront < count($killChains)): ?>
                            <div class="dropdown mx-full-more">
                                <button type="button" class="mx-full-tab dropdown-toggle" data-bs-toggle="dropdown" data-bs-display="static"
                                        aria-expanded="false" aria-selected="false" data-kc-more="<?= h(__('%s more', count($killChains) - $kcFront)) ?>">
                                    <?= h(__('%s more', count($killChains) - $kcFront)) ?>
                                </button>
                                <ul class="dropdown-menu">
                                    <?php foreach (array_slice($killChains, $kcFront, null, true) as $chain => $phases): ?>
                                        <li><?= $kcPick($c++, $chain, $phases, true) ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
                <?php $c = 0; ?>
                <?php foreach ($killChains as $chain => $phases): ?>
                    <div id="<?= h($kcId . '-' . $c) ?>" role="tabpanel" data-kc-chain="<?= $c ?>"<?= $c > 0 ? ' hidden' : '' ?>>
                        <ol class="gx-kc" style="<?= $kcColumns(count($phases)) ?>"
                            aria-label="<?= h(EventMatrixTool::tabLabel($chain, $data['type'] ?? '')) ?>">
                            <?php foreach ($phases as $i => $phase): ?>
                                <?php
                                $tone = $this->GalaxyColour->stepPalette($i, count($phases));
                                $phaseLabel = GalaxyMatrixLayout::formatTactic($phase);
                                ?>
                                <li class="gx-kc-step" title="<?= h($phaseLabel) ?>"
                                    style="--kc-bg:<?= h($tone['tintBg']) ?>;--kc-fg:<?= h($tone['headerText']) ?>;--kc-n:<?= h($tone['tintIcon']) ?>;">
                                    <span class="gx-kc-i"><?= sprintf('%02d', $i + 1) ?></span>
                                    <span class="gx-kc-l"><?= h($phaseLabel) ?></span>
                                </li>
                            <?php endforeach; ?>
                        </ol>
                    </div>
                    <?php $c++; ?>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

    </div>
</div>
