<?php
/**
 * A misp-modules family (Enrichment, Import, …): the settings of the service
 * itself, then a grid of the modules with their switch, and a panel holding
 * the settings of the module picked in the grid.
 *
 * Every module's panel is rendered up front (hidden) so picking one costs no
 * request; the switch saves the module's `_enabled` setting through the same
 * edit endpoints as any row.
 *
 * Params:
 *  - sections array the family's sections (ServerSettingGroups::byDestination())
 */

App::uses('ServerSettingGroups', 'Tools');

$grid = ServerSettingGroups::modules($sections);
$modules = $grid['modules'];
$familyId = preg_replace('/[^A-Za-z0-9_-]/', '', $destination);

$selected = null;
foreach (array('needsConfig', 'enabled') as $criterion) {
    foreach ($modules as $id => $module) {
        if ($selected === null && $module[$criterion]) {
            $selected = $id;
        }
    }
}
if ($selected === null && !empty($modules)) {
    $selected = array_keys($modules)[0];
}

$errorsByLevel = array(0 => 0, 1 => 0, 2 => 0);
foreach ($grid['service'] as $setting) {
    if (ServerSettingGroups::inError($setting)) {
        $errorsByLevel[$setting['level']]++;
    }
}
$serviceSection = array(
    'uid' => $familyId . '-service',
    'title' => __('Service'),
    'description' => __('How MISP reaches misp-modules for this family, and what it does with it'),
    'icon' => 'server',
    'accent' => $definition['accent'],
    'settings' => $grid['service'],
    'errorsByLevel' => $errorsByLevel,
);
$counts = array(
    'all' => count($modules),
    'enabled' => count(array_filter(array_column($modules, 'enabled'))),
    'config' => count(array_filter(array_column($modules, 'needsConfig'))),
);
?>
<?php if (!empty($grid['service'])): ?>
    <div data-ss-settings>
        <?= $this->element('healthElementsBS5/settings_section', array('section' => $serviceSection)) ?>
    </div>
<?php endif; ?>

<?php if (empty($modules)): ?>
    <div class="card shadow-sm"><div class="card-body d-flex flex-column align-items-center text-center text-muted py-5">
        <i class="fas fa-puzzle-piece fa-2x mb-3 opacity-50"></i>
        <?= __('No module is advertised by misp-modules for this family. Enable the service and check that misp-modules is reachable.') ?>
    </div></div>
    <?php return; ?>
<?php endif; ?>

<div class="row g-3 ss-modules" data-ss-modules>
    <div class="col-xl-8">
        <div class="card shadow-sm">
            <div class="card-body py-2 d-flex flex-wrap gap-2 align-items-center border-bottom">
                <div class="flex-grow-1" style="max-width: 320px; min-width: 200px;">
                    <div class="input-group input-group-sm">
                        <span class="input-group-text"><i class="fas fa-magnifying-glass"></i></span>
                        <input class="form-control" type="search" data-ss-module-filter autocomplete="off"
                               aria-label="<?= h(__('Filter modules')) ?>" placeholder="<?= h(__('Filter modules')) ?>">
                    </div>
                </div>
                <button type="button" class="ss-toggle active" data-ss-module-chip="all" aria-pressed="true">
                    <?= __('All') ?> <span class="text-muted"><?= h($counts['all']) ?></span>
                </button>
                <button type="button" class="ss-toggle" data-ss-module-chip="enabled" aria-pressed="false">
                    <span class="ss-dot ss-dot-2"></span><?= __('Enabled') ?> <span class="text-muted" data-ss-module-count="enabled"><?= h($counts['enabled']) ?></span>
                </button>
                <button type="button" class="ss-toggle" data-ss-module-chip="config" aria-pressed="false">
                    <span class="ss-dot ss-dot-1"></span><?= __('Needs configuration') ?> <span class="text-muted" data-ss-module-count="config"><?= h($counts['config']) ?></span>
                </button>
            </div>
            <div class="card-body">
                <div class="ss-module-grid">
                    <?php foreach ($modules as $id => $module): ?>
                        <?php
                        $toggleId = $module['toggle'] ? $familyId . '-' . preg_replace('/[^A-Za-z0-9_-]/', '', $id) . '-0' : null;
                        $settingCount = count($module['settings']) + ($module['toggle'] ? 1 : 0);
                        ?>
                        <div class="ss-module<?= $id === $selected ? ' ss-module-selected' : '' ?><?= $module['enabled'] ? '' : ' ss-module-off' ?>"
                             data-ss-module="<?= h($id) ?>"
                             data-ss-enabled="<?= $module['enabled'] ? 1 : 0 ?>"
                             data-ss-needs-config="<?= $module['needsConfig'] ? 1 : 0 ?>">
                            <div class="d-flex align-items-start gap-2">
                                <button type="button" class="ss-module-name btn btn-link p-0 text-start text-body text-decoration-none flex-grow-1 min-w-0"
                                        data-ss-module-open="<?= h($id) ?>"><?= h($id) ?></button>
                                <?php if ($module['toggle']): ?>
                                    <div class="form-check form-switch m-0">
                                        <input class="form-check-input" type="checkbox" role="switch"
                                               data-ss-module-toggle="<?= h($id) ?>"
                                               data-setting="<?= h($module['toggle']['setting']) ?>"
                                               data-setting-id="<?= h($toggleId) ?>"
                                               aria-label="<?= h(__('Enable %s', $id)) ?>"
                                               <?= $module['enabled'] ? 'checked' : '' ?>>
                                    </div>
                                <?php endif; ?>
                            </div>
                            <div class="ss-module-desc"><?= h($module['description']) ?></div>
                            <div class="d-flex justify-content-between align-items-center gap-2 mt-auto">
                                <span class="ss-module-warn<?= $module['needsConfig'] ? '' : ' d-none' ?>" data-ss-module-warn>
                                    <i class="fas fa-circle-exclamation me-1"></i><?= __('Needs configuration') ?>
                                </span>
                                <button type="button" class="btn btn-link btn-sm p-0 ms-auto text-decoration-none" data-ss-module-open="<?= h($id) ?>">
                                    <?= h(__n('%s setting', '%s settings', $settingCount, $settingCount)) ?> <i class="fas fa-arrow-right fa-xs"></i>
                                </button>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
                <div class="text-muted small d-none" data-ss-module-empty><?= __('No module matches.') ?></div>
            </div>
        </div>
    </div>

    <div class="col-xl-4">
        <div class="ss-module-panels" data-ss-settings>
            <?php foreach ($modules as $id => $module): ?>
                <?php $prefix = $familyId . '-' . preg_replace('/[^A-Za-z0-9_-]/', '', $id); ?>
                <div class="card shadow-sm ss-section ss-module-panel<?= $id === $selected ? '' : ' d-none' ?>"
                     data-ss-module-panel="<?= h($id) ?>" style="--ss-accent: <?= h($definition['accent']) ?>;">
                    <div class="card-header ss-section-header" style="cursor: default;">
                        <span class="ss-section-icon"><i class="fas fa-<?= h($definition['icon']) ?>"></i></span>
                        <div class="flex-grow-1 min-w-0">
                            <div class="ss-eyebrow"><?= __('Module settings') ?></div>
                            <div class="fw-semibold text-break"><?= h($id) ?></div>
                        </div>
                    </div>
                    <?php if ($module['description'] !== ''): ?>
                        <div class="px-3 pt-2 text-muted small"><?= h($module['description']) ?></div>
                    <?php endif; ?>
                    <div class="table-responsive">
                        <table class="table table-sm align-middle ss-table ss-essentials mb-0">
                            <tbody>
                                <?php
                                $rows = $module['toggle'] ? array_merge(array($module['toggle']), $module['settings']) : $module['settings'];
                                $paramPrefix = $module['toggle'] ? substr($module['toggle']['setting'], 0, -strlen('enabled')) : '';
                                foreach ($rows as $index => $setting) {
                                    $param = $paramPrefix !== '' && strpos($setting['setting'], $paramPrefix) === 0
                                        ? substr($setting['setting'], strlen($paramPrefix))
                                        : '';
                                    echo $this->element('healthElementsBS5/setting_row', array(
                                        'setting' => $setting,
                                        'k' => $prefix . '-' . $index,
                                        'variant' => 'essential',
                                        'label' => $param === 'enabled' ? __('Enabled') : Inflector::humanize($param),
                                    ));
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>
