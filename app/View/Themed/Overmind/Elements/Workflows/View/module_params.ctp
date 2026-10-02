<?php
/*
 * The parameters a module takes, as the editor offers them on its node.
 */
$typeLabels = [
    'input' => __('Text'),
    'textarea' => __('Long text'),
    'select' => __('Choice'),
    'picker' => __('Picker'),
    'hashpath' => __('Hash path'),
];

$formatValue = function ($value) {
    if (is_array($value)) {
        return h(json_encode($value, JSON_UNESCAPED_SLASHES));
    }
    if (is_bool($value)) {
        return $value ? 'true' : 'false';
    }
    return h((string)$value);
};
?>

<div class="card mb-3 shadow-sm">
    <div class="card-header bg-transparent d-flex align-items-center gap-2 py-3">
        <i class="fas fa-sliders text-secondary"></i>
        <span class="fw-semibold"><?= __('Parameters') ?></span>
        <span class="text-muted small">(<?= count($data['params']) ?>)</span>
    </div>
    <div class="table-responsive">
        <table class="table table-sm align-middle mb-0">
            <thead>
                <tr class="small text-uppercase text-muted">
                    <th class="ps-3"><?= __('Parameter') ?></th>
                    <th><?= __('Type') ?></th>
                    <th><?= __('Default') ?></th>
                    <th class="pe-3"><?= __('Accepted values') ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($data['params'] as $param): ?>
                    <?php
                    $options = $param['options'] ?? [];
                    if (!empty($options) && array_keys($options) === range(0, count($options) - 1)) {
                        $options = isset($options[0]['name'], $options[0]['value'])
                            ? array_column($options, 'name', 'value')
                            : array_combine($options, $options);
                    }
                    $hasDefault = isset($param['default']) && $param['default'] !== '' && $param['default'] !== [];
                    ?>
                    <tr>
                        <td class="ps-3">
                            <div class="fw-semibold"><?= h($param['label'] ?? $param['id']) ?></div>
                            <code class="small text-body-secondary"><?= h($param['id']) ?></code>
                        </td>
                        <td>
                            <span class="badge rounded-pill fw-normal ov-wf-chip">
                                <?= h($typeLabels[$param['type']] ?? $param['type']) ?>
                            </span>
                            <?php if (!empty($param['multiple'])): ?>
                                <span class="badge rounded-pill fw-normal ov-wf-chip" title="<?= h(__('Several values can be picked')) ?>">
                                    <?= __('multiple') ?>
                                </span>
                            <?php endif; ?>
                            <?php if (!empty($param['jinja_supported'])): ?>
                                <span class="badge rounded-pill text-bg-info fw-normal" title="<?= h(__('The value can use Jinja2 templating')) ?>">
                                    Jinja2
                                </span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($hasDefault): ?>
                                <code class="small"><?= $formatValue($param['default']) ?></code>
                            <?php else: ?>
                                <span class="text-muted small">&ndash;</span>
                            <?php endif; ?>
                        </td>
                        <td class="pe-3">
                            <?php if (!empty($options)): ?>
                                <div class="d-flex flex-wrap gap-1" style="max-width:420px;">
                                    <?php foreach ($options as $value => $label): ?>
                                        <span class="badge rounded-pill fw-normal ov-wf-chip" title="<?= h($value) ?>">
                                            <?= h(is_array($label) ? json_encode($label) : $label) ?>
                                        </span>
                                    <?php endforeach; ?>
                                </div>
                            <?php elseif (!empty($param['picker_options']['select_options_url'])): ?>
                                <span class="small text-muted">
                                    <?= __('Loaded from') ?>
                                    <code><?= h($param['picker_options']['select_options_url']) ?></code>
                                </span>
                            <?php elseif (!empty($param['placeholder'])): ?>
                                <span class="small text-muted"><?= __('e.g.') ?></span>
                                <code class="small"><?= h($param['placeholder']) ?></code>
                            <?php else: ?>
                                <span class="text-muted small">&ndash;</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
