<?php
/*
 * The collapsible panel behind the "More filters" button: a grid of controls
 * that apply nothing on their own, then the summary where the draft is shown
 * back and run. Drawn by initIndexFilterDraft() in mispOvermind.js, which
 * finds the controls by `.filter-draft-input` and the summary by
 * `.filter-draft-summary`.
 *
 * Parameters:
 *  - $id          : collapse id, matching the toggle's data-bs-target
 *  - $open        : whether it starts expanded
 *  - $fields      : normalised controls, each:
 *      [
 *        'name'        => 'published',       // the filter key
 *        'label'       => __('Published'),
 *        'type'        => 'select'|'text'|'date'|'number',   // default text
 *        'value'       => '1',               // already resolved by the caller
 *        'options'     => [...],             // select only, value => label
 *        'col'         => 3,                 // bootstrap column width
 *        'placeholder' => '', 'step' => '', 'help' => '',
 *      ]
 *  - $input_class : extra classes on every control. This is where the two
 *                   bars differ and the only reason this is a parameter: the
 *                   log card wires TomSelect through `tom-select`, the
 *                   scaffold through `topbar-filter`, and the scaffold's URL
 *                   builders read `.topbar-filter[name]`.
 */
$fields = $fields ?? [];
$inputClass = $input_class ?? '';
?>
<div class="collapse <?= !empty($open) ? 'show' : '' ?>" id="<?= h($id) ?>" data-filter-draft-panel>
    <hr>
    <div class="row g-3">
        <?php foreach ($fields as $f):
            $name = $f['name'];
            $type = $f['type'] ?? 'text';
            $val  = (string)($f['value'] ?? '');
            $base = ($type === 'select')
                ? 'form-select form-select-sm'
                : 'form-control form-control-sm';
            $attrs = 'name="' . h($name) . '" data-manual="1"'
                . ' class="filter-draft-input ' . $base . ' ' . h($inputClass) . '"';
        ?>
            <div class="col-md-<?= (int)($f['col'] ?? 3) ?> filter-draft-field">
                <label class="form-label small fw-semibold mb-1"><?= h($f['label'] ?? $name) ?></label>

                <?php if ($type === 'select'): ?>
                    <select <?= $attrs ?> data-placeholder="<?= h($f['options'][''] ?? __('Any')) ?>">
                        <?php foreach (($f['options'] ?? []) as $optVal => $optLabel): ?>
                            <option value="<?= h($optVal) ?>" <?= ((string)$optVal === $val) ? 'selected' : '' ?>>
                                <?= h($optLabel) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>

                <?php elseif ($type === 'date'): ?>
                    <input type="date" <?= $attrs ?> value="<?= h($val) ?>">

                <?php elseif ($type === 'number'): ?>
                    <input type="number" <?= $attrs ?>
                           <?= isset($f['step']) ? 'step="' . h($f['step']) . '"' : '' ?>
                           placeholder="<?= h($f['placeholder'] ?? '') ?>" value="<?= h($val) ?>">

                <?php else: ?>
                    <input type="text" <?= $attrs ?>
                           placeholder="<?= h($f['placeholder'] ?? '') ?>"
                           value="<?= h($val) ?>" autocomplete="off">
                <?php endif; ?>

                <?php if (!empty($f['help'])): ?>
                    <div class="form-text small"><?= h($f['help']) ?></div>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </div>

    <!-- Chips, status, "Apply filters" and "Clear all" — drawn by initIndexFilterDraft() -->
    <div class="filter-draft-summary border-top mt-3 pt-3"></div>
</div>
