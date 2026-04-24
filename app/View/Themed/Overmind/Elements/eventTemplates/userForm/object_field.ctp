<?php
    $id = isset($element['id']) ? (string)$element['id'] : '';
    $label = isset($element['label']) ? (string)$element['label'] : $id;
    $help = isset($element['help']) ? (string)$element['help'] : '';
    $mandatory = !empty($element['mandatory']);
    $repeatable = !empty($element['repeatable']);
    $spec = isset($objectRelationSpecs[$id]) ? $objectRelationSpecs[$id] : null;
?>
<div class="et-field et-object-field card border mb-3"
     data-et-element-id="<?= h($id) ?>"
     data-et-element-type="object_field"
     data-et-mandatory="<?= $mandatory ? '1' : '0' ?>"
     data-et-repeatable="<?= $repeatable ? '1' : '0' ?>">
    <div class="card-body">
        <div class="fw-semibold mb-1">
            <?= h($label) ?>
            <?php if ($mandatory): ?>
                <span class="text-danger" title="<?= __('Mandatory') ?>">*</span>
            <?php endif; ?>
            <?php if (!empty($spec) && !$spec['missing']): ?>
                <span class="text-muted small fw-normal ms-1">
                    <?= h($spec['meta_category'] . ' · v' . $spec['found_version']) ?>
                </span>
            <?php endif; ?>
        </div>
        <?php if ($help !== ''): ?>
            <div class="et-help text-muted small mb-2">
                <?= $this->EventTemplateMarkdown->render($help) ?>
            </div>
        <?php endif; ?>

        <?php if (empty($spec) || !empty($spec['missing'])): ?>
            <div class="alert alert-danger mb-0">
                <?= __('Referenced object template is not installed on this instance (uuid %s at pinned version %s).',
                    !empty($spec['uuid']) ? h($spec['uuid']) : '?',
                    !empty($spec['pinned_version']) ? (int)$spec['pinned_version'] : '?'
                ) ?>
            </div>
        <?php else: ?>
            <?php
                $req = isset($spec['requirements']) && is_array($spec['requirements'])
                    ? $spec['requirements']
                    : [];
                $required = isset($req['required']) && is_array($req['required'])
                    ? $req['required']
                    : [];
                $requiredOneOf = isset($req['requiredOneOf']) && is_array($req['requiredOneOf'])
                    ? $req['requiredOneOf']
                    : [];
            ?>
            <?php if (!empty($required) || !empty($requiredOneOf)): ?>
                <div class="et-object-requirements alert alert-info py-2 px-3 small mb-2">
                    <?php if (!empty($required)): ?>
                        <div>
                            <strong><?= __('Required:') ?></strong>
                            <?php
                                $chips = array_map(
                                    function ($r) { return '<code>' . h($r) . '</code>'; },
                                    $required
                                );
                                echo implode(', ', $chips);
                            ?>
                        </div>
                    <?php endif; ?>
                    <?php if (!empty($requiredOneOf)): ?>
                        <div>
                            <strong><?= __('At least one of:') ?></strong>
                            <?php
                                $chips = array_map(
                                    function ($r) { return '<code>' . h($r) . '</code>'; },
                                    $requiredOneOf
                                );
                                echo implode(', ', $chips);
                            ?>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <div class="et-entries">
                <div class="et-entry et-object-entry border rounded mb-2">
                    <div class="et-object-entry-header d-flex align-items-center gap-2 px-3 py-2">
                        <button type="button"
                                class="et-object-toggle btn btn-sm btn-link text-decoration-none p-0 fw-medium"
                                aria-expanded="false"
                                title="<?= __('Expand / collapse') ?>">
                            <span class="et-caret me-1">▶</span>
                            <span class="et-object-entry-title"><?= __('Expand to fill') ?></span>
                        </button>
                        <span class="et-object-filled-indicator badge rounded-pill bg-light text-muted border"
                              data-et-filled-state="empty">
                            <?= __('empty') ?>
                        </span>
                        <?php if ($repeatable): ?>
                            <button type="button"
                                    class="btn btn-sm btn-outline-danger ms-auto et-remove-entry"
                                    style="display:none;"
                                    title="<?= __('Remove instance') ?>">
                                <i class="fas fa-times"></i>
                            </button>
                        <?php endif; ?>
                    </div>
                    <div class="et-object-entry-body border-top px-3 py-2" hidden>
                        <?php foreach ($spec['relations'] as $rel): ?>
                            <?php
                                $relation = $rel['object_relation'];
                                $relType = $rel['type'];
                                $relDesc = $rel['description'];
                            ?>
                            <div class="mb-2">
                                <label class="form-label small fw-medium mb-0">
                                    <?= h($relation) ?>
                                    <span class="text-muted small">(<?= h($relType) ?>)</span>
                                </label>
                                <?php if ($relDesc !== ''): ?>
                                    <div class="text-muted small mb-1">
                                        <?= h($relDesc) ?>
                                    </div>
                                <?php endif; ?>
                                <input type="text"
                                       class="form-control form-control-sm bg-light et-value"
                                       data-et-path="<?= h($id . '.' . $relation) ?>">
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
            <?php if ($repeatable): ?>
                <button type="button"
                        class="btn btn-sm btn-outline-secondary mt-1 et-add-entry">
                    <i class="fas fa-plus me-1"></i><?= __('Add another instance') ?>
                </button>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</div>
