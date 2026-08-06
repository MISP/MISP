<?php
$tpl = $data['EventTemplate'] ?? [];
$definition = is_array($tpl['definition'] ?? null) ? $tpl['definition'] : [];
$structure = is_array($definition['structure'] ?? null)
    ? $definition['structure']
    : [];

$typeMeta = [
    'section' => ['label' => __('Section'), 'icon' => 'folder'],
    'text_block' => ['label' => __('Text block'), 'icon' => 'align-left'],
    'attribute_field' => ['label' => __('Attribute'), 'icon' => 'tag'],
    'object_field' => ['label' => __('Object'), 'icon' => 'cube'],
    'tag_field' => ['label' => __('Tag'), 'icon' => 'tags'],
    'galaxy_field' => ['label' => __('Galaxy'), 'icon' => 'globe'],
    'file_field' => ['label' => __('File'), 'icon' => 'file'],
    'event_report' => ['label' => __('Event report'), 'icon' => 'file-lines'],
    'object_reference' => ['label' => __('Reference'), 'icon' => 'link'],
];

/*
 * Two passes: collect the sections first so a child that happens to be
 * authored before its parent still lands in the right group. Elements with no
 * (or an unknown) parent are rendered on their own, above the sections.
 */
$sections = [];
foreach ($structure as $element) {
    if (($element['type'] ?? '') === 'section' && !empty($element['id'])) {
        $sections[$element['id']] = ['section' => $element, 'children' => []];
    }
}
$orphans = [];
foreach ($structure as $element) {
    if (($element['type'] ?? '') === 'section') {
        continue;
    }
    $parent = $element['parent'] ?? null;
    if ($parent !== null && isset($sections[$parent])) {
        $sections[$parent]['children'][] = $element;
    } else {
        $orphans[] = $element;
    }
}

/**
 * One structure element as a row: type badge, label, stable id, flags and the
 * type-specific detail line.
 */
$renderElement = function (array $element) use ($typeMeta, $baseurl) {
    $type = $element['type'] ?? '';
    $meta = $typeMeta[$type] ?? ['label' => $type, 'icon' => 'circle'];
    $label = $element['label'] ?? '';

    $flags = '';
    if (!empty($element['mandatory'])) {
        $flags .= '<span class="badge bg-warning-subtle text-warning-emphasis'
            . ' border border-warning-subtle" title="'
            . h(__('The reporter cannot leave this empty')) . '">'
            . '<i class="fas fa-asterisk me-1"></i>' . __('Mandatory') . '</span>';
    }
    if (!empty($element['repeatable'])) {
        $flags .= '<span class="badge bg-body border text-body-secondary fw-normal" title="'
            . h(__('The reporter can add several entries')) . '">'
            . '<i class="fas fa-plus me-1"></i>' . __('Repeatable') . '</span>';
    }
    if (!empty($element['multiple'])) {
        $flags .= '<span class="badge bg-body border text-body-secondary fw-normal" title="'
            . h(__('Several values can be picked')) . '">'
            . '<i class="fas fa-layer-group me-1"></i>' . __('Multiple') . '</span>';
    }

    // Type-specific detail: what this element ends up producing in the event.
    $detail = '';
    if ($type === 'attribute_field') {
        $misp = is_array($element['misp'] ?? null) ? $element['misp'] : [];
        $bits = [];
        if (!empty($misp['category'])) {
            $bits[] = $this->element('genericElementsBS5/Badges/category', [
                'category' => $misp['category'],
                'full' => true,
            ]);
        }
        if (!empty($misp['type'])) {
            $bits[] = $this->element('genericElementsBS5/Badges/type', [
                'type' => $misp['type'],
            ]);
        }
        if (!empty($misp['to_ids_default'])) {
            $bits[] = '<span class="badge bg-body border text-body-secondary fw-normal">'
                . '<i class="fas fa-shield-halved text-warning me-1"></i>'
                . __('IDS by default') . '</span>';
        }
        if (!empty($misp['default_value'])) {
            $bits[] = '<span class="text-muted small">'
                . __('Default: %s', '<code>' . h($misp['default_value']) . '</code>')
                . '</span>';
        }
        $detail = implode('', $bits);
    } elseif ($type === 'object_field') {
        $objectTemplate = is_array($element['object_template'] ?? null)
            ? $element['object_template']
            : [];
        if (!empty($objectTemplate['name'])) {
            $detail .= '<span class="badge bg-body border text-body-secondary fw-normal">'
                . '<i class="fas fa-cube me-1"></i>' . h($objectTemplate['name'])
                . (!empty($objectTemplate['minimum_version'])
                    ? ' v' . (int)$objectTemplate['minimum_version']
                    : '')
                . '</span>';
        }
        $relations = is_array($element['relations'] ?? null) ? $element['relations'] : [];
        if (!empty($relations)) {
            $detail .= '<span class="text-muted small">'
                . __n('%s object attribute', '%s object attributes',
                    count($relations), count($relations))
                . '</span>';
        }
    } elseif ($type === 'tag_field') {
        $taxonomies = is_array($element['restrict_taxonomies'] ?? null)
            ? $element['restrict_taxonomies']
            : [];
        $detail = empty($taxonomies)
            ? '<span class="text-muted small">' . __('Any taxonomy') . '</span>'
            : '<span class="text-muted small">'
                . __('Restricted to: %s', h(implode(', ', $taxonomies))) . '</span>';
    } elseif ($type === 'galaxy_field') {
        $galaxyTypes = is_array($element['restrict_galaxy_types'] ?? null)
            ? $element['restrict_galaxy_types']
            : [];
        $detail = empty($galaxyTypes)
            ? '<span class="text-muted small">' . __('Any galaxy') . '</span>'
            : '<span class="text-muted small">'
                . __('Restricted to: %s', h(implode(', ', $galaxyTypes))) . '</span>';
    } elseif ($type === 'file_field') {
        $detail = '<span class="badge bg-body border text-body-secondary fw-normal">'
            . '<i class="fas fa-paperclip me-1"></i>'
            . __('Saved as %s', h($element['as'] ?? 'attachment')) . '</span>';
    } elseif ($type === 'text_block') {
        $content = trim((string)($element['content'] ?? ''));
        $detail = $content === ''
            ? '<span class="text-muted small fst-italic">' . __('Empty text block') . '</span>'
            : '<span class="text-muted small">' . h(mb_strimwidth($content, 0, 160, '…')) . '</span>';
    } elseif ($type === 'object_reference') {
        $detail = '<span class="text-muted small font-monospace">'
            . h($element['from'] ?? '?') . ' &rarr; ' . h($element['to'] ?? '?')
            . ' (' . h($element['relationship_type'] ?? '?') . ')</span>';
    }

    $help = trim((string)($element['help'] ?? ''));

    return '<div class="border rounded p-3 bg-body">'
        . '<div class="d-flex align-items-center flex-wrap gap-2">'
            . '<span class="badge bg-secondary-subtle text-secondary-emphasis'
                . ' text-uppercase" style="font-size:.6rem; letter-spacing:.05em;">'
                . '<i class="fas fa-' . h($meta['icon']) . ' me-1"></i>'
                . h($meta['label']) . '</span>'
            . '<span class="fw-semibold">'
                . ($label !== '' ? h($label) : '<span class="text-muted fst-italic">'
                    . __('(unnamed)') . '</span>')
                . '</span>'
            . '<code class="text-muted ms-auto" style="font-size:.75rem;">'
                . h($element['id'] ?? '') . '</code>'
        . '</div>'
        . ($flags !== '' || $detail !== ''
            ? '<div class="d-flex align-items-center flex-wrap gap-2 mt-2">'
                . $flags . $detail . '</div>'
            : '')
        . ($help !== ''
            ? '<div class="text-muted mt-2" style="font-size:.8rem;">'
                . '<i class="fas fa-circle-info me-1" style="font-size:.7rem;"></i>'
                . nl2br(h($help)) . '</div>'
            : '')
        . '</div>';
};
?>
<div class="card mb-3 shadow-sm">
    <div class="card-header bg-white fw-semibold d-flex justify-content-between align-items-center">
        <span>
            <i class="fas fa-list-check me-2"></i><?= __('What the reporter is asked for') ?>
        </span>
        <?php if ($this->Acl->canAccess('eventTemplates', 'preview')): ?>
            <button type="button" class="btn btn-sm btn-outline-primary"
                    onclick="openModal('<?= h($baseurl . '/event_templates/preview/' . (int)($tpl['id'] ?? 0)) ?>', 'xl');"
                    title="<?= h(__('Walk through the generated form without creating anything')) ?>">
                <i class="fas fa-eye me-1"></i><?= __('Preview the form') ?>
            </button>
        <?php endif; ?>
    </div>
    <div class="card-body p-4">

        <?php if (empty($structure)): ?>
            <div class="text-muted fst-italic">
                <?= __('This template has no elements yet — open it in the builder to compose one.') ?>
            </div>
        <?php else: ?>

            <div class="d-flex flex-column gap-4">

                <?php if (!empty($orphans)): ?>
                    <div>
                        <div class="text-primary fw-bold text-uppercase mb-2"
                             style="font-size:.65rem; letter-spacing:.1em;">
                            <?= __('Outside any section') ?>
                        </div>
                        <div class="d-flex flex-column gap-2">
                            <?php foreach ($orphans as $element): ?>
                                <?= $renderElement($element) ?>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>

                <?php foreach ($sections as $group): ?>
                    <?php $section = $group['section']; ?>
                    <div>
                        <div class="d-flex align-items-center flex-wrap gap-2 mb-2">
                            <span class="text-primary fw-bold text-uppercase"
                                  style="font-size:.65rem; letter-spacing:.1em;">
                                <i class="fas fa-folder me-1"></i>
                                <?= h($section['label'] ?? __('(untitled section)')) ?>
                            </span>
                            <span class="badge bg-secondary-subtle text-secondary-emphasis"
                                  style="font-size:.6rem;">
                                <?= count($group['children']) ?>
                            </span>
                            <code class="text-muted ms-auto" style="font-size:.75rem;">
                                <?= h($section['id'] ?? '') ?>
                            </code>
                        </div>

                        <?php if (!empty($section['help'])): ?>
                            <div class="text-muted mb-2" style="font-size:.8rem;">
                                <i class="fas fa-circle-info me-1" style="font-size:.7rem;"></i>
                                <?= nl2br(h($section['help'])) ?>
                            </div>
                        <?php endif; ?>

                        <?php if (empty($group['children'])): ?>
                            <div class="text-muted fst-italic" style="font-size:.85rem;">
                                <?= __('Empty section.') ?>
                            </div>
                        <?php else: ?>
                            <div class="d-flex flex-column gap-2 ps-3 border-start border-2 border-light-subtle">
                                <?php foreach ($group['children'] as $element): ?>
                                    <?= $renderElement($element) ?>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>

            </div>

        <?php endif; ?>

    </div>
</div>
