<?php
/**
 * An object's attributes as a grid of the attribute indexes' cards
 * (Attributes/index_card_tile), each part drawn by the field the attribute
 * index draws it with, and the object relation between the category and the
 * type, which it stands for when the two are the same. Shared by the object
 * card and the objects index's expanded row.
 *
 * Parameters:
 *   attrs              array  the object's attributes, as the Objects tab loads them
 *   canEdit            bool   may modify the object's event
 *   canTag             bool   may tag the object's attributes
 *   mayGraph           bool   may add to a workspace
 *   showActions        bool   draw each attribute's selection box and action
 *                             menu (default true)
 *   readonly           bool   report the IDS and correlation states without
 *                             their toggles, for a page that has not loaded
 *                             the attribute's event
 *   enrichmentEnabled  bool   Plugin.Enrichment_services_enable
 *   cortexEnabled      bool   Plugin.Cortex_services_enable
 *
 * Read from the view: $baseurl, $me.
 */
$objCanEdit = !empty($canEdit);
$objCanTag = !empty($canTag);
$mayGraph = !empty($mayGraph);
$showActions = $showActions ?? true;
$readonly = !empty($readonly);
$menuOptions = [
    'canEdit' => $objCanEdit,
    'enrichmentEnabled' => !empty($enrichmentEnabled),
    'cortexEnabled' => !empty($cortexEnabled),
];

$sectionsOf = function (array $attr) use ($objCanTag, $mayGraph, $showActions, $menuOptions, $baseurl) {
    $row = ['Attribute' => $attr];
    $field = function ($element, array $field, $fieldRow = null) use ($row) {
        return $this->element('genericElementsBS5/IndexTable/Fields/' . $element, [
            'row' => $fieldRow ?? $row,
            'field' => $field,
            'viewMode' => 'card',
        ]);
    };
    $sections = [
        'category' => sprintf(
            '<span class="oi-attr-category" title="%s">%s</span>',
            h($attr['category'] ?? ''),
            $field('category', ['data_path' => 'Attribute.category'])
        ),
        'type' => $field('type', ['data_path' => 'Attribute.type']),
        'value' => $field('attribute_value', ['data_path' => 'Attribute']),
        'tags' => $field('tag_list', [
            'data_path' => 'Attribute.AttributeTag',
            'add_tag' => $objCanTag,
            'add_tag_url' => $baseurl . '/attributes/editAttributeTags/%id%',
            'add_tag_id_path' => 'Attribute.id',
            'add_relationship_url' => $baseurl . '/attributes/editAttributeTagRelationships/%id%',
        ]),
        'galaxies' => $field('galaxy', [
            'data_path' => 'Attribute.Galaxy',
            'add_galaxy' => $objCanTag,
            'add_galaxy_url' => $baseurl . '/attributes/editAttributeGalaxies/%id%',
            'add_galaxy_id_path' => 'Attribute.id',
            'add_galaxy_relationship_url' => $baseurl . '/attributes/editAttributeGalaxyRelationships/%id%',
        ]),
        'related' => $field('relatedEvents', [], $attr),
        'feeds' => $field('feedHits', []),
        'sightings' => $field('sightings', ['sightings' => ['data' => [], 'csv' => []]], $attr),
        'analyst' => $field('analyst_data_badges', [
            'note_path' => 'Note',
            'opinion_path' => 'Opinion',
            'relationship_path' => 'Relationship',
            'uuid_path' => 'uuid',
            'object_type' => 'Attribute',
        ], $attr),
    ];
    if (!empty($attr['object_relation'])) {
        // Most relations are named after their type: one box says both.
        if ($attr['object_relation'] === ($attr['type'] ?? null)) {
            unset($sections['type']);
        }
        $sections['relation'] = sprintf(
            '<span class="d-inline-flex align-items-center"><p class="border border-dark rounded p-1 mb-0'
                . ' bg-dark text-white" style="font-size:inherit;" title="%s">%s</p></span>',
            h(__('Object relation')),
            h($attr['object_relation'])
        );
    }
    if ($showActions) {
        $sections['selector'] = sprintf(
            '<div class="d-inline-flex align-items-center checkbox-actions-wrapper checkbox-index">'
                . '<input type="checkbox" class="item-checkbox form-check-input mass-select mt-0"'
                . ' data-item-id="%d" data-can-delete="%s"%s></div>',
            (int)$attr['id'],
            $menuOptions['canEdit'] ? '1' : '0',
            ($mayGraph && empty($attr['deleted']))
                ? ' data-graph-item="' . h(json_encode([
                    'type' => 'Attribute', 'uuid' => $attr['uuid'], 'label' => $attr['value'],
                ])) . '"'
                : ''
        );
        $sections['actions'] = '<div class="d-inline-flex align-items-center checkbox-actions-wrapper checkbox-index">'
            . $this->element('Objects/attribute_actions', ['attr' => $attr] + $menuOptions)
            . '</div>';
    }
    // As the scaffold hands them over: a list per section, the blank ones out.
    return array_filter(array_map(function ($html) {
        return trim($html) === '' ? [] : [$html];
    }, $sections));
};
?>
<?php if (!empty($attrs)): ?>
    <div class="oi-attrs idx-card-grid">
        <?php foreach ($attrs as $attr): ?>
            <div class="idx-card-col">
                <div class="card shadow-sm idx-card h-100<?= !empty($attr['deleted']) ? ' attr-deleted' : '' ?>">
                    <?= $this->element('Attributes/index_card_tile', [
                        'row' => ['Attribute' => $attr],
                        'sections' => $sectionsOf($attr),
                        'readonly' => $readonly,
                    ]) ?>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
<?php else: ?>
    <div class="oi-attrs-empty">
        <?= __('No attributes to display for this object.') ?>
    </div>
<?php endif; ?>
