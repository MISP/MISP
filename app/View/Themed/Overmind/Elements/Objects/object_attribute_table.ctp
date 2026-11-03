<?php
/**
 * An object's attributes as an index table: the row under an object that its
 * expand button opens, in the event's Objects tab and in the objects index.
 *
 * Parameters:
 *   attrs              array  the object's attributes, as the Objects tab loads them
 *   canEdit            bool   may modify the object's event
 *   canTag             bool   may tag the object's attributes
 *   mayGraph           bool   may add to a workspace
 *   enrichmentEnabled  bool   Plugin.Enrichment_services_enable
 *   cortexEnabled      bool   Plugin.Cortex_services_enable
 *   readonly           bool   for a page that has not loaded the attribute's
 *                             event: no selection box and no action menu, the
 *                             IDS and correlation states without their toggles
 *
 * Read from the view: $baseurl, $me.
 */
$canEdit = !empty($canEdit);
$canTag = !empty($canTag);
$mayGraph = !empty($mayGraph);
$enrichmentEnabled = !empty($enrichmentEnabled);
$cortexEnabled = !empty($cortexEnabled);
$readonly = !empty($readonly);
?>
<?php if (!empty($attrs)): ?>
<div class="table-responsive">
    <table class="table table-hover align-middle mb-0 ix-table">
        <thead>
            <tr>
                <?php if (!$readonly): ?>
                <th></th>
                <?php endif; ?>
                <th><?= __('Value') ?></th>
                <th><?= __('Category') ?></th>
                <th><?= __('Type') ?></th>
                <th><?= __('Tags') ?></th>
                <th><?= __('Galaxy') ?></th>
                <th><?= __('IDS') ?></th>
                <th><?= __('Correlate') ?></th>
                <th><?= __('Related Events') ?></th>
                <th><?= __('Feed hits') ?></th>
                <th><?= __('Sightings') ?></th>
                <th><?= __('Analyst data') ?></th>
                <?php if (!$readonly): ?>
                <th class="me-2"><?= __('Actions') ?></th>
                <?php endif; ?>
            </tr>
        </thead>
        <tbody>
        <?php foreach (
            $attrs as $attr
        ): ?>
        <?php $attrId = (int)$attr['id']; ?>
            <tr data-primary-id="<?= $attrId ?>"<?php if (
                !empty($attr['deleted'])
            ): ?> class="ov-attr-deleted"<?php
            endif; ?>>

                <?php if (!$readonly): ?>
                <!-- Checkbox -->
                <td>
                    <div class="d-inline-flex align-items-center
                                checkbox-actions-wrapper
                                checkbox-index">
                        <input
                            type="checkbox"
                            class="item-checkbox form-check-input
                                   mass-select mt-0"
                            data-item-id="<?= $attrId ?>"
                            data-can-delete="<?= $canEdit ? '1' : '0' ?>"
                            <?php if ($mayGraph && empty($attr['deleted'])): ?>
                            data-graph-item="<?= h(json_encode(['type' => 'Attribute', 'uuid' => $attr['uuid'], 'label' => $attr['value']])) ?>"
                            <?php endif; ?>
                        >
                    </div>
                </td>
                <?php endif; ?>

                <!-- Value: distribution badge + value + comment via attribute_value -->
                <td class="text-break">
                    <?php echo $this->element(
                        'genericElementsBS5/IndexTable/Fields/attribute_value',
                        [
                            'row'   => ['Attribute' => $attr],
                            'field' => ['data_path' => 'Attribute'],
                        ]
                    ); ?>
                </td>

                <!-- Category + Relation (merged) -->
                <td>
                    <div class="d-flex align-items-center gap-1">
                        <?php echo $this->element(
                            'genericElementsBS5/Badges/category',
                            ['category' => $attr['category'] ?? '']
                        ); ?>
                        <?= $this->element('genericElementsBS5/Badges/object_relation', [
                            'relation' => $attr['object_relation'] ?? '',
                        ]) ?>
                    </div>
                </td>

                <!-- Type -->
                <td>
                    <?php echo $this->element(
                        'genericElementsBS5/Badges/type',
                        ['type' => $attr['type'] ?? '']
                    ); ?>
                </td>

                <!-- Tags -->
                <td>
                    <?php echo $this->element(
                        'genericElementsBS5/IndexTable/Fields/tag_list',
                        [
                            'row'   => $attr,
                            'field' => [
                                'data_path'       => 'AttributeTag',
                                'add_tag'         => $canTag,
                                'add_tag_url'     => $baseurl . '/attributes/editAttributeTags/%id%',
                                'add_tag_id_path' => 'id',
                                'add_relationship_url' => $baseurl
                                    . '/attributes/editAttributeTagRelationships/%id%',
                            ],
                        ]
                    ); ?>
                </td>


                <!-- Galaxies -->
                <td>
                    <?php echo $this->element(
                        'genericElementsBS5/IndexTable/Fields/galaxy',
                        [
                            'row'   => $attr,
                            'field' => [
                                'data_path'          => 'Galaxy',
                                'add_galaxy'         => $canTag,
                                'add_galaxy_url'     => $baseurl . '/attributes/editAttributeGalaxies/%id%',
                                'add_galaxy_id_path' => 'id',
                                'add_galaxy_relationship_url' => $baseurl
                                    . '/attributes/editAttributeGalaxyRelationships/%id%',
                            ],
                        ]
                    ); ?>
                </td>

                <!-- IDS (interactive via ids.ctp) -->
                <td class="text-center">
                    <?php echo $this->element(
                        'genericElementsBS5/IndexTable/Fields/ids',
                        [
                            'row'   => $attr,
                            'field' => ['data_path' => 'to_ids', 'readonly' => $readonly],
                        ]
                    ); ?>
                </td>

                <!-- Correlate (interactive via correlate.ctp) -->
                <td class="text-center">
                    <?php echo $this->element(
                        'genericElementsBS5/IndexTable/Fields/correlate',
                        [
                            'row'   => $attr,
                            'field' => ['data_path' => 'disable_correlation', 'readonly' => $readonly],
                        ]
                    ); ?>
                </td>

                <!-- Related Events -->
                <td>
                    <?php echo $this->element(
                        'genericElementsBS5/IndexTable/Fields/relatedEvents',
                        [
                            'row'   => $attr,
                            'field' => [],
                        ]
                    ); ?>
                </td>

                <!-- Feed Hits -->
                <td>
                    <?php echo $this->element(
                        'genericElementsBS5/IndexTable/Fields/feedHits',
                        [
                            'row'   => ['Attribute' => $attr],
                            'field' => [],
                        ]
                    ); ?>
                </td>

                <!-- Sightings -->
                <td>
                    <?php echo $this->element(
                        'genericElementsBS5/IndexTable/Fields/sightings',
                        [
                            'row'   => $attr,
                            'field' => [
                                'sightings' => [
                                    'data' => [],
                                    'csv'  => [],
                                ],
                            ],
                        ]
                    ); ?>
                </td>

                <!-- Analyst data -->
                <td>
                    <?= $this->element(
                        'genericElementsBS5/IndexTable/Fields/analyst_data_badges',
                        [
                            'row'   => $attr,
                            'field' => [
                                'note_path'         => 'Note',
                                'opinion_path'      => 'Opinion',
                                'relationship_path' => 'Relationship',
                                'uuid_path'         => 'uuid',
                                'object_type'       => 'Attribute',
                            ],
                        ]
                    ) ?>
                </td>

                <?php if (!$readonly): ?>
                <!-- Actions (3-dots dropdown) -->
                <td class="pe-3">
                    <div class="d-inline-flex align-items-center
                                checkbox-actions-wrapper
                                checkbox-index">
                        <?= $this->element('Objects/attribute_actions', [
                            'attr' => $attr,
                            'canEdit' => $canEdit,
                            'enrichmentEnabled' => $enrichmentEnabled,
                            'cortexEnabled' => $cortexEnabled,
                            'showView' => false,
                        ]) ?>
                    </div>
                </td>
                <?php endif; ?>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php else: ?>
    <p class="text-muted small fst-italic px-3 py-2 mb-0">
        <i class="fas fa-info-circle me-1"></i>
        <?= __('No visible attributes.') ?>
    </p>
<?php endif; ?>
