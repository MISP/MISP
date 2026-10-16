<?php
/**
 * An object's attributes as a list: relation, flags, value, tags and galaxies,
 * and the attribute's action menu. Shared by the object card and the objects
 * index's expanded row.
 *
 * Parameters:
 *   attrs              array  the object's attributes, as the Objects tab loads them
 *   canEdit            bool   may modify the object's event
 *   canTag             bool   may tag the object's attributes
 *   showActions        bool   draw each attribute's action menu (default true)
 *   readonly           bool   report the IDS flag without its toggle and leave
 *                             out correlation, for a page that has not loaded
 *                             the attribute's event
 *   enrichmentEnabled  bool   Plugin.Enrichment_services_enable
 *   cortexEnabled      bool   Plugin.Cortex_services_enable
 *
 * Read from the view: $baseurl, $me.
 */
$objCanEdit = !empty($canEdit);
$objCanTag = !empty($canTag);
$showActions = $showActions ?? true;
$readonly = !empty($readonly);
?>
<?php if (!empty($attrs)): ?>
    <div class="list-group list-group-flush border-top">
        <?php foreach ($attrs as $attr): ?>
            <?php
                $relation = (string)($attr['object_relation'] ?? '');
                $label = $relation !== ''
                    ? $relation : (string)($attr['type'] ?? '');
            ?>
            <div class="list-group-item px-3 py-2<?= !empty($attr['deleted']) ? ' opacity-50' : '' ?>">
                <div class="d-flex align-items-start gap-2">
                    <div class="flex-grow-1" style="min-width:0;">
                        <div class="d-flex align-items-baseline gap-2">
                            <span class="text-uppercase text-secondary fw-semibold text-truncate"
                                  style="font-size:.65rem;letter-spacing:.04em;"
                                  title="<?= h($label) ?>">
                                <?= h($label) ?>
                            </span>
                            <span class="d-inline-flex align-items-center gap-2 flex-shrink-0">
                                <?php if (!empty($attr['deleted'])): ?>
                                    <i class="fas fa-trash text-danger" style="font-size:.7rem;"
                                       title="<?= h(__('Deleted')) ?>"></i>
                                <?php endif; ?>
                                <?= $this->element(
                                    'genericElementsBS5/IndexTable/Fields/ids',
                                    ['row' => $attr, 'field' => ['data_path' => 'to_ids', 'readonly' => $readonly]]
                                ) ?>
                                <?php if (!$readonly): ?>
                                <?= $this->element(
                                    'genericElementsBS5/IndexTable/Fields/correlate',
                                    ['row' => $attr, 'field' => ['data_path' => 'disable_correlation']]
                                ) ?>
                                <?php endif; ?>
                                <?= $this->element('Attributes/value_flags', [
                                    'attribute' => $attr, 'small' => true,
                                ]) ?>
                            </span>
                        </div>

                        <div class="font-monospace small text-break">
                            <?= $this->element(
                                'genericElementsBS5/IndexTable/Fields/attribute_value',
                                [
                                    'row'      => ['Attribute' => $attr],
                                    'field'    => ['data_path' => 'Attribute'],
                                    'viewMode' => 'card',
                                    'showFlags' => false,
                                ]
                            ) ?>
                        </div>

                        <?php
                        $chips = trim(
                            $this->element(
                                'genericElementsBS5/IndexTable/Fields/tag_list',
                                [
                                    'row' => $attr,
                                    'field' => [
                                        'data_path'       => 'AttributeTag',
                                        'add_tag'         => $objCanTag,
                                        'add_tag_url'     => $baseurl . '/attributes/editAttributeTags/%id%',
                                        'add_tag_id_path' => 'id',
                                        'add_relationship_url' => $baseurl
                                            . '/attributes/editAttributeTagRelationships/%id%',
                                    ],
                                ]
                            )
                            . $this->element(
                                'genericElementsBS5/IndexTable/Fields/galaxy',
                                [
                                    'row' => $attr,
                                    'field' => [
                                        'data_path'          => 'Galaxy',
                                        'add_galaxy'         => $objCanTag,
                                        'add_galaxy_url'     => $baseurl . '/attributes/editAttributeGalaxies/%id%',
                                        'add_galaxy_id_path' => 'id',
                                        'add_galaxy_relationship_url' => $baseurl
                                            . '/attributes/editAttributeGalaxyRelationships/%id%',
                                    ],
                                ]
                            )
                        );
                        ?>
                        <?php if ($chips !== ''): ?>
                            <div class="d-flex flex-wrap align-items-center gap-1 mt-1">
                                <?= $chips ?>
                            </div>
                        <?php endif; ?>
                    </div>

                    <?php if ($showActions): ?>
                    <div class="flex-shrink-0">
                        <?= $this->element('Objects/attribute_actions', [
                            'attr' => $attr,
                            'canEdit' => $objCanEdit,
                            'enrichmentEnabled' => $enrichmentEnabled ?? false,
                            'cortexEnabled' => $cortexEnabled ?? false,
                        ]) ?>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
<?php else: ?>
    <div class="border-top py-3 px-3 text-center text-muted small fst-italic">
        <?= __('No attributes to display for this object.') ?>
    </div>
<?php endif; ?>
