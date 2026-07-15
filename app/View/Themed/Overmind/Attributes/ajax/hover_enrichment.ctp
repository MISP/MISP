<?php

$formatValue = function (array $attribute) {
    if (($attribute['type'] ?? '') === 'link') {
        return '<a href="' . h($attribute['value']) . '" rel="noreferrer noopener" target="_blank">' . h($attribute['value']) . '</a>';
    }
    return h($attribute['value']);
};
?>
<div class="p-3" style="min-width:16rem;">
<?php if (empty($results)): ?>
    <div class="text-muted small d-flex align-items-center gap-2">
        <i class="fas fa-circle-info"></i><?= __('No hover enrichment available for this attribute.') ?>
    </div>
<?php else: ?>
    <?php foreach ($results as $enrichment_type => $enrichment_values): ?>
        <div class="mb-2">
            <div class="text-enrichment text-uppercase fw-semibold mb-1" style="font-size:.62rem; letter-spacing:.08em;">
                <i class="fas fa-wand-magic-sparkles me-1"></i><?= h(Inflector::humanize($enrichment_type)) ?>
            </div>

            <?php if (isset($enrichment_values['error'])): ?>
                <div class="text-danger small"><?= __('Error: %s', h($enrichment_values['error'])) ?></div>
            <?php elseif (empty($enrichment_values)): ?>
                <div class="text-muted small fst-italic"><?= __('Empty results') ?></div>
            <?php else: ?>

                <?php if (!empty($enrichment_values['Object'])): ?>
                    <?php foreach ($enrichment_values['Object'] as $object): ?>
                        <div class="fw-semibold small mb-1"><?= __('Object: %s', h($object['name'])) ?></div>
                        <table class="table table-sm mb-2">
                            <tbody>
                            <?php foreach ($object['Attribute'] as $object_attribute): ?>
                                <tr>
                                    <th class="text-muted fw-normal" style="width:11em;"><?= h($object_attribute['object_relation']) ?></th>
                                    <td class="font-monospace small"><?= $formatValue($object_attribute) ?></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endforeach; ?>
                    <?php unset($enrichment_values['Object']); ?>
                <?php endif; ?>

                <?php if (!empty($enrichment_values['Attribute'])): ?>
                    <div class="fw-semibold small mb-1"><?= __('Attributes') ?></div>
                    <table class="table table-sm mb-2">
                        <tbody>
                        <?php foreach ($enrichment_values['Attribute'] as $attribute): ?>
                            <tr>
                                <th class="text-muted fw-normal" style="width:11em;"><?= h($attribute['type']) ?></th>
                                <td class="font-monospace small"><?= $formatValue($attribute) ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php unset($enrichment_values['Attribute']); ?>
                <?php endif; ?>

                <?php foreach ($enrichment_values as $attributes): ?>
                    <?php foreach ($attributes as $attribute): ?>
                        <div class="small py-1" style="word-break:break-word;">
                            <?php if (is_array($attribute)): ?>
                                <?php foreach ($attribute as $attribute_name => $attribute_value): ?>
                                    <?php if (!is_numeric($attribute_name)): ?>
                                        <strong><?= h($attribute_name) ?>:</strong>
                                    <?php endif; ?>
                                    <?= ' ' . h($attribute_value) ?>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <?= h($attribute) ?>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                <?php endforeach; ?>

            <?php endif; ?>
        </div>
    <?php endforeach; ?>
<?php endif; ?>
</div>
