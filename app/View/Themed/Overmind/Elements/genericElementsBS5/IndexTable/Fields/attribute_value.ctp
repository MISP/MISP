<?php
$attribute = Hash::extract($row, $field['data_path']);

if (empty($attribute)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

if (isset($row['Attribute'])) {
    $row = $row['Attribute'];
}

$proposals         = !empty($attribute['ShadowAttribute']) ? $attribute['ShadowAttribute'] : [];
$isProposalRow     = !empty($attribute['is_proposal']);
$canModifyProposal = !empty($isSiteAdmin) || !empty($mayModify);

// Hover enrichment: when enabled, the value queries the hover modules and shows a floating popover
$hoverEnrichId = (Configure::read('Plugin.Enrichment_hover_enable') && !empty($me['Role']['perm_add'])
    && empty($isProposalRow) && !empty($attribute['id']))
    ? (int)$attribute['id'] : null;
$hoverClickOnly = (bool)Configure::read('Plugin.Enrichment_hover_popover_only');


$renderPropActions = function ($pid) use ($canModifyProposal, $baseurl) {
    if (!$canModifyProposal) {
        return '';
    }
    $pid = (int)$pid;
    $accept = '<button type="button" class="btn btn-sm btn-success py-0 px-2" title="'
        . h(__('Accept proposal')) . '" onclick="acceptProposal(' . $pid . ')">'
        . '<i class="fas fa-check"></i></button>';
    $discard = '<button type="button" class="btn btn-sm btn-outline-danger py-0 px-2" title="'
        . h(__('Discard proposal')) . '" onclick="openModal(\'' . $baseurl . '/shadow_attributes/discard/'
        . $pid . '\', \'sm\')"><i class="fas fa-times"></i></button>';
    return '<span class="d-inline-flex gap-1 ms-2 align-items-center">' . $accept . $discard . '</span>';
};
?>

<div class="d-flex flex-column gap-1">
    <div class="d-flex align-items-baseline gap-2 mb-0 flex-wrap">
        <?php if (!$isCard) {
                echo $this->element(
                    '/genericElementsBS5/IndexTable/Fields/distribution',
                    [
                        'row' => $row,
                        'field' => [
                            'data_path' => 'distribution',
                            'display' =>'short'
                        ]
                    ]
                );
            }
        ?>

        <?php if ($isProposalRow): ?>
            <span class="badge bg-warning text-dark text-uppercase" style="font-size:.6rem; letter-spacing:.05em;">
                <i class="fas fa-comment-dots me-1"></i><?= __('Proposal') ?>
            </span>
        <?php endif; ?>

        <?php if ($hoverEnrichId && !$hoverClickOnly): ?>
            <p class="mb-0 om-hover-enrichment"
               data-hover-enrichment-id="<?= $hoverEnrichId ?>"
               data-hover-trigger="hover"
               style="cursor:help;"
               title="<?= __('Hover to look up enrichment') ?>">
                <?= h($attribute['value']); ?>
            </p>
        <?php elseif ($hoverEnrichId && $hoverClickOnly): ?>
            <p class="mb-0">
                <?= h($attribute['value']); ?>
                <i class="fas fa-magnifying-glass-plus text-muted ms-1 om-hover-enrichment"
                   role="button" tabindex="0"
                   data-hover-enrichment-id="<?= $hoverEnrichId ?>"
                   data-hover-trigger="click"
                   style="font-size:.8em; cursor:pointer;"
                   title="<?= __('Look up enrichment') ?>"></i>
            </p>
        <?php else: ?>
            <p class="mb-0">
                <?= h($attribute['value']); ?>
            </p>
        <?php endif; ?>

        <?php if ($isProposalRow): ?>
            <?php if (!empty($attribute['proposal_org_name'])): ?>
                <span class="text-muted small"><?= __('by %s', h($attribute['proposal_org_name'])) ?></span>
            <?php endif; ?>
            <?= $renderPropActions($attribute['proposal_id'] ?? $attribute['id']) ?>
        <?php endif; ?>
    </div>

    <!-- Show if it contains a comment -->
    <?php if (!empty($attribute['comment'])): ?>
        <div class="card card-link-item bg-light">
            <div class="card-body p-1">
                <i class="fa fa-comment"></i>
                <span><?= h($attribute['comment']) ?></span>
            </div>
        </div>
    <?php endif; ?>

    <!-- Pending proposals (edits / deletions) on this attribute -->
    <?php foreach ($proposals as $p): ?>
        <?php
        $isDelete = !empty($p['proposal_to_delete']);
        $org      = $p['org_name'] ?? ($p['org_id'] ?? '');
        ?>
        <div class="border-start border-warning border-3 ps-2 py-1 bg-light small d-flex align-items-center flex-wrap gap-2">
            <span class="badge bg-warning text-dark text-uppercase" style="font-size:.55rem; letter-spacing:.05em;">
                <i class="fas fa-comment-dots me-1"></i><?= $isDelete ? __('Deletion proposed') : __('Proposed change') ?>
            </span>
            <?php if ($isDelete): ?>
                <span class="text-danger"><i class="fas fa-trash me-1"></i><?= __('Remove this attribute') ?></span>
            <?php else: ?>
                <?php
                // Highlight (bold) the fields the proposal actually changes vs. the live attribute
                $diffs = [];
                if ((string)($p['category'] ?? '') !== (string)($attribute['category'] ?? '')) {
                    $diffs[] = [__('Category'), $attribute['category'] ?? '', $p['category'] ?? ''];
                }
                if ((string)($p['type'] ?? '') !== (string)($attribute['type'] ?? '')) {
                    $diffs[] = [__('Type'), $attribute['type'] ?? '', $p['type'] ?? ''];
                }
                if ((string)($p['value'] ?? '') !== (string)($attribute['value'] ?? '')) {
                    $diffs[] = [__('Value'), $attribute['value'] ?? '', $p['value'] ?? ''];
                }
                if ((string)($p['comment'] ?? '') !== (string)($attribute['comment'] ?? '')) {
                    $diffs[] = [__('Comment'), $attribute['comment'] ?? '', $p['comment'] ?? ''];
                }
                if ((int)($p['to_ids'] ?? 0) !== (int)($attribute['to_ids'] ?? 0)) {
                    $diffs[] = [__('IDS'), !empty($attribute['to_ids']) ? __('yes') : __('no'), !empty($p['to_ids']) ? __('yes') : __('no')];
                }
                ?>
                <?php if (empty($diffs)): ?>
                    <span class="fw-semibold"><?= h($p['value']) ?></span>
                <?php else: ?>
                    <?php foreach ($diffs as $d): ?>
                        <span class="d-inline-flex align-items-center gap-1">
                            <span class="text-muted"><?= h($d[0]) ?>:</span>
                            <?php if ($d[1] !== ''): ?>
                                <del class="text-muted"><?= h($d[1]) ?></del>
                                <i class="fas fa-arrow-right text-muted" style="font-size:.6rem;"></i>
                            <?php endif; ?>
                            <strong><?= h($d[2]) ?></strong>
                        </span>
                    <?php endforeach; ?>
                <?php endif; ?>
            <?php endif; ?>
            <span class="text-muted"><?= __('by %s', h($org)) ?></span>
            <?= $renderPropActions($p['id']) ?>
        </div>
    <?php endforeach; ?>

</div>