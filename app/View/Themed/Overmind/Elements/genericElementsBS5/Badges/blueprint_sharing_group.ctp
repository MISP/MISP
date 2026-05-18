<?php
/*
 * Expected:
 * $sgData (Array)
 * $blueprintId (int)
 * $full (bool) → Print label or just icon
 */

$sgData = isset($sgData) ? $sgData : null;
$blueprintId = isset($blueprintId) ? $blueprintId : null;
$full = $full ?? true;
?>

<div class="d-inline-flex align-items-center bg-white rounded-pill px-2 py-1 shadow-sm"  style="border: 1px solid #0e146d;">
    <i class="fas fa-share-alt me-2 ms-1" style="color: #0e146d;"></i>
    
    <a href="<?= $baseurl ?>/sharingGroups/view/<?= h($sgData['id']) ?>" 
       class="fw-bold text-dark text-decoration-none me-2" 
       title="<?= h($sgData['releasability'] ?? '') ?>"
       style="font-size: 0.85rem;">
        <?= sprintf('%s', h($sgData['name'])) ?>
    </a>

    <?php if ($isSiteAdmin): ?>
        <button type="button" 
                class="btn btn-link btn-sm text-danger p-0 me-1" 
                onclick="openModal('<?= $baseurl ?>/sharing_group_blueprints/detach/<?= h($blueprintId) ?>', 'md');"
                title="<?= __('Detach Sharing Group') ?>">
            <i class="fas fa-times-circle"></i>
        </button>
    <?php endif; ?>
</div>
