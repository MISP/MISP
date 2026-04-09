
<?php
/**
 * Params:
 * - 'title' => string
 * - 'content' => string (HTML)
 * - 'icon' => string (optional)
 * - 'id' => string (optional)
 * - 'collapsed' => bool (optional)
 */

$collapseId = !empty($id) ? h($id) : 'category-' . uniqid();

$isCollapsed = $collapsed ?? true;
$showClass = !$isCollapsed ? 'show' : '';
$ariaExpanded = !$isCollapsed ? 'true' : 'false';
$headerClass = $isCollapsed ? 'collapsed' : '';
?>

<div class="card shadow-sm border-0 category-card hover-border-primary">
    <div class="category-container border-start border-4 border-secondary transition-border">
        <!-- HEADER -->
        <div class="card-header d-flex justify-content-between align-items-center <?= $headerClass ?>"
            data-bs-toggle="collapse"
            data-bs-target="#<?= $collapseId ?>"
            aria-expanded="<?= $ariaExpanded ?>"
            aria-controls="<?= $collapseId ?>"
            style="cursor: pointer;">

            <div class="d-flex align-items-center gap-2 p-1">

                <?php if (!empty($icon)): ?>
                    <i class="fas fa-<?= h($icon) ?> text-primary"></i>
                <?php endif; ?>

                <span class="fw-semibold">
                    <?= h($title) ?>
                </span>

            </div>

        </div>
    </div>

    <!-- BODY -->
    <div id="<?= $collapseId ?>" class="collapse <?= $showClass ?>">
        <div class="d-flex flex-column ps-4">

            <?= $content ?>

        </div>
    </div>
</div>