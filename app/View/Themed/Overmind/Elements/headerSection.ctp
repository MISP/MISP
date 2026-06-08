<?php
$breadcrumb = '';
if (!empty($currentController)) {
    $controllerUrl = $this->Html->url('/' . $currentController);
    $breadcrumb = '<a href="' . $controllerUrl . '" '
        . 'class="text-muted text-decoration-none breadcrumb-controller-link">'
        . ucfirst(h($currentController)) . '</a>';
    if (!empty($currentAction)) {
        $breadcrumb .= ' > ' . ucfirst(h($currentAction));
    }
}
$title = isset($headerTitle)
    ? h($headerTitle)
    : (isset($currentController) ? ucfirst(h($currentController)) : '');

$paginatorCount = null;
try {
    $paginatorParams = $this->Paginator->params();
    if (isset($paginatorParams['count'])) {
        $paginatorCount = (int)$paginatorParams['count'];
    }
} catch (Exception $e) {
    // no paginator on this page
}
$totalCount = $headerCount ?? $paginatorCount;
?>

<div class="container-fluid py-3">

    <div class="d-flex justify-content-between align-items-center">

        <div class="d-flex flex-column">
            <?php if ($breadcrumb): ?>
                <span class="text-muted text-uppercase fw-semibold mb-1"
                        style="font-size:0.68rem; letter-spacing:0.07em;">
                    <?= $breadcrumb ?>
                </span>
            <?php endif; ?>
            <div class="d-flex align-items-center gap-2 ">
                <h1 class="mb-0 fw-bold lh-1 d-flex" style="font-size:2rem;">
                    <?= $title ?>
                </h1>
                <?php if ($totalCount !== null): ?>
                    <span class="badge rounded-pill bg-primary fw-semibold px-3">
                        <?= number_format($totalCount) ?>
                    </span>
                <?php endif; ?>
            </div>

            <?php if (!empty($headerDescription)): ?>
                <p class="text-muted text-center" style="font-size:0.85rem;">
                    <?= $headerDescription ?>
                </p>
            <?php else: //small space, just to match the size of the Flash messages ?>
                <div style="height: 0.5rem;"></div>
            <?php endif; ?>
        </div>

        <?php if (!empty($headerActions)): ?>
            <div class="d-flex gap-2 align-items-center flex-wrap">
                <?php foreach ($headerActions as $action): ?>

                    <?php if ($action['type'] === 'navigate'): ?>
                        <a href="<?= h($action['url']) ?>"
                            <?php if (!empty($action['onClick'])): ?>
                                onclick="event.preventDefault(); <?= h($action['onClick']) ?>();"
                            <?php endif; ?>
                            <?php if (!empty($action['id'])): ?>
                                id="<?= h($action['id']) ?>"
                            <?php endif; ?>
                            class="btn btn-outline-dark fw-semibold d-flex align-items-center gap-2">
                            <i class="fas fa-<?= h($action['icon']) ?>"></i>
                            <?= h($action['label']) ?>
                        </a>

                    <?php elseif ($action['type'] === 'action'): ?>
                        <?php
                            echo $this->Form->postLink(
                                '<i class="fas fa-' . h($action['icon']) . '"></i> '
                                    . h($action['label']),
                                $action['url'],
                                [
                                    'class' => 'btn btn-outline-primary fw-semibold'
                                        . ' d-flex align-items-center gap-2',
                                    'escape' => false,
                                ]
                            );
                        ?>

                    <?php elseif ($action['type'] === 'modal'): ?>
                        <a href="<?= h($action['url']) ?>"
                            onclick="event.preventDefault(); openModal('<?= h($action['url']) ?>');"
                            class="btn btn-primary fw-semibold d-flex align-items-center gap-2">
                            <i class="fas fa-<?= h($action['icon']) ?>"></i>
                            <?= h($action['label']) ?>
                        </a>

                    <?php endif; ?>

                <?php endforeach; ?>
            </div>
        <?php endif; ?>

    </div>

    <?php if (!empty($headerStats)): ?>
        <div class="row g-3 mt-2">
            <?php foreach ($headerStats as $stat): ?>
                <?php
                    $color = h($stat['color'] ?? 'secondary');
                    $subtitleColor = h($stat['subtitleColor'] ?? 'muted');
                ?>
                <div class="col-12 col-sm-6 col-xl-3">
                    <div class="card h-100 border-0 border-start border-4
                                border-<?= $color ?>"
                            style="background:var(--bs-body-secondary-bg,
                                var(--bs-secondary-bg));">
                        <div class="card-body p-3 d-flex
                                    justify-content-between align-items-start">
                            <div>
                                <div class="text-uppercase fw-semibold text-secondary mb-1"
                                        style="font-size:0.65rem; letter-spacing:0.08em;">
                                    <?= h($stat['label']) ?>
                                </div>
                                <div class="fw-bold lh-1 mb-1"
                                        style="font-size:1.75rem;">
                                    <?= h($stat['value']) ?>
                                </div>
                                <?php if (!empty($stat['subtitle'])): ?>
                                    <div class="text-<?= $subtitleColor ?>"
                                            style="font-size:0.75rem;">
                                        <?php if (!empty($stat['subtitleIcon'])): ?>
                                            <i class="fas fa-<?= h($stat['subtitleIcon']) ?> me-1"></i>
                                        <?php endif; ?>
                                        <?= h($stat['subtitle']) ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                            <?php if (!empty($stat['icon'])): ?>
                                <i class="fas fa-<?= h($stat['icon']) ?> text-<?= $color ?> opacity-25 fa-xl"></i>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

</div>

