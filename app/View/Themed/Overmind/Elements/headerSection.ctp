<?php
$breadcrumb = '';
$unclickableControllers = ['pages'];
if (!empty($currentController)) {
    if ($currentController === 'galaxy_clusters') {
        $currentController = 'galaxies';
        $middle = 'clusters';
    }
    $controllerUrl = $this->Html->url('/' . $currentController);
    if ($currentController === 'users') {
        if (!empty($me['Role']['perm_site_admin'])) {
            $controllerUrl = $this->Html->url('/admin/' . $currentController);
        } else {
            $controllerUrl = $this->Html->url('#');
        }
    }
    if (in_array($currentController, $unclickableControllers)) {
        $controllerUrl = '#';
    }
    $breadcrumb = '<a href="' . $controllerUrl . '" '
        . 'class="text-muted text-decoration-none breadcrumb-controller-link">'
        . ucfirst(h($currentController)) . '</a>';
    if (!empty($currentAction)) {
        if (empty($middle)) {
            $breadcrumb .= ' > ' . ucfirst(h($currentAction));
        } else {
            $breadcrumb .= ' > ' . ucfirst(h($middle)) .  ' > ' . ucfirst(h($currentAction));
        }
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

// Compact count formatting (1,4K, ...)
// Count prefixed with "+" to denote an estimate.
$abbreviateCount = function ($num) {
    $num = (int)$num;
    if ($num < 1000) {
        return (string)$num;
    }
    foreach ([['T', 1e12], ['B', 1e9], ['M', 1e6], ['K', 1e3]] as [$suffix, $scale]) {
        if ($num >= $scale) {
            $v = floor($num / $scale * 10) / 10; // one decimal, truncated
            $s = rtrim(rtrim(number_format($v, 1, ',', ''), '0'), ',');
            return $s . $suffix;
        }
    }
    return (string)$num;
};

$countDisplay = null;
if (isset($headerCountText)) {
    $countDisplay = $headerCountText;
} elseif (isset($headerCountApprox)) {
    $n = $headerCount ?? $paginatorCount;
    if ($n !== null && $n < PHP_INT_MAX) {
        $countDisplay = ($headerCountApprox ? '+' : '') . $abbreviateCount($n);
    }
} elseif ($totalCount !== null && $totalCount < PHP_INT_MAX) {
    $countDisplay = number_format($totalCount, 0, ',', ' ');
}
?>

<div class="container-fluid py-3">

    <div class="d-flex justify-content-between align-items-center">

        <div class="d-flex flex-column align-items-start">
            <?php if ($breadcrumb): ?>
                <span class="text-muted text-uppercase fw-semibold mb-1"
                        style="font-size:0.68rem; letter-spacing:0.07em;">
                    <?= $breadcrumb ?>
                </span>
            <?php endif; ?>
            <div class="d-flex align-items-center gap-2 ">
                <h1 class="mb-0 fw-bold lh-1 d-flex" style="font-size:2rem; word-break:break-word; max-width:100%;">
                    <?= $title ?>
                </h1>
                <?php if ($countDisplay !== null): ?>
                    <span class="badge rounded-pill bg-primary fw-semibold px-3">
                        <?= h($countDisplay) ?>
                    </span>
                <?php endif; ?>
            </div>

            <?php if (!empty($headerDescription)): ?>
                <p class="text-muted mt-1" style="font-size:0.85rem;">
                    <?= $headerDescription ?>
                </p>
            <?php else: //small space, just to match the size of the Flash messages ?>
                <div style="height: 0.5rem;"></div>
            <?php endif; ?>
        </div>

        <?php if (!empty($headerActions)): ?>
            <div class="d-flex gap-2 align-items-center flex-wrap">
                <?php foreach ($headerActions as $action): ?>
                    <?php
                        $tabAttr = !empty($action['tab']) ? ' data-header-tab="' . h($action['tab']) . '"' : '';
                        $tabHidden = !empty($action['tab']) ? ' d-none' : '';
                    ?>

                    <?php if ($action['type'] === 'navigate'): ?>
                        <a href="<?= h($action['url']) ?>"<?= $tabAttr ?>
                            <?php if (!empty($action['onClick'])): ?>
                                onclick="event.preventDefault(); <?= h($action['onClick']) ?>();"
                            <?php endif; ?>
                            <?php if (!empty($action['id'])): ?>
                                id="<?= h($action['id']) ?>"
                            <?php endif; ?>
                            class="btn btn-outline-dark fw-semibold d-flex align-items-center gap-2<?= $tabHidden ?>">
                            <i class="fas fa-<?= h($action['icon']) ?>"></i>
                            <?= h($action['label']) ?>
                        </a>

                    <?php elseif ($action['type'] === 'action'): ?>
                        <?php
                            echo $this->Form->postLink(
                                '<i class="fas fa-' . h($action['icon']) . '"></i> '
                                    . h($action['label']),
                                $action['url'],
                                array_merge([
                                    'class' => 'btn btn-outline-primary fw-semibold'
                                        . ' d-flex align-items-center gap-2' . $tabHidden,
                                    'escape' => false,
                                ], !empty($action['tab']) ? ['data-header-tab' => $action['tab']] : []),
                                $action['confirm'] ?? false
                            );
                        ?>

                    <?php elseif ($action['type'] === 'modal'): ?>
                        <a href="<?= h($action['url']) ?>"<?= $tabAttr ?>
                            onclick="event.preventDefault(); openModal('<?= h($action['url']) ?>');"
                            class="btn btn-primary fw-semibold d-flex align-items-center gap-2<?= $tabHidden ?>">
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
                                <i class="fas fa-<?= h($stat['icon']) ?> text-<?= $color ?> opacity-25" style="font-size:1.25rem;"></i>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

</div>

