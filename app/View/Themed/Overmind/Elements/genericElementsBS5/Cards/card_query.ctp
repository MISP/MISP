<?php
$method = strtoupper($method ?? 'GET');
$title = $title ?? '';
$url = $url ?? '#';
$favorite = $favorite ?? false;
$status = (int) $status ?? 0;

// Color for HTTP method
$methodClass = [
    'GET' => 'bg-success-subtle text-success',
    'POST' => 'bg-primary-subtle text-primary',
    'PUT' => 'bg-warning-subtle text-warning',
    'DELETE' => 'bg-danger-subtle text-danger',
][$method] ?? 'bg-secondary-subtle text-secondary';

// Color for status code
$statusClass = null;
if ($status !== null) {
    if ($status >= 200 && $status < 300) {
        $statusClass = 'text-success';
    } elseif ($status >= 400 && $status < 500) {
        $statusClass = 'text-danger';
    }
}

$onClickAction = $onClickAction ?? 'applyTemplate(this)';
$onMouseEnterAction = $status == 0 ? 'handleQueryHover(this)' : '';
$onMouseLeaveAction = $status == 0 ? 'leaveQueryHover()' : '';
$id = $id ?? null;
$payloadAttr = isset($payload) ? 'data-payload="' . $payload . '"' : '';
?>

<div class="card shadow-sm border-0 hover-shadow transition bg-light query-card mb-2"
     style="cursor: pointer;"
     onclick="<?= $onClickAction ?>"
     data-url="<?= h($url) ?>"
     data-method="<?= h($method) ?>"
     <?= $payloadAttr ?>>
    <div class="query-container border-start border-4 border-secondary transition-border">
        <div class="card-body d-flex flex-column gap-2">
            <div class="d-flex justify-content-between align-items-start">
                <div class="d-flex align-items-center gap-2">
                    <span class="badge <?= $methodClass ?> rounded-pill px-3 py-2 fw-semibold">
                        <?= h($method) ?>
                    </span>
                    <span class="fw-semibold text-dark">
                        <?= h($title) ?>
                    </span>
                </div>

                <div class="d-flex gap-2 align-items-center">
                    <?php if ($status !== 0): ?>
                            <?php if ($favorite): ?>
                                <i class="fas fa-star text-warning"></i>
                            <?php endif; ?>
                            <button class="btn btn-link text-danger p-0 shadow-none hover-scale" 
                                    onclick="event.stopPropagation(); deleteBookmark(<?= $id ?>, this.closest('.query-card'))">
                                <i class="fas fa-trash-alt"></i>
                            </button>
                    <?php else: ?>
                        <button class="btn btn-link text-primary p-0 shadow-none hover-scale"
                                onclick="event.stopPropagation(); showQueryInfo(this)"
                                onmouseenter="<?= $onMouseEnterAction ?>"
                                onmouseleave="<?= $onMouseLeaveAction ?>">
                            <i class="fas fa-circle-info"></i>
                        </button>
                    <?php endif; ?>
                </div>
            </div>

            <div class="small text-muted text-truncate">
                <?= h($url) ?>
            </div>

            <!-- Status -->
            <div class="d-flex justify-content-between align-items-center mt-1">
                <?php if ($status !== 0): ?>
                    <span class="small fw-semibold <?= $statusClass ?>">
                        Status: <?= h($status) ?>
                    </span>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>