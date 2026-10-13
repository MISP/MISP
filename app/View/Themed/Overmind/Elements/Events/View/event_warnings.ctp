<?php
if (empty($eventWarnings)) {
    return;
}
$total = array_sum(array_map('count', $eventWarnings));
?>
<div class="card shadow-sm mb-3 ev-warnings-card" id="event-warnings-card">
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center ev-warnings-tile">
                <i class="fas fa-triangle-exclamation"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Event warnings') ?></div>
                <div class="small text-muted mt-1"><?= __n('%s thing to review', '%s things to review', $total, $total) ?></div>
            </div>
        </div>
    </div>
    <ul class="list-unstyled mb-0 ev-warnings-list">
        <?php foreach ($eventWarnings as $category => $messages): ?>
            <?php foreach (array_unique($messages) as $message): ?>
                <li>
                    <span class="ev-warnings-category"><?= h($category) ?></span>
                    <span class="ev-warnings-text"><?= h($message) ?></span>
                </li>
            <?php endforeach; ?>
        <?php endforeach; ?>
    </ul>
</div>
