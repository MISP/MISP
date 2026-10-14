<?php
/*
 * The notices, each read as a rule: on <scope>, when <field> is one of
 * <values>, show <message> and suggest <tags>.
 */
$entries = $data['Noticelist']['NoticelistEntry'] ?? [];

$chips = function (array $items, $class) {
    $out = '';
    foreach ($items as $item) {
        $out .= '<span class="badge rounded-pill fw-normal ' . $class . '">' . h($item) . '</span>';
    }
    return $out;
};
?>
<div class="card mb-3 shadow-sm">
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center bg-primary-subtle text-primary"
                 style="width:36px;height:36px;">
                <i class="fas fa-bullhorn"></i>
            </div>
            <div>
                <div class="fw-bold lh-1"><?= __('Notices') ?></div>
                <div class="small text-muted mt-1">
                    <?= h(__n('%s rule', '%s rules', count($entries), count($entries))) ?>
                </div>
            </div>
        </div>
    </div>

    <?php if (empty($entries)): ?>
        <div class="card-body text-center text-body-secondary small py-4">
            <i class="fas fa-bullhorn me-1 opacity-50"></i><?= __('This noticelist defines no notice.') ?>
        </div>
    <?php else: ?>
        <ul class="list-group list-group-flush">
            <?php foreach ($entries as $entry): ?>
                <?php
                $rule = $entry['data'] ?? [];
                $messages = $rule['message'] ?? [];
                if (!is_array($messages)) {
                    $messages = ['' => $messages];
                }
                ?>
                <li class="list-group-item py-3 px-3 d-flex flex-column gap-2">
                    <div class="d-flex flex-wrap align-items-center gap-1 small">
                        <span class="text-body-secondary"><?= __('On') ?></span>
                        <?= $chips((array)($rule['scope'] ?? []), 'border bg-body-tertiary text-body-emphasis') ?>
                        <span class="text-body-secondary ms-1"><?= __('when') ?></span>
                        <?= $chips((array)($rule['field'] ?? []), 'border bg-body-tertiary text-body-emphasis font-monospace') ?>
                        <span class="text-body-secondary ms-1"><?= __('is one of') ?></span>
                        <?= $chips((array)($rule['value'] ?? []), 'bg-primary-subtle text-primary-emphasis border border-primary-subtle') ?>
                    </div>
                    <?php foreach ($messages as $lang => $message): ?>
                        <div class="d-flex gap-2 border-start border-3 border-primary rounded-end px-3 py-2 bg-primary-subtle bg-opacity-25">
                            <?php if (is_string($lang) && $lang !== ''): ?>
                                <span class="badge rounded-pill border bg-body text-body-secondary fw-normal text-uppercase align-self-start"><?= h($lang) ?></span>
                            <?php endif; ?>
                            <span class="small text-break"><?= h($message) ?></span>
                        </div>
                    <?php endforeach; ?>
                    <?php if (!empty($rule['tags'])): ?>
                        <div class="d-flex flex-wrap align-items-center gap-1 small">
                            <span class="text-body-secondary"><i class="fas fa-tags me-1 opacity-50"></i><?= __('Suggested tags') ?></span>
                            <?= $chips((array)$rule['tags'], 'border bg-body text-body-secondary font-monospace') ?>
                        </div>
                    <?php endif; ?>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</div>
