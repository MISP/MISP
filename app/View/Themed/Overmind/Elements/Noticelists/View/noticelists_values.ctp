<?php
$entries = $data['Noticelist']['NoticelistEntry'] ?? [];
?>

<div class="card mb-3 shadow-sm">
    <div class="card-body p-0">
        <?php if (empty($entries)): ?>
            <div class="p-2 text-muted small">
                <?= __('No values available.') ?>
            </div>
        <?php else: ?>

            <!-- HEADER -->
            <div class="border-bottom px-3 py-2 bg-light">
                <div class="row g-2 small text-uppercase fw-bold text-muted">
                    <div class="col-auto">ID</div>
                    <div class="col-md-1"><?= __('Scope') ?></div>
                    <div class="col-md-2"><?= __('Field') ?></div>
                    <div class="col-md-2"><?= __('Value') ?></div>
                    <div class="col-md-2"><?= __('Tags') ?></div>
                    <div class="col"><?= __('Messages') ?></div>
                </div>
            </div>

            <!-- LINES -->
            <?php foreach ($entries as $entry): ?>
                <?php
                    $dataEntry = $entry['data'] ?? [];
                    $scopes = $dataEntry['scope'] ?? [];
                    $fields = $dataEntry['field'] ?? [];
                    $values = $dataEntry['value'] ?? [];
                    $tags = $dataEntry['tags'] ?? [];
                    $messages = $dataEntry['message'] ?? [];
                ?>

                <div class="border-bottom px-3 py-2">
                    <div class="row g-2 align-items-start small">

                        <div class="col-auto fw-semibold text-muted">
                            #<?= h($entry['id']) ?>
                        </div>

                        <div class="col-md-1 d-flex flex-wrap gap-1">
                            <?php foreach ($scopes as $s): ?>
                                <span class="badge border text-dark bg-light">
                                    <?= h($s) ?>
                                </span>
                            <?php endforeach; ?>
                        </div>

                        <div class="col-md-2 d-flex flex-wrap gap-1">
                            <?php foreach ($fields as $f): ?>
                                <span class="badge bg-info-subtle text-dark border">
                                    <?= h($f) ?>
                                </span>
                            <?php endforeach; ?>
                        </div>

                        <div class="col-md-2 d-flex flex-wrap gap-1">
                            <?php foreach ($values as $v): ?>
                                <span class="badge bg-primary-subtle text-primary border">
                                    <?= h($v) ?>
                                </span>
                            <?php endforeach; ?>
                        </div>

                        <div class="col-md-2 d-flex flex-wrap gap-1">
                            <?php foreach ($tags as $t): ?>
                                <span class="badge bg-dark-subtle text-dark border">
                                    <?= h($t) ?>
                                </span>
                            <?php endforeach; ?>
                        </div>

                        <div class="col">
                            <?php if (!empty($messages)): ?>
                                <ul class="mb-0 ps-3">
                                    <?php foreach ($messages as $m): ?>
                                        <li class="small text-muted">
                                            <?= h($m) ?>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                            <?php else: ?>
                                <div class="text-muted fst-italic small">
                                    —
                                </div>
                            <?php endif; ?>
                        </div>

                    </div>
                </div>
            <?php endforeach; ?>

        <?php endif; ?>
    </div>
</div>