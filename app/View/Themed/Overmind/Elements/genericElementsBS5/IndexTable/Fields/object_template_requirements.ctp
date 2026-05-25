<?php
$data = Hash::extract($row, $field['data_path']);

if (!empty($data)): ?>
    <div class="requirements-wrapper">
        <?php foreach ($data as $group => $requirements): ?>
            <div class="requirement-group mb-3">
                <div class="d-flex align-items-center mb-1">
                    <span class="badge bg-secondary-subtle text-primary border border-secondary-subtle fw-bold text-uppercase" style="font-size: 0.75rem;">
                        <?= h($group) ?>
                    </span>
                </div>

                <div class="requirement-list ps-2 border-start border-2 border-light-subtle">
                    <?php foreach ($requirements as $requirement): ?>
                        <div class="d-flex align-items-baseline gap-2 mb-1">
                            <i class="fas fa-check-circle text-primary" style="font-size: 0.8rem;"></i>
                            <span class="text-muted small">
                                <?= h($requirement) ?>
                            </span>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
<?php endif; ?>