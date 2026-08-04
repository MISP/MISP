<?php if (!empty($api_info['description'])): ?>
    <div class="d-flex align-items-center justify-content-between mb-2">
        <h6 class="mb-0 fw-bold text-primary">
            <?= __('Description') ?>
        </h6>
    </div>
    <p class="text-muted small mb-3">
        <?= h($api_info['description']) ?>
    </p>

    <?php
        $operationId = null;
        if (!empty($api_info['operationId'])) {
            $operationId = $api_info['operationId'];
        } else {
            echo '<div class="text-muted small alert alert-warning" role="alert">';
            echo __('OpenAPI documentation is not available for this endpoint');
            echo '</div>';
        }

        $openapiUrl = $baseurl . '/api/openapi#operation/' . $operationId;
    ?>

    <?php if (!empty($operationId)): ?>
        <a href="<?= h($openapiUrl) ?>"
            target="_blank"
            class="btn btn-sm btn-outline-primary w-100">
            <i class="fas fa-book-open me-1"></i>
            <?= __('View in OpenAPI documentation') ?>
        </a>
    <?php endif; ?>

<?php endif; ?>