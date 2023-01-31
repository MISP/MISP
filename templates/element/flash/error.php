<?php

/**
 * @var \App\View\AppView $this
 * @var array $params
 * @var string $message
 */
if (!isset($params['escape']) || $params['escape'] !== false) {
    $message = h($message);
}
?>
<?php if (!empty($params['toast'])) : ?>
    <script>
        $(document).ready(function() {
            UI.toast({
                variant: 'danger',
                titleHtml: '<?= $message ?>'
            })
        })
    </script>
<?php else : ?>
    <div class="alert alert-danger alert-dismissible fade show" role="alert">
        <?= $message ?>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close">
        </button>
    </div>
<?php endif; ?>