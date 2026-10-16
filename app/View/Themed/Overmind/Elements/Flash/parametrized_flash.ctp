<?= $this->element('genericElementsBS5/toast', [
    'kind' => $params['variant'] ?? 'info',
    'title' => $params['toast_header'] ?? null,
    'message' => $params['toast_body'] ?? '',
]) ?>
