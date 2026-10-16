<?php
$iconStyle = !empty($small) ? ' style="font-size:.7rem;"' : '';

if (!empty($attribute['validationIssue'])):
    $title = __('Warning, this doesn\'t seem to be a legitimate %s value', strtoupper($attribute['type']));
?>
    <i class="fas fa-circle-exclamation text-danger" role="img" tabindex="0"<?= $iconStyle ?>
       title="<?= h($title) ?>" aria-label="<?= h($title) ?>"></i>
<?php
endif;

if (!empty($attribute['warnings'])):
    $categories = [
        'false_positive' => __('False positive'),
        'known' => __('Known identifier'),
    ];
    $content = '';
    foreach ($attribute['warnings'] as $warning) {
        $category = $warning['warninglist_category'] ?? '';
        $content .= '<div class="om-wl-hit">'
            . '<div class="fw-semibold">' . h($warning['warninglist_name'] ?? '') . '</div>'
            . '<div class="small text-muted">'
            . h(__('Matching entry: %s', $warning['match'] ?? $warning['value'] ?? ''))
            . ($category !== '' ? ' · ' . h($categories[$category] ?? $category) : '')
            . '</div>'
            . (!empty($warning['comment']) ? '<div class="small">' . h($warning['comment']) . '</div>' : '')
            . '</div>';
    }
    $label = __n('On %s warning list', 'On %s warning lists', count($attribute['warnings']), count($attribute['warnings']));
?>
    <i class="fas fa-exclamation-triangle text-warning om-lazy-popover" role="img" tabindex="0"<?= $iconStyle ?>
       aria-label="<?= h($label) ?>"
       data-bs-title="<?= h($label) ?>"
       data-bs-content="<?= h($content) ?>"
       data-bs-custom-class="om-wl-popover"></i>
<?php endif; ?>
