<?php
    $selectAllCheckbox = false;
    echo '<thead>';
    foreach ($fields as $k => $header) {
        if (!isset($header['requirement']) || $header['requirement']) {
            $header_data = '';
            if (!empty($header['icon'])) {
                $header['name'] = sprintf(
                    '<i class="fas fa-%s"></i> %s',
                    h($header['icon']),
                    empty($header['name']) ? '' : h($header['name'])
                );
            } else {
                if (!empty($header['name'])) {
                    $header['name'] = h($header['name']);
                }
            }
            if (!empty($header['sort'])) {
                if (!empty($header['name'])) {
                    $header_data = $paginator->sort($header['sort'], $header['name'], ['escape' => false]);
                } else {
                    $header_data = $paginator->sort($header['sort']);
                }
            } else {
                if (!empty($header['element']) && $header['element'] === 'selector') {
                    $selectAllCheckbox = true;
                    $header_data = sprintf(
                        '<input id="select_all" class="%s" type="checkbox" %s>',
                        empty($header['select_all_class']) ? 'select_all' : $header['select_all_class'],
                        empty($header['select_all_function']) ? 'onclick="toggleAllAttributeCheckboxes();"' : 'onclick="' . $header['select_all_function'] . '"'
                    );
                } else {
                    $header_data = $header['name'];
                }
            }
            $classes = [];
            if (!empty($header['sort'])) {
                $classes[] = 'pagination_link';
            }
            if (!empty($header['rotate_header'])) {
                $classes[] = 'rotate';
                $header_data = "<div><span>$header_data</span></div>";
            }

            echo sprintf(
                '<th%s%s>%s</th>',
                !empty($classes) ? ' class="' . implode(' ', $classes) .'"' : '',
                !empty($header['header_title']) ? ' title="' . h($header['header_title']) . '"' : '',
                $header_data
            );
        }
    }
    if ($actions) {
        echo sprintf(
            '<th class="actions">%s</th>',
            __('Actions')
        );
    }
    echo '</thead>';
?>
<?php if ($selectAllCheckbox): ?>
<script>
    $(function() {
        $('.select_attribute').add('#select_all').on('change', function() {
            if ($('.select_attribute:checked').length > 0) {
                $('.mass-select').show();
            } else {
                $('.mass-select').hide();
            }
        });
    });
</script>
<?php endif; ?>