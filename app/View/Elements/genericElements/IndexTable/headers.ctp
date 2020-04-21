<?php
    $headersHtml = '';
    foreach ($fields as $k => $header) {
        if (!isset($header['requirement']) || $header['requirement']) {
            $header_data = '';
            if (!empty($header['sort'])) {
                if (!empty($header['name'])) {
                    $header_data = $paginator->sort($header['sort'], $header['name']);
                } else {
                    $header_data = $paginator->sort($header['sort']);
                }
                if (!empty($header['element']) && $header['element'] === 'extended_generic') {
                    $hideExtensionHtml = sprintf(
                        '<span style="font-size: x-small;" title="%s"><input id="show_extension" type="checkbox" style="margin-left: 0.5rem" checked><i class="%s"></i></span>',
                        __('Show extensions'),
                        sprintf('%s %s', $this->FontAwesome->findNamespace('code-branch'), 'fa-code-branch')
                    );
                    $header_data .= $hideExtensionHtml;
                }
            } else {
                if (!empty($header['element']) && $header['element'] === 'selector') {
                    $header_data = sprintf(
                        '<input id="select_all" class="%s" type="checkbox" %s>',
                        empty($header['select_all_class']) ? 'select_all' : $header['select_all_class'],
                        empty($header['select_all_function']) ? 'onclick="toggleAllAttributeCheckboxes();"' : 'onclick="' . $header['select_all_function'] . '"'
                    );
                } elseif (!empty($header['element']) && $header['element'] === 'extended_generic') {
                    $hideExtensionHtml = '<input id="hide_extension" type="checkbox" %s>';
                    $header_data = sprintf('%s %s', h($header['name']), $hideExtensionHtml);
                } else {
                    $header_data = h($header['name']);
                }

            }
            $headersHtml .= sprintf(
                '<th>%s</th>',
                $header_data
            );
        }
    }
    if ($actions) {
        $headersHtml .= sprintf(
            '<th class="actions">%s</th>',
            __('Actions')
        );
    }
    $thead = '<thead>';
    $thead .= $headersHtml;
    $thead .= '</thead>';
    echo $thead;
?>
<script type="text/javascript">
    $(document).ready(function() {
        $('.select_attribute').add('#select_all').on('change', function() {
            if ($('.select_attribute:checked').length > 0) {
                $('.mass-select').show();
            } else {
                $('.mass-select').hide();
            }
        });
        $('#show_extension').change(function(d) {
            if (this.checked) {
                $('#show_extension').closest('table').find('.extendedByCell').show();
                $('#show_extension').closest('table').find('.extendedFromCell').show();
            } else {
                $('#show_extension').closest('table').find('.extendedByCell').hide();
                $('#show_extension').closest('table').find('.extendedFromCell').hide();
            }
        })
    });
</script>
