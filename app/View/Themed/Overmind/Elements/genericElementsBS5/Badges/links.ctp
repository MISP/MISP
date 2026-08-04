<?php
$data_elements = $links;
$field = $object;

$url_param_data_paths = '';
$urlWithData = empty($field['url']) ? '#' : h($field['url']);


if (!empty($field['url_params_data_paths'])) {
    if (is_array($field['url_params_data_paths'])) {
        $temp = array();
        foreach ($field['url_params_data_paths'] as $k => $path) {
            $extracted_value = Hash::extract($row, $path);
            if (!empty($extracted_value)) {
                if (is_string($k)) { 
                    $temp[] = h($k) . ':' . h($extracted_value[0]);
                } else {
                    $temp[] = h($extracted_value[0]);
                }
            }
        }
        $url_param_data_paths = implode('/', $temp);
    } else {
        $url_param_data_paths = Hash::extract($row, $field['url_params_data_paths']);
        if (empty($url_param_data_paths)) {
            $url_param_data_paths = '';
        }
    }
}

$display_links = array();

foreach ($data_elements as $k => $data) {
    $current_title = !empty($field['title']) ? $field['title'] : '';
    if (!empty($data['name'])) {
        $current_title = $data['name'];
    }
    $data_val = !empty($data['url']) ? $data['url'] : $data;

    if (isset($field['url']) && strpos($field['url'], '%s') !== false) {
        $url = sprintf($field['url'], $data_val);
    } elseif (!empty($field['url_params_data_paths'])) {
        $url = $urlWithData;
        if (!empty($url_param_data_paths)) {
            $url .= '/' . (is_array($url_param_data_paths) ? $url_param_data_paths[$k] : $url_param_data_paths);
        }
    } else {
        $url = $data_val;
    }

    $display_links[] = [
        'url'   => h($url),
        'title' => h(!empty($current_title) ? $current_title : $data_val)
    ];
}
?>


<div class="link-list">
    <?php foreach ($display_links as $link): ?>
        <div class="py-1">
            <i class="fa fa-link text-muted mr-2"></i>
            <a href="<?= $link['url'] ?>" title="<?= $link['title'] ?>" class="text-decoration-none">
                <?= h($link['title']) ?>
            </a>
        </div>
    <?php endforeach; ?>
</div>