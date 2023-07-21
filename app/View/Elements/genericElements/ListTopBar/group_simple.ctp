<?php
if (!isset($data['requirement']) || $data['requirement']) {
    $elements = [];
    foreach ($data['children'] as $element) {
        $elements[] = $this->element('/genericElements/ListTopBar/element_' . (empty($element['type']) ? 'simple' : $element['type']), array('data' => $element));
    }
    echo sprintf(
        '<div%s class="btn-group">%s</div>',
        (!empty($data['id'])) ? ' id="' . h($data['id']) . '"' : '',
        implode('', $elements)
    );
}

