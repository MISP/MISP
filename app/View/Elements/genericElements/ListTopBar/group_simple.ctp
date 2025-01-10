<?php
    if (!isset($data['requirement']) || $data['requirement']) {
        $elements = '';
        foreach ($data['children'] as $element) {
            $elements .= $this->element('/genericElements/ListTopBar/element_' . (empty($element['type']) ? 'simple' : h($element['type'])), array('data' => $element, 'tableRandomValue' => $tableRandomValue));
        }
        echo sprintf(
            '<div %s class="btn-group btn-group-sm me-2 flex-wrap" role="group" aria-label="button-group">%s</div>',
            (!empty($data['id'])) ? 'id="' . h($data['id']) . '"' : '',
            $elements
        );
    }
?>
