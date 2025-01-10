<?php
    if (!isset($data['requirement']) || $data['requirement']) {
        $dataFields = array();
        if (!empty($data['data'])) {
            foreach ($data['data'] as $dataKey => $dataValue) {
                $dataFields[] = sprintf(
                    'data-%s="%s"',
                    h($dataKey),
                    h($dataValue)
                );
            }
        }
        $dataFields = implode(' ', $dataFields);
        if (!empty($data['children'])) {
            $child_data = '';
            foreach ($data['children'] as $child) {
                $child_data .= $this->element('/genericElements/ListTopBar/element_embedded', array('data' => $child));
            }
        }
        $aria_label = '';
        if (empty($data['text'])) {
            if (!empty($data['title'])) {
                $aria_label = sprintf('aria-label="%s"', h($data['title']));
            }
        }
        echo sprintf(
            '<a class="btn btn-small btn-dropdown-toggle %s %s" %s %s data-bs-toggle="dropdown" href="#" %s>%s%s%s <span class="caret"></span></a><ul class="dropdown-menu">%s</ul>',
            empty($data['class']) ? '' : h($data['class']),
            empty($data['active']) ? 'btn-inverse' : 'btn-primary',   // Change the default class for highlighted/active toggles here
            empty($data['id']) ? '' : 'id="' . h($data['id']) . '"',
            empty($data['title']) ? '' : sprintf('title="%s"', h($data['title'])),
            $aria_label,
            empty($data['fa-icon']) ? '' : sprintf('<i class="fa fa-%s"></i>', $data['fa-icon']),  // this has to be sanitised beforehand!
            empty($data['html']) ? '' : $data['html'],  // this has to be sanitised beforehand!
            empty($data['text']) ? '' : h($data['text']),
            empty($data['children']) ? '' : $child_data
        );
    }
?>
