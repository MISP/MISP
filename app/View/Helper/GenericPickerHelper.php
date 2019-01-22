<?php
App::uses('AppHelper', 'View/Helper');


/* Class containing functions to ease the creation of the GenericPicker */
class GenericPickerHelper extends AppHelper {

    function add_select_params($options) {
        $select_html = '';
        foreach ($options['select_options'] as $option => $value) {
            $select_html .= h($option) . '=' . h($value) . ' ';
        }
        if (isset($options['functionName']) && $options['functionName'] !== "") {
            $select_html .= ' data-functionname=' . h($options['functionName']) .' ';
        }
        return $select_html;
    }

    function add_option($param, $defaults) {
        $option_html = '<option';

        if (isset($param['value'])) {
            $option_html .= ' value=' . h($param['value']);
        } else {
            $option_html .= ' value=' . h($param['name']);
        }
        if (isset($param['additionalData'])) {
            $additionalData = json_encode($param['additionalData']);
        } else {
            $additionalData = json_encode(array());
        }

        if (isset($param['template'])) {
            // $option_html .= ' data-template=' . base64_encode($param['template']);
            $template = $this->build_template($param);
            $option_html .= ' data-template=' . base64_encode($template);
        }

        $option_html .= ' data-additionaldata=' . base64_encode($additionalData);
        if (isset($param['disabled']) && $param['disabled']) {
            $option_html .= ' disabled';
        } else if (isset($param['selected']) && $param['selected']) { // nonsense to pre-select if disabled
            $option_html .= ' selected';
        }

        $option_html .= '>';

        $option_html .= h($param['name']);
        $option_html .= '</option>';
        return $option_html;
    }

    function add_link_params($param, $defaults=array()) {
        $param_html = ' ';
        if (isset($param['functionName'])) {
            $param_html .= 'onclick="execAndClose(this, ' . h($param['functionName']) . ')" ';
        } else { // fallback to default submit function
            if ($defaults['functionName'] !== '') {
                $param_html .= 'onclick="submitFunction(this, ' . h($defaults['functionName']) . ')" ';
            } else {
                $param_html .= 'data-endpoint="' . h($param['value']) . '" ';
                $param_html .= 'onclick="fetchRequestedData(this)" ';
            }
        }

        $additionalData = json_encode(array());
        foreach ($param as $paramName => $paramValue) {
            if ($paramName === 'additionalData') {
                $additionalData = json_encode($param['additionalData']);
            } else if ($paramName === 'value') {
                $param_html .= 'value="' . h($paramValue) . '" ';
            } else if ($paramName === 'template') {
                continue;
            } else {
                $param_html .= 'data-' . h($paramName). '="' . h($paramValue) . '" ';
            }
        }
        $param_html .= ' data-additionaldata=' . base64_encode($additionalData);
        return $param_html;
    }

    function add_pill($param, $defaults=array()) {
        $pill_html = '<li>';
        $pill_html .= '<a href="#" data-toggle="pill" class="pill-pre-picker"';
        $pill_html .= ' ' . $this->add_link_params($param, $defaults);
        $pill_html .= '>';
        if (isset($param['img'])) {
            $pill_html .= '<img src="' . h($param['img']) . '" style="margin-right: 5px; height: 14px;">';
        } else if (isset($param['icon'])) {
            $icon = $param['icon'];
            $pill_html .= '<span class="fa fa-' . h($icon) . '" style="margin-right: 5px;"></span>';
        }
        $pill_html .= h($param['name']) . '</a>';
        $pill_html .= '</li>';
        return $pill_html;
    }

    function build_template($param) {
        $template = "";
        if(isset($param['template'])) {
            $templateParam = $param['template'];
            if (isset($templateParam['preIcon'])) {
                $template .= $this->_View->element('genericPickerElements/pre_icon', array('preIcon' => $templateParam['preIcon']));
            }
            $template .= $this->_View->element('genericPickerElements/name', array('name' => $templateParam['name']));
            if (isset($templateParam['infoExtra'])) {
                $template .= $this->_View->element('genericPickerElements/info_extra', array('infoExtra' => $templateParam['infoExtra']));
            }
            if (isset($templateParam['infoContextual'])) {
                $template .= $this->_View->element('genericPickerElements/info_contextual', array('infoContextual' => $templateParam['infoContextual']));
            }
        }
        return $template;
    }
}
?>
