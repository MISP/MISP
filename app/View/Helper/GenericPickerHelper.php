<?php
App::uses('AppHelper', 'View/Helper');


/* Class containing functions to ease the creation of the GenericPicker */
class GenericPickerHelper extends AppHelper {

    function add_select_params($options) {
        if (isset($options['select_options']['additionalData'])) {
            $additionalData = json_encode($options['select_options']['additionalData']);
            unset($options['select_options']['additionalData']);
        } else {
            $additionalData = json_encode(array());
        }

        $select_html = '';
        foreach ($options['select_options'] as $option => $value) {
            $select_html .= sprintf('%s=%s ', h($option), h($value));
        }
        if (isset($options['functionName']) && $options['functionName'] !== "") {
            $select_html .= sprintf('data-functionname=%s ', h($options['functionName']));
        }
        $select_html .= sprintf(' data-additionaldata=%s', base64_encode($additionalData));
        return $select_html;
    }

    function add_option($param, $defaults, $countThresholdReached) {
        $option_html = '<option';

        if (isset($param['value'])) {
            $option_html .= sprintf(' value=%s',  h($param['value']));
        } else {
            $option_html .= sprintf(' value=%s', h($param['name']));
        }

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
            $param_html .= sprintf('onclick="execAndClose(this, %s)" ', h($param['functionName']));
        } else { // fallback to default submit function
            if ($defaults['functionName'] !== '') {
                $param_html .= 'onclick="submitFunction(this, ' . h($defaults['functionName']) . ')" ';
                $param_html .= sprintf('onclick="submitFunction(this, %s)" ', h($defaults['functionName']));
            } else {
                $param_html .= sprintf('data-endpoint="%s" onclick="fetchRequestedData(this)" ', h($param['value']));
            }
        }

        $additionalData = json_encode(array());
        foreach ($param as $paramName => $paramValue) {
            if ($paramName === 'value') {
                $param_html .= sprintf('value="%s" ', h($paramValue));
            } else if ($paramName === 'template' || $paramName === 'additionalData') {
                continue;
            } else {
                $param_html .= sprintf('data-%s="%s" ', h($paramName), h($paramValue));
            }
        }
        return $param_html;
    }

    function add_pill($param, $defaults=array()) {
        $pill_html = '<li>';
        $pill_html .= '<a href="#" data-toggle="pill" class="pill-pre-picker"';
        $pill_html .= ' ' . $this->add_link_params($param, $defaults) . '>';
        if (isset($param['img'])) {
            $pill_html .= '<img src="' . h($param['img']) . '" style="margin-right: 5px; height: 14px;">';
        } else if (isset($param['icon'])) {
            $icon = $param['icon'];
            $pill_html .= '<span class="fa fa-' . h($icon) . '" style="margin-right: 5px;"></span>';
        }
        $pill_html .= h($param['name']);
        if (isset($param['template']['infoExtra'])) {
            $pill_html .= $this->_View->element('genericPickerElements/info_extra', array('infoExtra' => $param['template']['infoExtra'], 'forceIcon' => true));
        }
        if (isset($param['isMatrix']) && $param['isMatrix']) {
            $span = '<span style="position: absolute; font-size: 8px; top: 2px;" class="fa fa-th" title="' . __('Start the galaxy matrix picker') . '"></span>';
            $pill_html .= $span;
        }
        $pill_html .= '</a>';
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
