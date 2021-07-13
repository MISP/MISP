<?php

echo $this->Form->input($fieldData['field'], $params);
if (!empty($params['description'])) {
    echo sprintf('<small class="clear form-field-description apply_css_arrow">%s</small>', h($params['description']));
}
