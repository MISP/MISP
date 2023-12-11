<?php
    echo sprintf(
        '<span id="onDemandButtonResult%s-%s" class="buttonResultField"></span><div>%s<button class="btn %s %s" style="%s %s" %s>%s</button></div>',
        h($k),
        h($column),
        empty($field['textInput']) ? '' : sprintf(
            '<input id="onDemandTextEntry%s-%s" style="line-height:16px; font-size:10px;" />',
            h($k),
            h($column)
        ),
        !empty($field['button_class']) ? $field['button_class'] : 'btn-inverse',
        empty($field['button_icon']) ? '' : $this->FontAwesome->getClass($field['button_icon']) . ' white',
        !empty($field['button_style']) ? $field['button_style'] : 'line-height:20px;',
        empty($field['textInput']) ? '' : 'border-radius: 0px 3px 3px 0px;',
        empty($field['url']) ? '' : sprintf(
            'onClick="runOnDemandAction(this, \'%s%s\', \'onDemandButtonResult%s-%s\', \'%s\');"',
            h($field['url']),
            h(Hash::extract($row, $field['data_path'])[0]),
            h($k),
            h($column),
            empty($field['textInput']) ? '' : sprintf(
                'onDemandTextEntry%s-%s',
                h($k),
                h($column)
            )
        ),
        !empty($field['button']) ? h($field['button']) : ''
    );

?>
