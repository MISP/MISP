<?php
    if (!empty($ajax)) {
        echo sprintf(
            '%s',
            sprintf(
                '<button id="submitButton" class="btn btn-primary" data-form-id="%s" type="button" autofocus>%s</button>',
                '#form-' . h($formRandomValue),
                __('Submit')
            )
        );
    } else {
        echo $this->Form->button(empty($text) ? __('Submit') : h($text), [
            'class' => 'btn btn-' . (empty($type) ? 'primary' : h($type)),
            'type' => 'submit',
            'data-form-id' => '#form-' . h($formRandomValue)
        ]);
    }
?>
