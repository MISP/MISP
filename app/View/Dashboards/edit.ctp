<?php
    $modelForForm = 'Dashboard';
    $paramsHtml = '';
    if (!empty($data['params'])) {
        foreach ($data['params'] as $param => $desc) {
            $paramsHtml .= sprintf(
                '<span class="bold">%s</span>: %s<br />',
                h($param),
                h($desc)
            );
        }
    }
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'url' => 'updateSettings',
        'data' => array(
            'title' => __('Edit Widget'),
            'model' => 'Dashboard',
            'fields' => array(
                array(
                    'field'=> 'config',
                    'type' => 'textarea',
                    'class' => 'input span6',
                    'div' => 'input clear',
                    'label' => __('Config'),
                    'default' => empty($data['config']) ? '' : json_encode($data['config'], JSON_PRETTY_PRINT)
                )
            ),
            'submit' => array(
                'action' => 'edit',
                'ajaxSubmit' => sprintf(
                    "submitDashboardForm('%s')",
                    h($data['id'])
                )
            ),
            'description' => sprintf(
                '<p class="black">%s<span></p><p class="bold">Parameters</p><p>%s</p>',
                h($data['description']),
                $paramsHtml
            )
        )
    ));
?>
