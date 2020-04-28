<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'url' => 'saveDashboardTemplate',
        'data' => array(
            'title' => __('Save Dashboard Template'),
            'model' => 'Dashboard',
            'fields' => array(
                array(
                    'field'=> 'name',
                    'type' => 'text',
                    'class' => 'input span6',
                    'div' => 'input clear',
                    'label' => __('Template Name')
                ),
                array(
                    'field'=> 'description',
                    'type' => 'textarea',
                    'class' => 'input span6',
                    'div' => 'input clear',
                    'label' => __('Description')
                ),
                array(
                    'field' => 'restrict_to_org_id',
                    'options' => $options['org_id'],
                    'class' => 'input span6',
                    'div' => 'input clear',
                    'label' => __('Restrict to organisation'),
                    'requirements' => $isSiteAdmin
                ),
                array(
                    'field' => 'restrict_to_role_id',
                    'options' => $options['role_id'],
                    'class' => 'input span6',
                    'div' => 'input clear',
                    'label' => __('Restrict to role'),
                    'requirements' => $isSiteAdmin
                ),
                array(
                    'field' => 'restrict_to_permission_flag',
                    'options' => $options['role_perms'],
                    'class' => 'input span6',
                    'div' => 'input clear',
                    'label' => __('Restrict to role permission flag'),
                    'requirements' => $isSiteAdmin
                ),
                array(
                    'field' => 'selectable',
                    'type' => 'checkbox',
                    'class' => 'input',
                    'div' => 'input',
                    'label' => __('Selectable')
                ),
                array(
                    'field' => 'default',
                    'type' => 'checkbox',
                    'class' => 'input',
                    'div' => 'input',
                    'label' => __('Default'),
                    'requirements' => $isSiteAdmin
                ),
            ),
            'submit' => array(
                'action' => 'import',
                'ajaxSubmit' => "$('#DashboardSaveTemplateForm').submit();"
            ),
            'description' => __('Save your current dashboard state as a template for others to reuse.')
        )
    ));
?>
