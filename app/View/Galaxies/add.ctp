<?php
    $modelForForm = 'Galaxy';

    echo $this->element('genericElements/Form/genericForm', [
        'form' => $this->Form,
        'data' => [
            'title' => $action == 'add' ? __('Add Galaxy') : __('Edit Galaxy'),
            'model' => $modelForForm,
            'fields' => array(
                array(
                    'field' => 'name',
                    'label' => __('Name'),
                    'class' => 'span4',
                    'type' => 'text',
                    'stayInLine' => true
                ),
                array(
                    'field' => 'namespace',
                    'label' => __('Namespace'),
                    'class' => 'span2',
                    'type' => 'text',
                ),
                array(
                    'field' => 'distribution',
                    'options' => $distributionLevels,
                    'default' => isset($galaxy['Galaxy']['distribution']) ? $galaxy['Galaxy']['distribution'] : $initialDistribution,
                    'stayInLine' => 1,
                    'type' => 'dropdown'
                ),
                array(
                    'field' => 'id',
                    'type' => 'hidden',
                ),
                array(
                    'field' => 'uuid',
                    'type' => 'hidden',
                ),
                array(
                    'field' => 'version',
                    'type' => 'hidden',
                ),
                array(
                    'field' => 'description',
                    'label' => __('Description'),
                    'type' => 'textarea',
                    'class' => 'input span6',
                    'div' => 'input clear'
                ),
                array(
                    'field' => 'icon',
                    'label' => __('Icon'),
                    'class' => 'span6',
                    'type' => 'text',
                ),
                array(
                    'field' => 'kill_chain_order',
                    'label' => __('Kill Chain - For the Galaxy Matrix'),
                    'class' => 'span6',
                    'type' => 'textarea'
                ),
                array(
                    'field' => 'enabled',
                    'label' => __('Enabled'),
                    'type' => 'checkbox',
                ),
            ),
        ]
    ]);
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => $this->action === 'add' ? 'galaxy_add' : 'galaxy_edit'));
?>
