<?php
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'model' => 'Galaxy',
        'title' => sprintf(__('Export galaxy: %s'), h($galaxy['Galaxy']['name'])),
        'fields' => array(
            array(
                'field' => 'distribution',
                'label' => '<strong>' . __("Cluster's distribution:") . '</strong>',
                'options' => $distributionLevels,
                'selected' => array(1, 2, 3),
                'multiple' => 'checkbox', 
            ),
            '<br />',
            array(
                'field' => 'custom',
                'type' => 'checkbox',
                'label' => __("Include Custom Clusters"),
                'checked' => true
            ),
            array(
                'field' => 'default',
                'type' => 'checkbox',
                'label' => __("Include Default Clusters"),
                'checked' => true
            ),
            '<br />',
            array(
                'field' => 'download',
                'type' => 'radio',
                'label' => __('Export type'),
                'legend' => false,
                'options' => array(
                    'download' => __('Download'),
                    'raw' => __('Raw'),
                ),
                'default' => 'raw',
            ),
        )
    )
));

echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'export'));
