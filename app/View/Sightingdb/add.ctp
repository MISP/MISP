<?php
    $modelForForm = 'Sightingdb';
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Add SightingDB connection'),
            'model' => 'Sightingdb',
            'fields' => array(
                array(
                    'field' => 'org_id',
                    'class' => 'org-id-picker-hidden-field',
                    'type' => 'text',
                    'hidden' => true
                ),
                array(
                    'field' => 'name',
                    'class' => 'input-xxlarge'
                ),
                array(
                    'field' => 'host',
                    'class' => 'input-xxlarge'
                ),
                array(
                    'field' => 'port',
                    'class' => 'input'
                ),
                array(
                    'field' => 'namespace',
                    'class' => 'input-xxlarge'
                ),
                array(
                    'field' => 'owner',
                    'class' => 'input-xxlarge'
                ),
                array(
                    'field' => 'description',
                    'class' => 'input-xxlarge',
                    'type' => 'textarea'
                ),
                array(
                    'field' => 'host_id',
                    'type' => 'hidden'
                ),
                array(
                    'field' => 'enabled',
                    'type' => 'checkbox',
                    'default' => true
                ),
                array(
                    'field' => 'skip_proxy',
                    'type' => 'checkbox',
                    'default' => false
                ),
                array(
                    'field' => 'ssl_skip_verification',
                    'label' => 'Skip SSL verification',
                    'type' => 'checkbox',
                    'default' => false
                )
            ),
            'metaFields' => array(
                $this->element('genericElements/org_picker', array('orgs' => $orgs, 'modelForForm' => $modelForForm))
            ),
            'submit' => array(
                'action' => $this->request->params['action']
            )
        )
    ));
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sightingdb', 'menuItem' => $this->request->params['action']));
?>
