<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'data' => array(
            'description' => __('Tags can be attached to entity to quickly classify them, allowing further filtering and searches.'),
            'model' => 'Tags',
            'fields' => array(
                array(
                    'field' => 'name'
                ),
                array(
                    'field' => 'colour',
                    'type' => 'color',
                ),
            ),
            'submit' => array(
                'action' => $this->request->getParam('action')
            )
        )
    ));
?>
</div>
