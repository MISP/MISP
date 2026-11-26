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
                    'field' => 'false_positive_namespace',
                    'label' => __('False-positive namespace'),
                    'class' => 'input-xxlarge',
                    'placeholder' => __('e.g. misp/false-positive'),
                    'description' => __('Where false-positives are pushed to and read from, kept apart from sightings. Leave empty to leave false-positives out.')
                ),
                array(
                    'field' => 'api_key',
                    'label' => __('API key'),
                    'class' => 'input-xxlarge',
                    'type' => 'password',
                    'autocomplete' => 'new-password',
                    'placeholder' => $this->request->params['action'] === 'edit' ? __('Leave empty to keep the current key') : __('Leave empty if the SightingDB does not require one')
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
                    'field' => 'push_sightings',
                    'label' => __('Push sightings'),
                    'type' => 'checkbox',
                    'default' => false,
                    'description' => __('Write the sightings and false-positives recorded in MISP to this SightingDB, as the SHA-256 of the value, under <namespace>/misp so they are not counted twice. Needs an API key allowed to write there.')
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
<script>
$(function() {
    // Follow the namespace with <namespace>/false-positive until edited by hand
    var $namespace = $('#SightingdbNamespace'), $falsePositive = $('#SightingdbFalsePositiveNamespace');
    var follows = $falsePositive.val() === '' || $falsePositive.val() === $namespace.val() + '/false-positive';
    $falsePositive.on('input', function() { follows = false; });
    $namespace.on('input', function() {
        if (follows) {
            $falsePositive.val($namespace.val() === '' ? '' : $namespace.val() + '/false-positive');
        }
    });
});
</script>
