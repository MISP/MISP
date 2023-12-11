<div class="attributes form">
<?php
    echo $this->Form->create('Server', array('id', 'url' => '/communities/requestAccess/' . $community['uuid']));
    echo sprintf(
        '<fieldset><legend>%s</legend><p style="width:550px;">%s</p>%s</fieldset>%s',
        'Request access to ' . h($community['name']),
        __('Describe both yourself and your organisation as best as you can - keep in mind this information is to be used by the hosts of the community you are requesting access to in order to determine whether you\'re a good fit for their community. The sending server\'s basic metadata is included by default, you can opt out using the "anonymise" checkbox (server url, uuid, version are shared otherwise - though this can be a useful step in establishing trust.).'),
        (
            $this->Form->input('email', array(
                'label' => __('Requestor E-mail address'),
                'div' => 'input clear',
                'class' => 'input-xxlarge'
            )) .
            $this->Form->input('org_name', array(
                'label' => __('Organisation name'),
                'div' => 'input clear',
                'class' => 'input-xxlarge'
            )) .
            $this->Form->input('org_uuid', array(
                'label' => __('Organisation uuid'),
                'div' => 'input clear',
                'class' => 'input-xxlarge'
            )) .
            $this->Form->input('org_description', array(
                'label' => __('Description of the requestor organisation'),
                'div' => 'input clear',
                'type' => 'textarea',
                'class' => 'input-xxlarge'
            )) .
            $this->Form->input('message', array(
                'label' => __('Message to the community host organisation'),
                'div' => 'input clear',
                'type' => 'textarea',
                'class' => 'input-xxlarge'
            )) .
            $this->Form->input('gpgkey', array(
                'label' => __('PGP public key'),
                'div' => 'input clear',
                'type' => 'textarea',
                'class' => 'input-xxlarge'
            )) .
            $this->element('/genericElements/Forms/clear') .
            $this->Form->input('sync', array(
                'label' => __('Request sync access'),
                'type' => 'checkbox'
            )) .
            $this->element('/genericElements/Forms/clear') .
            $this->Form->input('anonymise', array(
                'label' => __('Anonymise information on the server used to issue the request'),
                'type' => 'checkbox'
            )) .
            $this->element('/genericElements/Forms/clear') .
            $this->Form->input('mock', array(
                'label' => __('Generate e-mail for later use, but do not send it'),
                'type' => 'checkbox',
                'disabled' => !empty(Configure::read('MISP.disable_emailing')),
                'checked' => !empty(Configure::read('MISP.disable_emailing'))
            ))
        ),
        $this->Form->button('Submit', array(
            'class' => 'btn btn-primary',
            'div' => 'input clear',
        )) .
        $this->Form->end()
    );
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => 'request_community_access'));
?>
<script type="text/javascript">
$(document).ready(function() {
});
</script>
<?php echo $this->Js->writeBuffer();
