<div class="attributes form">
<?php
    echo $this->Form->create('Server', array('id', 'url' => '/communities/requestAccess/' . $community['community_uuid']));
    echo sprintf(
        '<fieldset><legend>%s</legend>%s</fieldset>%s',
        'Request access to ' . h($community['community_name']),
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
