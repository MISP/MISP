<?php
    echo '<span class="hidden instanceKeyContainer"></span>';
    echo $this->element('genericElements/Form/genericForm', [
        'data' => [
            'description' => __('Add a signing key to be used to validate the origin of event updates. By putting an event into protected mode, the event cannot reliably be propagated to / updated at instances beyond the reach of those that can sign with the listed keys below.'),
            'model' => 'CryptographicKey',
            'title' => __('Add Cryptographic key'),
            'fields' => [
                [
                    'field' => 'type',
                    'class' => 'span6',
                    'type' => 'dropdown',
                    'options' => [
                        'pgp' => 'PGP'
                    ]
                ],
                [
                    'field' => 'instance_key',
                    'type' => 'action',
                    'class' => 'btn btn-inverse',
                    'icon' => 'key',
                    'text' => __('Use the instance\'s signing key'),
                    'onClick' => 'insertInstanceKey();'
                ],
                [
                    'field' => 'key_data',
                    'label' => __('Key contents'),
                    'type' => 'textarea',
                    'class' => 'input span6'
                ],
            ],
            'submit' => [
                'action' => $this->request->params['action'],
                'ajaxSubmit' => 'submitGenericFormInPlace();'
            ]
        ]
    ]);

    if (!$ajax) {
        echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
    }
?>
<script type="text/javascript">
    var instanceKey = <?= json_encode(h($instanceKey)); ?>;
    function insertInstanceKey() {
        $('#CryptographicKeyKeyData').val(instanceKey);
    }
</script>
