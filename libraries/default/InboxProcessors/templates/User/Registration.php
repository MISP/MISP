<?php
$combinedForm = $this->element('genericElements/Form/genericForm', [
    'entity' => $userEntity,
    'ajax' => false,
    'raw' => true,
    'data' => [
        'description' => __('Create user account'),
        'model' => 'User',
        'fields' => [
            [
                'field' => 'individual_id',
                'type' => 'dropdown',
                'label' => __('Associated individual'),
                'options' => $dropdownData['individual'],
            ],
            [
                'field' => 'username',
                'autocomplete' => 'off',
            ],
            [
                'field' => 'organisation_id',
                'type' => 'dropdown',
                'label' => __('Organisation'),
                'options' => $dropdownData['organisation']
            ],
            [
                'field' => 'role_id',
                'type' => 'dropdown',
                'label' => __('Role'),
                'options' => $dropdownData['role']
            ],
            [
                'field' => 'disabled',
                'type' => 'checkbox',
                'label' => 'Disable'
            ],

            sprintf('<div class="pb-2 fs-4">%s</div>', __('Create individual')),
            [
                'field' => 'email',
                'autocomplete' => 'off'
            ],
            [
                'field' => 'uuid',
                'label' => 'UUID',
                'type' => 'uuid',
                'autocomplete' => 'off'
            ],
            [
                'field' => 'first_name',
                'autocomplete' => 'off'
            ],
            [
                'field' => 'last_name',
                'autocomplete' => 'off'
            ],
            [
                'field' => 'position',
                'autocomplete' => 'off'
            ],
        ],
        'submit' => [
            'action' => $this->request->getParam('action')
        ]
    ]
]);


echo $this->Bootstrap->modal([
    'title' => __('Register user'),
    'size' => 'lg',
    'type' => 'confirm',
    'bodyHtml' => sprintf(
        '<div class="form-container">%s</div>',
        $combinedForm
    ),
    'confirmText' => __('Create user'),
    'confirmFunction' => 'submitRegistration'
]);
?>
</div>

<script>
    function submitRegistration(modalObject, tmpApi) {
        const $form = modalObject.$modal.find('form')
        return tmpApi.postForm($form[0]).then((result) => {
            const url = '/inbox/index'
            const $container = $('div[id^="table-container-"]')
            const randomValue = $container.attr('id').split('-')[2]
            return result
        })
    }

    $(document).ready(function() {
        $('div.user-container #individual_id-field').change(function() {
            if ($(this).val() == -1) {
                $('div.individual-container').show()
            } else {
                $('div.individual-container').hide()
            }
        })
    })

    function getFormData(form) {
        return Object.values(form).reduce((obj, field) => {
            if (field.type === 'checkbox') {
                obj[field.name] = field.checked;
            } else {
                obj[field.name] = field.value;
            }
            return obj
        }, {})
    }
</script>

<style>
    div.individual-container>div,
    div.user-container>div {
        font-size: 1.5rem;
    }
</style>