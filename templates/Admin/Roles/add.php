<?php

    $fields = [
        [
            'field' => 'restricted_to_site_admin',
            'label' => __('Restrict to site admins'),
            'type' => 'checkbox',
            'class' => 'readonlyenabled'
        ],
        [
            'field' => 'name',
            'stayInLine' => 1
        ],
        [
            'field' => 'permission',
            'label' => __('Permissions'),
            'type' => 'dropdown',
            'options' => $dropdownData['options'],
            'value' => '3',
            'class' => 'span3'
        ],
        [
            'field' => 'memory_limit',
            'label' => __('Memory limit ({0})', $default_memory_limit),
            'stayInLine' => 1
        ],
        [
            'field' => 'max_execution_time',
            'label' => __('Maximum execution time ({0}s)', $default_max_execution_time)
        ],
        [
            'field' => 'enforce_rate_limit',
            'label' => __('Enforce search rate limit'),
            'type' => 'checkbox',
        ],
        [
            'field' => 'rate_limit_count',
            'label' => __('# of searches / 15 min'),
            'div' => [
                'id' => 'rateLimitCountContainer'
            ]
        ]
    ];
    $counter = 0;
    foreach ($permFlags as $k => $flag) {
        $counter += 1;
        $fields[] = [
            'field' => $k,
            'label' => h($flag['text']),
            'checked' => false,
            'type' => 'checkbox',
            'div' => [
                'class' => sprintf(
                    'permFlags %s checkbox',
                    ($flag['readonlyenabled'] ? 'readonlyenabled' : 'readonlydisabled')
                )
            ],
            'class' => sprintf(
                'checkbox %s %s',
                ($flag['readonlyenabled'] ? 'readonlyenabled' : 'readonlydisabled'),
                empty($flag['site_admin_optional']) ? 'site_admin_enforced' : 'site_admin_optional'
            ),
            'stayInLine' => ($counter%3 != 0)
        ];
    }
    echo $this->element('genericElements/Form/genericForm', [
        'data' => [
            'description' => __('Roles define global rules for a set of users, including first and foremost access controls to certain functionalities.'),
            'model' => 'Roles',
            'fields' => $fields,
            'submit' => [
                'action' => $this->request->getParam('action')
            ]
        ]
    ]);
?>
</div>


<script type="text/javascript">
    $(function() {
        checkRolePerms();
        checkRoleEnforceRateLimit();
        $(".checkbox, #RolePermission").change(function() {
            checkRolePerms();
        });
        $("#RoleEnforceRateLimit").change(function() {
            checkRoleEnforceRateLimit();
        });
    });
</script>
