<?php

use Cake\Core\Configure;
use Cake\Utility\Hash;
?>

<?php
$toggleNextTabButton = $this->Bootstrap->button(
    [
    'onclick' => 'toggleNextTab()',
    'text' => __('Next page'),
    'variant' => 'secondary',
    ]
);
$toggleNextTabDiv = $this->Bootstrap->node('div', ['class' => 'mt-2'], $toggleNextTabButton);

$formGeneral = $this->element(
    'genericElements/Form/genericForm',
    [
    'data' => [
        'model' => 'SharingGroups',
        'fields' => [
            [
                'field' => 'uuid',
                'label' => 'UUID',
                'type' => 'uuid',
                'placeholder' => __('If not provided, random UUID will be generated'),
            ],
            [
                'field' => 'name',
                'placeholder' => __('Example: Multinational sharing group'),
            ],
            [
                'field' => 'releasability',
                'label' => __('Releasable to'),
                'placeholder' => __('Example: Community1, Organisation1, Organisation2'),
            ],
            [
                'field' => 'description',
                'type' => 'textarea',
                'placeholder' => __('A description of the sharing group.'),
            ],
            [
                'field' => 'active',
                'label' => __('Make the sharing group selectable (active)'),
                'type' => 'checkbox',
                'default' => 1,
                'tooltip' => __('Active sharing groups can be selected by users of the local instance when creating events. Generally, sharing groups received through synchronisation will have this disabled until manually enabled.'),
            ],
        ],
    ],
    'raw' => true,
    ]
);

$formOrgs = $this->element(
    'genericElements/Form/genericForm',
    [
    'data' => [
        'model' => 'SharingGroups',
        'fields' => [
            [
                'field' => 'local_orgs',
                'label' => __('Local Organisations'),
                'placeholder' => __('Add local organisation(s) to the sharing group'),
                'type' => 'dropdown',
                'multiple' => false,
                'select2' => [
                    'placeholder' => __('Select a local organisation'),
                ],
                'options' => ['' => ''] + Hash::combine(
                    array_filter($organisations, fn ($org) => $org['local']),
                    '{n}.id',
                    '{n}.name'
                ),
            ],
            [
                'field' => 'remote_orgs',
                'label' => __('Remote Organisations'),
                'placeholder' => __('Add remote organisation(s) to the sharing group'),
                'type' => 'dropdown',
                'multiple' => false,
                'select2' => [
                    'placeholder' => __('Select a remote organisation'),
                ],
                'options' => ['' => ''] + Hash::combine(
                    array_filter($organisations, fn ($org) => !$org['local']),
                    '{n}.id',
                    '{n}.name'
                ),
            ],
        ],
    ],
    'raw' => true,
    ]
);
$orgTable = $this->Bootstrap->table(
    [
        'id' => 'organisations_table',
        'condensed' => true,
        'striped' => true,
        'borderless' => true,
    ],
    [
        'fields' => [
            __('Type'),
            __('Name'),
            __('UUID'),
            __('Extend'),
            __('Actions'),
        ],
        'items' => [],
    ]
);

$formServers = $this->element(
    'genericElements/Form/genericForm',
    [
    'data' => [
        'model' => 'SharingGroups',
        'fields' => [
            [
                'field' => 'roaming',
                'label' => __('Enable roaming mode'),
                'type' => 'checkbox',
                'default' => false,
                'tooltip' => __('Roaming mode will allow the sharing group and associated data to be passed to any instance where the remote recipient is contained in the organisation list.'),
                'div' => [
                    'class' => 'mb-3',
                ],
            ],
            [
                'field' => 'misp_instances',
                'label' => __('MISP instances'),
                'placeholder' => __('Add instance(s) to the sharing group'),
                'type' => 'dropdown',
                'multiple' => true,
                'select2' => true,
                'options' => Hash::combine(
                    $mispInstances,
                    '{n}.id',
                    '{n}.name'
                ),
                'div' => [
                    'id' => 'server-picker-container',
                ],
            ],
        ],
    ],
    'raw' => true,
    ]
);
$serverTable = $this->Bootstrap->table(
    [
        'id' => 'servers_table',
        'condensed' => true,
        'striped' => true,
        'borderless' => true,
    ],
    [
        'fields' => [
            __('Name'),
            __('URL'),
            __('All orgs'),
            __('Actions'),
        ],
        'items' => [],
    ]
);

$formSummary = $this->element(
    'genericElements/Form/genericForm',
    [
    'data' => [
        'model' => 'SharingGroups',
        'fields' => [
            [
                'field' => 'json',
                'type' => 'text',
            ],
        ],
    ],
    'raw' => true,
    ]
);

$summaryText = '<p>' . $this->Bootstrap->render(
    '<b>' . __('General') . '</b>: ' .
        __('You are about to create the {{title_container}} sharing group, which is intended to be releasable to {{releasable_container}}.'),
    [
        'title_container' => '<strong id="summarytitle" class="text-danger">XX</strong>',
        'releasable_container' => '<strong id="summaryreleasable" class="text-danger">XX</strong>',
    ]
) . '</p>';
$summaryText .= '<p>' . $this->Bootstrap->render(
    '<b>' . __('Local organisations') . '</b>: ' .
        __('It will be visible to {{local}}, from which {{extend}} can extend the sharing group.'),
    [
        'local' => '<strong id="summarylocal" class="text-danger"></strong>',
        'extend' => ' <strong id="summarylocalextend" class="text-danger"></strong>',
    ]
) . '</p>';
$summaryText .= '<p>' . $this->Bootstrap->render(
    '<b>' . __('External organisations') . '</b>: ' .
        __('It will also be visible to {{external}}, out of which {{extend}} can extend the sharing group.'),
    [
        'external' => '<strong id="summaryexternal" class="text-danger"></strong>',
        'extend' => '<strong id="summaryexternalextend" class="text-danger"></strong>',
    ]
) . '</p>';
$summaryText .= '<p>' . $this->Bootstrap->render(
    '<b>' . __('Synchronisation') . '</b>: ' .
        __('Furthermore, events are automatically pushed to: {{servers}}'),
    [
        'servers' => '<strong id="summaryservers" class="text-danger"></strong>',
    ]
) . '</p>';
$summaryText .= $this->Bootstrap->alert(
    [
    'text' => __('You can edit this information by going back to one of the previous pages.'),
    'dismissible' => false,
    ]
);

$formSummary =  $this->Bootstrap->node('div', ['class' => 'd-none'], $formSummary);
$formSummary .= $summaryText;
$formSummary .=  $this->Bootstrap->node(
    'div',
    ['class' => 'mt-2'],
    $this->Bootstrap->button(
        [
        'text' => $this->request->getParam('action') == 'edit' ? __('Edit sharing group') : __('Create sharing group'),
        'onclick' => 'sgSubmitForm()',
        ]
    )
);

$formGeneral .= $toggleNextTabDiv;
$formOrgs .= $orgTable . $toggleNextTabDiv;
$formServers .= $serverTable . $toggleNextTabDiv;

$bsTabs = $this->Bootstrap->tabs(
    [
    'id' => 'tabs-sg-form',
    'card' => !false,
    'content-class' => ['p-3'],
    'data' => [
        'navs' => [
            ['text' => __('General'), 'active' => true],
            ['text' => __('Organisations'),],
            ['text' => __('Instances'),],
            ['text' => __('Summary & Save'), 'id' => 'tab-summary-and-save'],
        ],
        'content' => [
            $formGeneral,
            $formOrgs,
            $formServers,
            $formSummary,
        ],
    ]
    ]
);

if (!empty($ajax)) {
    $seedModal = 'mseed-' . mt_rand();
    echo $this->Bootstrap->modal(
        [
        'title' => __('New Sharing group'),
        'bodyHtml' =>  $bsTabs,
        'size' => 'lg',
        'type' => 'cancel',
        'modalClass' => $seedModal,
        ]
    );
} else {
    $page = sprintf('<h2 class="fw-light">%s</h2>', __('New Sharing Group'));
    $page .= $bsTabs;
    echo $page;
}

$existingSharingGroupOrgs = [];
foreach ($entity->SharingGroupOrg as $org) {
    $existingSharingGroupOrgs[] = [
        'id' => h($org['org_id']),
        'type' => ($org['Organisation']['local'] == 1 ? 'local' : 'remote'),
        'name' => h($org['Organisation']['name']),
        'extend' => h($org['extend']),
        'uuid' => h($org['Organisation']['uuid']),
        'removable' => $entity->Organisation->id != $org['org_id'],
    ];
}

$existingSharingGroupServers = [];
foreach ($entity->SharingGroupServer as $server) {
    if ($server['server_id'] == 0) {
        continue;
    }
    $existingSharingGroupServers[] = [
        'id' => h($server['server_id']),
        'name' => h($server['Server']['name']),
        'url' => h($server['Server']['url']),
        'all_orgs' => h($server['all_orgs']),
        'removable' => 1,
    ];
}

?>
</div>

<script>
    var roaming = false;
    var organisations = [{
        id: '<?php echo h($user['Organisation']['id']) ?>',
        type: 'local',
        name: '<?php echo h($user['Organisation']['name']) ?>',
        extend: true,
        uuid: '',
        removable: 0
    }];
    var orgids = [];
    var servers = [{
        id: '0',
        name: '<?php echo __('Local instance'); ?>',
        url: '<?php echo h(empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl')); ?>',
        all_orgs: true,
        removable: 0
    }];
    var serverids = [0];

    $(document).ready(function() {

        var existingSharingGroupOrgs = <?= json_encode($existingSharingGroupOrgs) ?>;
        var existingSharingGroupServers = <?= json_encode($existingSharingGroupServers) ?>;
        if (existingSharingGroupOrgs.length > 0) {
            organisations = existingSharingGroupOrgs
        }
        if (existingSharingGroupServers.length > 0) {
            servers = servers.concat(servers, existingSharingGroupServers)
        }
        orgids = organisations.map((org) => org.id.toString())

        $('#roaming-field').change(function() {
            toggleServerTableVisibility()
        });
        toggleServerTableVisibility()

        if ($('#json-field').val()) sharingGroupPopulateFromJson();
        sharingGroupPopulateOrganisations();
        sharingGroupPopulateServers();

        const lastTabEl = document.querySelector('#tabs-sg-form a#tab-summary-and-save-tab[data-bs-toggle].nav-link')
        lastTabEl.addEventListener('shown.bs.tab', event => {
            updateSummaryText()
        })

        $('#local_orgs-field').on('select2:select', function(e) {
            const data = $(this).select2('data');
            refreshPickedOrgList('local', data);
            $(this).val(null).trigger('change');
        });
        $('#remote_orgs-field').on('select2:select', function(e) {
            const data = $(this).select2('data');
            refreshPickedOrgList('remote', data);
            $(this).val(null).trigger('change');
        });
        $('#misp_instances-field').on('select2:select', function(e) {
            const data = $(this).select2('data');
            refreshPickedServerList('remote', data)
        });

    })

    function toggleServerTableVisibility() {
        if ($('#roaming-field').is(":checked")) {
            $('#servers_table').hide();
            $('#server-picker-container').hide();
        } else {
            $('#servers_table').show();
            $('#server-picker-container').show();
        }
    }

    function refreshPickedOrgList(localType, pickedOrgs) {
        pickedOrgs.forEach(function(org) {
            if (orgids.indexOf(org.id) == -1) {
                organisations.push({
                    id: org.id,
                    type: localType,
                    name: org.text,
                    extend: false,
                    uuid: '',
                    removable: 1
                });
            }
            orgids.push(org.id);
            sharingGroupPopulateOrganisations();
        })
    }

    function refreshPickedServerList(pickedServers) {
        pickedServers.forEach(function(server) {
            if (serverids.indexOf(server.id) == -1) {
                servers.push({
                    id: server.id,
                    name: server.text,
                    url: $(server.element).data('url'),
                    all_orgs: false,
                    removable: 1
                });
            }
            serverids.push($(this).val());
            sharingGroupPopulateServers();
        })
    }

    function sgSubmitForm() {
        var ajaxData = {
            'organisations': organisations,
            'servers': servers,
            'sharingGroup': {
                'uuid': $('#uuid-field').val(),
                'name': $('#name-field').val(),
                'releasability': $('#releasability-field').val(),
                'description': $('#description-field').val(),
                'active': $('#active-field').is(":checked"),
                'roaming': $('#roaming-field').is(":checked"),
            }
        };
        $('#json-field').val(JSON.stringify(ajaxData));
        $('#json-field').closest('form').submit();
    }

    function toggleNextTab() {
        const activeTabEl = document.querySelector('#tabs-sg-form a[data-bs-toggle].nav-link.active')
        const nexTabEl = activeTabEl.parentElement.nextElementSibling.querySelector('a[data-bs-toggle].nav-link')
        bootstrap.Tab.getOrCreateInstance(nexTabEl).show()
    }

    function updateSummaryText() {
        var summaryorgs = summaryextendorgs = remotesummaryorgs = remotesummaryextendorgs = summaryservers = "";
        var orgcounter = extendcounter = remoteorgcounter = remoteextendcounter = servercounter = 0;
        var sgname = "[Sharing group name not set!]";
        if ($('#name-field').val()) sgname = $('#name-field').val();
        var sgreleasability = "<?= __('[Sharing group releasability not set!]') ?>";
        if ($('#releasability-field').val()) sgreleasability = $('#releasability-field').val();
        $('#summarytitle').text(sgname);
        $('#summaryreleasable').text(sgreleasability);
        organisations.forEach(function(organisation) {
            if (organisation.type == 'local') {
                if (orgcounter > 0) summaryorgs += ", ";
                summaryorgs += organisation.name;
                if (organisation.extend == true) {
                    if (extendcounter > 0) summaryextendorgs += ", "
                    summaryextendorgs += organisation.name;
                    extendcounter++;
                }
                orgcounter++;
            } else {
                if (remoteorgcounter > 0) remotesummaryorgs += ", ";
                remotesummaryorgs += organisation.name;
                if (organisation.extend == true) {
                    if (remoteextendcounter > 0) remotesummaryextendorgs += ", "
                    remotesummaryextendorgs += organisation.name;
                    remoteextendcounter++;
                }
                remoteorgcounter++;
            }
        });
        if (orgcounter == 0) $('#localText').hide();
        if (remoteorgcounter == 0) $('#externalText').hide();
        if (extendcounter == 0) summaryextendorgs = "nobody";
        if (remoteextendcounter == 0) remotesummaryextendorgs = "nobody";
        servers.forEach(function(server) {
            if (servercounter > 0) summaryservers += ", ";
            if (server.id != 0) {
                summaryservers += server.name;
                if (extendcounter == 0) summaryextendorgs = "none";
                servercounter++;
            }
            if (server.id == 0 && server.all_orgs == true) summaryorgs = "all organisations on this instance";
        });
        if ($('#roaming-field').is(":checked")) {
            summaryservers = "any interconnected instances linked by an eligible organisation.";
        } else {
            if (servercounter == 0) {
                summaryservers = "data marked with this sharing group will not be pushed.";
            }
        }
        $('#summarylocal').text(summaryorgs);
        $('#summarylocalextend').text(summaryextendorgs);
        $('#summaryexternal').text(remotesummaryorgs);
        $('#summaryexternalextend').text(remotesummaryextendorgs);
        $('#summaryservers').text(summaryservers);
    }

    function sharingGroupPopulateOrganisations() {
        $('.orgRow').remove();
        var html = '';
        organisations.forEach(function(org, i) {
            html = '<tr id="orgRow' + i + '" class="orgRow">';
            html += '<td class="short">' + org.type + '&nbsp;</td>';
            html += '<td>' + $('<div>').text(org.name).html() + '&nbsp;</td>';
            html += '<td>' + org.uuid + '&nbsp;</td>';
            html += '<td class="short" style="text-align:center;">';
            if (org.removable == 1) {
                html += '<input id="orgExtend' + i + '" type="checkbox" onClick="sharingGroupExtendOrg(' + i + ')" ';
                if (org.extend) html += 'checked';
                html += '>';
            } else {
                html += '<?= $this->Bootstrap->icon('check') ?>'
            }
            html += '</td>';
            html += '<td class="actions short">';
            if (org.removable == 1) html += '<span class="<?= $this->FontAwesome->getClass('trash') ?>" onClick="sharingGroupRemoveOrganisation(' + i + ')"></span>';
            html += '&nbsp;</td></tr>';
            $('#organisations_table tbody').append(html);
        });
    }

    function sharingGroupPopulateServers() {
        $('.serverRow').remove();
        var id = 0;
        var html = '';
        servers.forEach(function(server) {
            html = '<tr id="serverRow' + id + '" class="serverRow">';
            html += '<td>' + server.name + '&nbsp;</td>';
            html += '<td>' + server.url + '&nbsp;</td>';
            html += '<td>';
            html += '<input id="serverAddOrgs' + id + '" type="checkbox" onClick="sharingGroupServerAddOrgs(' + id + ')" ';
            if (server.all_orgs) html += 'checked';
            html += '>';
            html += '</td>';
            html += '<td class="actions short">';
            if (server.removable == 1) html += '<span class="icon-trash" onClick="sharingGroupRemoveServer(' + id + ')"></span>';
            html += '&nbsp;</td></tr>';
            $('#servers_table tbody').append(html);
            id++;
        });
    }

    function sharingGroupPopulateFromJson() {
        var jsonparsed = JSON.parse($('#json-field').val());
        organisations = jsonparsed.organisations;
        servers = jsonparsed.servers;
        if (jsonparsed.sharingGroup.active == 1) {
            $("#active-field").prop("checked", true);
        }
        if (jsonparsed.sharingGroup.roaming == 1) {
            $("#roaming-field").prop("checked", true);
        }
    }

    function sharingGroupExtendOrg(id) {
        organisations[id].extend = $('#orgExtend' + id).is(":checked");
    }

    function sharingGroupServerAddOrgs(id) {
        servers[id].all_orgs = $('#serverAddOrgs' + id).is(":checked");
    }

    function sharingGroupPopulateUsers() {
        $('input[id=SharingGroupServers]').val(JSON.stringify(organisations));
    }

    function sharingGroupRemoveOrganisation(id) {
        organisations.splice(id, 1);
        orgids.splice(id, 1);
        sharingGroupPopulateOrganisations();
    }

    function sharingGroupRemoveServer(id) {
        servers.splice(id, 1);
        serverids.splice(id, 1);
        sharingGroupPopulateServers();
    }
</script>