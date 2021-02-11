<div class="logs index">
    <h2><?= __('Audit logs') ?></h2>
    <div>
        <div id="builder"></div>
        <div style="display: flex; justify-content: flex-end; margin-top: 5px;">
            <button id="qbSubmit" type="button" class="btn btn-success" style="margin-right: 5px;"> <i class="fa fa-filter"></i> <?= __('Filter'); ?></button>
            <button id="qbClear" type="button" class="btn btn-xs btn-danger" title="<?= __('Clear filtering rules'); ?>"> <i class="fa fa-times"></i> <?= __('Clear'); ?></button>
        </div>
    </div>
    <?php
        echo $this->Html->script('moment-with-locales');
        echo $this->Html->script('doT');
        echo $this->Html->script('extendext');
        echo $this->Html->css('query-builder.default');
        echo $this->Html->script('query-builder');
    ?>
    <script type="text/javascript">
        var qbOptions = {
            plugins: {
                'unique-filter': null,
                'filter-description' : {
                    mode: 'inline'
                },
            },
            conditions: ['AND'],
            allow_empty: true,
            filters: [
                {
                    id: 'created',
                    label: 'Created',
                    type: 'date',
                    operators: ['greater_or_equal', 'between'],
                    validation: {
                        format: 'YYYY-MM-DD'
                    },
                    plugin: 'datepicker',
                    plugin_config: {
                        format: 'yyyy-mm-dd',
                        todayBtn: 'linked',
                        todayHighlight: true,
                        autoclose: true
                    }
                },
                {
                    input: "select",
                    type: "string",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "action",
                    label: "Action",
                    values: <?= json_encode($actions) ?>
                },
                {
                    input: "select",
                    type: "string",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "model",
                    label: "Model type",
                    values: <?= json_encode($models) ?>
                },
                {
                    input: "text",
                    type: "integer",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "model_id",
                    label: "Model ID",
                },
                {
                    input: "text",
                    type: "integer",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "event_id",
                    label: "Belongs to event with ID",
                },
                {
                    input: "text",
                    type: "string",
                    operators: [
                        "contains",
                    ],
                    unique: true,
                    id: "model_title",
                    label: "Model title",
                },
                {
                    input: "text",
                    type: "string",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "ip",
                    label: "IP",
                },
                {
                    input: "text",
                    type: "string",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "user",
                    label: "User",
                    description: "User ID or mail",
                },
                {
                    input: "text",
                    type: "integer",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "authkey_id",
                    label: "Authentication key ID",
                },
                {
                    input: "select",
                    type: "integer",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "request_type",
                    label: "Request type",
                    values: {0: "Browser", 1: "API", 2: "CLI or background job"}
                },
                {
                    input: "text",
                    type: "string",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "request_id",
                    label: "Request ID",
                    description: "Request ID from X-Request-ID HTTP header",
                },
                {
                    input: "text",
                    type: "string",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "org",
                    label: "Organisation",
                    description: "Organisation ID, UUID or name",
                }
            ],
            rules: {
                condition: 'AND',
                not: false,
                rules: <?= json_encode($qbRules) ?>,
                flags: {
                    no_add_group: true,
                    condition_readonly: true,
                }
            },
            icons: {
                add_group: 'fa fa-plus-square',
                add_rule: 'fa fa-plus-circle',
                remove_group: 'fa fa-minus-square',
                remove_rule: 'fa fa-minus-circle',
                error: 'fa fa-exclamation-triangle'
            }
        };

        $(function() {
            var $builder = $('#builder');

            // Fix for Bootstrap Datepicker
            $builder.on('afterUpdateRuleValue.queryBuilder', function (e, rule) {
                if (rule.filter.plugin === 'datepicker') {
                    rule.$el.find('.rule-value-container input').datepicker('update');
                }
            });

            var queryBuilder = $builder.queryBuilder(qbOptions);
            queryBuilder = queryBuilder[0].queryBuilder;

            $('#qbClear').off('click').on('click', function () {
                queryBuilder.reset();
            });

            // Submit on enter
            $builder.on('keyup', 'input[type=text], select', function (event) {
                if (event.keyCode === 13) {
                    $('#qbSubmit').click();
                }
            });

            $('#qbSubmit').off('click').on('click', function () {
                var rules = queryBuilder.getRules({skip_empty: true});
                passedArgs = [];
                for (var key in rules.rules) {
                    var rule = rules.rules[key];
                    var k = rule.id;
                    var v = rule.value;
                    if (Array.isArray(v)) {
                        v = v.join('||');
                    }
                    passedArgs[k] = v;
                }

                var url = here;
                for (var key in passedArgs) {
                    if (typeof key === 'number') {
                        url += "/" + passedArgs[key];
                    } else if (key !== 'page') {
                        url += "/" + key + ":" + encodeURIComponent(passedArgs[key]);
                    }
                }
                window.location.href = url;
            });
        });
    </script>
    <div class="pagination">
        <ul>
            <?php
            $paginator = $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            $paginator .= $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            $paginator .= $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $paginator;
            ?>
        </ul>
    </div>
    <table class="table table-striped table-hover table-condensed">
        <tr>
            <th><?= $this->Paginator->sort('created') ?></th>
            <th><?= $this->Paginator->sort('user_id', __('User')) ?></th>
            <th><?= $this->Paginator->sort('ip', __('IP')) ?></th>
            <th><?= $this->Paginator->sort('org_id', __('Org')) ?></th>
            <th><?= $this->Paginator->sort('action') ?></th>
            <th><?= __('Model') ?></th>
            <th><?= __('Title') ?></th>
            <th><?= __('Change') ?></th>
        </tr>
        <?php foreach ($list as $item): ?>
        <tr>
            <td class="short"><?= $this->Time->time($item['AuditLog']['created']); ?></td>
            <td class="short" data-search="user" data-search-value="<?= h($item['AuditLog']['user_id']) ?>"><?php
                if (isset($item['AuditLog']['user_id']) && $item['AuditLog']['user_id'] == 0) {
                    echo __('SYSTEM');
                } else if (isset($item['User']['email'])) {
                    echo '<a href="' . $baseurl . '/admin/users/view/' . h($item['User']['id']) . '">' . h($item['User']['email']) . '</a>';
                } else {
                    echo __('<i>Deleted user #%s</i>', h($item['AuditLog']['user_id']));
                }

                if ($item['AuditLog']['request_type'] == AuditLog::REQUEST_TYPE_CLI) {
                    echo ' <i class="fas fa-terminal" title="' . __('Action done by CLI or background job') .'"></i>';
                } else if ($item['AuditLog']['request_type'] == AuditLog::REQUEST_TYPE_API) {
                    $key = $item['AuditLog']['authkey_id'] ? ' ' . __('by auth key #%s', h($item['AuditLog']['authkey_id'])) : '';
                    echo ' <i class="fas fa-cogs" title="' . __('Action done trough API') . $key . '"></i>';
                }
                ?></td>
            <td class="short" data-search="ip" data-search-value="<?= h($item['AuditLog']['ip']) ?>"><?= h($item['AuditLog']['ip']) ?></td>
            <td class="short" data-search="org" data-search-value="<?= h($item['AuditLog']['org_id']) ?>">
                <?php if (isset($item['Organisation']) && $item['Organisation']['id']) {
                    echo $this->OrgImg->getOrgLogo($item, 24);
                } else if ($item['AuditLog']['org_id'] != 0) {
                    echo __('<i>Deleted org #%s</i>', h($item['AuditLog']['org_id']));
                }
                ?>
            </td>
            <td class="short" data-search="action" data-search-value="<?= h($item['AuditLog']['action']) ?>"><?= h($item['AuditLog']['action_human']) ?></td>
            <td class="short" data-search="model" data-search-value="<?= h($item['AuditLog']['model']) . ':' . h($item['AuditLog']['model_id']) ?>">
                <?php $title = isset($item['AuditLog']['event_info']) ? ' title="' . __('Event #%s: %s', $item['AuditLog']['event_id'], h($item['AuditLog']['event_info'])) . '"' : '' ?>
                <?= isset($item['AuditLog']['model_link']) ? '<a href="' . h($item['AuditLog']['model_link']) . '"' . $title . '>' : '' ?>
                <?= h($item['AuditLog']['model']) . ' #' . h($item['AuditLog']['model_id']) ?>
                <?= isset($item['AuditLog']['model_link']) ? '</a>' : '' ?>
            </td>
            <td class="limitedWidth"><?= h($item['AuditLog']['title']) ?></td>
            <td ondblclick="showFullChange(<?= h($item['AuditLog']['id']) ?>)"><?= $this->element('AuditLog/change', ['item' => $item]) ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
    <p>
    <?= $this->Paginator->counter(array(
        'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
    ));
    ?>
    </p>
    <div class="pagination">
        <ul>
        <?= $paginator ?>
        </ul>
    </div>
</div>
<script type="text/javascript">
    var passedArgs = <?= $passedArgs ?>;

    function showFullChange(id) {
        $.get(baseurl + "/audit_logs/fullChange/" + id, function(data) {
            var $popoverFormLarge = $('#popover_form_large');
            $popoverFormLarge.html(data);
            $popoverFormLarge.find("span.json").each(function () {
                $(this).html(syntaxHighlightJson($(this).text()));
            });
            openPopup($popoverFormLarge);
        });
        return false;
    }

    $('td[data-search]').mouseenter(function() {
        var $td = $(this);
        if ($td.data('search-value').length === 0) {
            return;
        }

        $td.find('#quickEditButton').remove(); // clean all similar if exist
        var $div = $('<div id="quickEditButton"></div>');
        $div.addClass('quick-edit-row-div');
        var $span = $('<span></span>');
        $span.addClass('fa-as-icon fa fa-search-plus');
        $span.css('font-size', '12px');
        $div.append($span);
        $td.append($div);

        $span.click(function() {
            if ($td.data('search') === 'model') {
                var val = $td.data('search-value').split(":");
                passedArgs['model'] = encodeURIComponent(val[0]);
                passedArgs['model_id'] = encodeURIComponent(val[1]);
            } else {
                passedArgs[$td.data('search')] = encodeURIComponent($td.data('search-value'));
            }

            var url = here;
            for (var key in passedArgs) {
                if (typeof key === 'number') {
                    url += "/" + passedArgs[key];
                } else if (key !== 'page') {
                    url += "/" + key + ":" + passedArgs[key];
                }
            }
            window.location.href = url;
        });

        $td.off('mouseleave').on('mouseleave', function() {
            $div.remove();
        });
    });
</script>
<?= $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'logs', 'menuItem' => 'listAuditLogs']);

