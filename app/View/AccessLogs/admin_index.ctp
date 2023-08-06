<div class="logs index">
    <h2><?= __('Access logs') ?></h2>
    <div>
        <div id="builder"></div>
        <div style="display: flex; justify-content: flex-end; margin-top: 5px;">
            <button id="qbSubmit" type="button" class="btn btn-success" style="margin-right: 5px;"> <i class="fa fa-filter"></i> <?= __('Filter'); ?></button>
            <button id="qbClear" type="button" class="btn btn-xs btn-danger" title="<?= __('Clear filtering rules'); ?>"> <i class="fa fa-times"></i> <?= __('Clear'); ?></button>
        </div>
    </div>
    <?php
    echo $this->Html->script('moment.min');
    echo $this->Html->script('doT');
    echo $this->Html->script('extendext');
    echo $this->Html->css('query-builder.default');
    echo $this->Html->script('query-builder');
    ?>
    <script>
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
                },
                {
                    input: "select",
                    type: "string",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "request_method",
                    label: "HTTP request method",
                    values: ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"],
                },
                {
                    input: "text",
                    type: "integer",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "response_code",
                    label: "HTTP response code",
                    validation: {
                        min: 100,
                        max: 599
                    }
                },
                {
                    input: "text",
                    type: "string",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "controller",
                    label: "Controller",
                },
                {
                    input: "text",
                    type: "string",
                    operators: [
                        "equal",
                    ],
                    unique: true,
                    id: "action",
                    label: "Action",
                },
                {
                    input: "text",
                    type: "string",
                    operators: [
                        "contains",
                    ],
                    unique: true,
                    id: "url",
                    label: "URL",
                },
                {
                    input: "text",
                    type: "string",
                    operators: [
                        "contains",
                    ],
                    unique: true,
                    id: "user_agent",
                    label: "User agent",
                },
                {
                    type: "double",
                    operators: [
                        "greater_or_equal",
                    ],
                    unique: true,
                    id: "memory_usage",
                    label: "Memory usage",
                    description: "In MB",
                    validation: {
                        min: 0,
                        step: 0.01
                    }
                },
                {
                    type: "double",
                    operators: [
                        "greater_or_equal",
                    ],
                    unique: true,
                    id: "duration",
                    label: "Duration",
                    description: "In milliseconds (1 second is equal to 1000 milliseconds)",
                    validation: {
                        min: 0,
                    }
                },
                {
                    type: "integer",
                    operators: [
                        "greater_or_equal",
                    ],
                    unique: true,
                    id: "query_count",
                    label: "Query count",
                    description: "Number of SQL queries",
                    validation: {
                        min: 0,
                    }
                }
            ],
            rules: {
                condition: 'AND',
                not: false,
                rules: <?= JsonTool::encode($qbRules) ?>,
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
            $paginator = $this->LightPaginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            $paginator .= $this->LightPaginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            $paginator .= $this->LightPaginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $paginator;
            ?>
        </ul>
    </div>
    <table class="table table-striped table-hover table-condensed">
        <tr>
            <th><?= $this->LightPaginator->sort('created') ?></th>
            <th><?= $this->LightPaginator->sort('user_id', __('User')) ?></th>
            <th><?= $this->LightPaginator->sort('ip', __('IP')) ?></th>
            <th><?= $this->LightPaginator->sort('org_id', __('Org')) ?></th>
            <th><?= $this->LightPaginator->sort('request_method', __('Request')) ?></th>
            <th><?= $this->LightPaginator->sort('url', __('URL')) ?></th>
            <th title="<?= __('HTTP response code') ?>"><?= $this->LightPaginator->sort('response_code', __('Code')) ?></th>
            <th title="<?= __('Memory used during responding to request') ?>"><?= $this->LightPaginator->sort('memory_usage', __('Memory')) ?></th>
            <th title="<?= __('Time used during responding to request') ?>"><?= $this->LightPaginator->sort('duration', __('Duration')) ?></th>
            <th title="<?= __('SQL database query count') ?>"><?= $this->LightPaginator->sort('query_count', __('Queries')) ?></th>
        </tr>
        <?php foreach ($list as $item): ?>
            <tr>
                <td class="short"><?= $this->Time->time($item['AccessLog']['created']); ?></td>
                <td class="short" data-search="user" data-search-value="<?= h($item['AccessLog']['user_id']) ?>"><?php
                    if (isset($item['User']['email'])) {
                        echo '<a href="' . $baseurl . '/admin/users/view/' . h($item['User']['id']) . '">' . h($item['User']['email']) . '</a>';
                    } else {
                        echo __('<i>Deleted user #%s</i>', h($item['AccessLog']['user_id']));
                    }

                    if (!empty($item['AccessLog']['authkey_id'])) {
                        echo ' <i class="fas fa-cogs" title="' . __('Request trough API by auth key #%s', h($item['AccessLog']['authkey_id'])) . '"></i>';
                    }
                    ?></td>
                <td class="short" data-search="ip" data-search-value="<?= h($item['AccessLog']['ip']) ?>"><?= h($item['AccessLog']['ip']) ?></td>
                <td class="short" data-search="org" data-search-value="<?= h($item['AccessLog']['org_id']) ?>">
                    <?php if (isset($item['Organisation']) && $item['Organisation']['id']) {
                        echo $this->OrgImg->getOrgLogo($item, 24);
                    } else if ($item['AccessLog']['org_id'] != 0) {
                        echo __('<i>Deleted org #%s</i>', h($item['AccessLog']['org_id']));
                    }
                    ?>
                </td>
                <td class="short" data-search="request_method" data-search-value="<?= h($item['AccessLog']['request_method']) ?>">
                    <span title="<?= __("User agent: %s\nRequest ID: %s", h($item['AccessLog']['user_agent']), h($item['AccessLog']['request_id'])) ?>"><?= h($item['AccessLog']['request_method']) ?></span>
                    <?= in_array($item['AccessLog']['request_method'], ['POST', 'PUT']) ? ' <a href="#" class="far fa-file request" title="' . __('Show HTTP request') . '" data-log-id="' . h($item['AccessLog']['id']) . '"></i>' : '' ?>
                </td>
                <td class="short" data-search="controller:action" data-search-value="<?= h($item['AccessLog']['controller']) . ':' . h($item['AccessLog']['action']) ?>" title="<?= __('Controller: %s, action: %s', h($item['AccessLog']['controller']), h($item['AccessLog']['action'])) ?>"><?= h($item['AccessLog']['url']) ?></td>
                <td class="short" data-search="response_code" data-search-value="<?= h($item['AccessLog']['response_code']) ?>"><?= h($item['AccessLog']['response_code']) ?></td>
                <td class="short"><?= CakeNumber::toReadableSize($item['AccessLog']['memory_usage']) ?></td>
                <td class="short"><?= $item['AccessLog']['duration'] ?> ms</td>
                <td class="short"><?= $item['AccessLog']['query_count'] . ($item['AccessLog']['has_query_log'] ? ' <a href="#" class="fas fa-database query-log" title="' . __('Show SQL queries') . '" data-log-id="' . h($item['AccessLog']['id']) . '"></i>' : '') ?>
                </td>
            </tr>
        <?php endforeach; ?>
    </table>
    <div class="pagination">
        <ul>
            <?= $paginator ?>
        </ul>
    </div>
</div>
<script>
    var passedArgs = <?= $passedArgs ?>;

    $('.request').click(function (e) {
        e.preventDefault();
        var id = $(this).data('log-id');
        $.get(baseurl + "/admin/access_logs/request/" + id, function(data) {
            var $popoverFormLarge = $('#popover_form_large');
            $popoverFormLarge.html(data);
            openPopup($popoverFormLarge);
        }).fail(xhrFailCallback);
        return false;
    });

    $('.query-log').click(function (e) {
        e.preventDefault();
        var id = $(this).data('log-id');
        $.get(baseurl + "/admin/access_logs/queryLog/" + id, function(data) {
            var $popoverFormLarge = $('#popover_form_large');
            $popoverFormLarge.html(data);
            openPopup($popoverFormLarge);
        }).fail(xhrFailCallback);
        return false;
    });

    $(function() {
        filterSearch(function (e, searchKey, searchValue) {
            if (searchKey === 'controller:action') {
                var val = searchValue.split(":");
                passedArgs['controller'] = encodeURIComponent(val[0]);
                passedArgs['action'] = encodeURIComponent(val[1]);
            } else {
                passedArgs[searchKey] = encodeURIComponent(searchValue);
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
    });
</script>
<?= $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'logs', 'menuItem' => 'listAccessLogs']);

