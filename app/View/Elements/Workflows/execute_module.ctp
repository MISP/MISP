<?php
$type_mapper = [
    'picker' => 'dropdown',
];
?>

<h3><?= __('Stateless module execution') ?></h3>

<div class="row">
    <div class="span6">
        <h5><?= __('Module parameters') ?></h5>
        <div>
            <?php
            $formFields = array_map(function ($param) use ($type_mapper) {
                $param['field'] = $param['id'];
                $param['class'] = 'span6';
                $param['type'] = $type_mapper[$param['type']] ?? $param['type'];
                if (!empty($param['options']) && array_keys($param['options']) === range(0, count($param['options']) - 1)) {
                    // Sequential arrays should be keyed with their value
                    if (!empty($param['options'])) {
                        if (isset($param['options'][0]['name']) && isset($param['options'][0]['value'])) {
                            $tmp = [];
                            foreach ($param['options'] as $option) {
                                $tmp[$option['value']] = $option['name'];
                            };
                            $param['options'] = $tmp;
                        } else {
                            $param['options'] = array_combine($param['options'], $param['options']);
                        }
                    }
                }
                return $param;
            }, $module['params']);
            echo $this->element('genericElements/Form/genericForm', [
                'data' => [
                    'skip_side_menu' => true,
                    'title' => ' ',
                    'fields' => $formFields,
                    'submit' => [
                        'no_submit' => true,
                        'action' => $this->request->params['action'],
                        'ajaxSubmit' => 'submitGenericFormInPlace();'
                    ]
                ]
            ]);
            ?>
        </div>
    </div>
    <div class="span6">
        <h5><?= __('Input data') ?></h5>
        <div>
            <?php
            $formFields = [
                [
                    'field' => 'module_input_data',
                    'type' => 'textarea',
                    'class' => 'span6',
                ]
            ];
            echo $this->element('genericElements/Form/genericForm', [
                'data' => [
                    'skip_side_menu' => true,
                    'title' => ' ',
                    'fields' => $formFields,
                    'submit' => [
                        'no_submit' => true,
                        'action' => $this->request->params['action'],
                        'ajaxSubmit' => 'submitGenericFormInPlace();'
                    ]
                ]
            ]);
            ?>
        </div>
    </div>
</div>

<div>
    <button id="run-module" class="btn btn-primary">
        <span class="fa fa-spin fa-spinner loading-span hidden"></span>
        <?= __('Execute module') ?>
    </button>
</div>

<div class="row" style="margin-top: 10px;">
    <div class="span9">
        <div style="margin: 0.5em 0;">
            <strong><?= __('Execution result:') ?></strong>
            <span id="executionResultStatus" class="label"><?= __('none') ?></span>
        </div>
        <pre id="executionResultText"><?= __('- not executed -') ?></pre>
        <div id="executionResultHtml"></div>
    </div>
</div>

<script>
    var module = <?= JsonTool::encode($module) ?>;
    var $runModuleBtn = $('#run-module')
    var $executionResultStatus = $('#executionResultStatus')
    var $executionResultText = $('#executionResultText')
    var $formParams = $('#WorkflowModuleViewForm')
    var $inputData = $('#WorkflowModuleInputData')
    $(document).ready(function() {
        $runModuleBtn.click(submitModuleExecution)
        $('select[multiple]').chosen()
    })

    function submitModuleExecution() {
        var data = collectData()
        performRequest(data)
    }

    function toggleLoading($button, loading) {
        if (loading) {
            $button
                .prop('disabled', true)
                .find('.loading-span').show()
        } else {
            $button
                .prop('disabled', false)
                .find('.loading-span').hide()
        }
    }

    function collectData() {
        var formData = new FormData($formParams[0])
        var indexedParams = {}
        Array.from(formData.keys()).forEach(function(fullFieldName) {
            var myRegexp = new RegExp(/data\[Workflow\]\[(\w+)\](\[\])*/, 'g');
            var match = myRegexp.exec(fullFieldName);
            if (match != null) {
                fieldName = match[1]
                isMultiple = match[2] !== undefined
                if (isMultiple) {
                    indexedParams[fieldName] = formData.getAll(fullFieldName)
                } else {
                    indexedParams[fieldName] = formData.get(fullFieldName)
                }
            }
        })
        return {
            module_indexed_param: indexedParams,
            input_data: $inputData.val(),
        }
    }

    function showExecutionResult(jqXHR, result) {
        $executionResultStatus
            .text(jqXHR.status + ' [' + jqXHR.duration + ' ms]')
            .removeClass(['label-success', 'label-important'])
            .addClass(jqXHR.status == 200 ? 'label-success' : 'label-important')
        if (typeof result === 'object') {
            $executionResultText.text(JSON.stringify(result, '', 4));
        } else {
            $('#executionResultHtml').html(result);
            // $executionResultText.text(result);
        }
    }

    function performRequest(data) {
        url = '<?= $baseurl ?>/workflows/moduleStatelessExecution/<?= h($module['id']) ?>'
        var start = new Date().getTime();
        $.ajax({
            data: data,
            beforeSend: function() {
                toggleLoading($runModuleBtn, true)
            },
            success: function(result, textStatus, jqXHR) {
                jqXHR.duration = (new Date().getTime() - start);
                if (result) {
                    showExecutionResult(jqXHR, result)
                }
            },
            error: function(jqXHR, _, _) {
                jqXHR.duration = (new Date().getTime() - start);
                errorThrown = jqXHR.responseJSON ? jqXHR.responseJSON.errors : (jqXHR.responseText ? jqXHR.responseText : jqXHR.statusText)
                showExecutionResult(jqXHR, errorThrown)
            },
            complete: function() {
                toggleLoading($runModuleBtn, false)
            },
            type: 'post',
            url: url
        })
    }
</script>

<style>
    .loading-span {
        margin-right: 5px;
        margin-left: 0px;
        line-height: 20px;
    }
</style>