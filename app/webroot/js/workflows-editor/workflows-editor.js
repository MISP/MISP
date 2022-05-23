var dotBlock_default = doT.template(' \
<div class="canvas-workflow-block" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%;"> \
        <div class="default-main-container"> \
            <i class="fa-fw fa-{{=it.icon}} {{=it.icon_class}}"></i> \
            <strong style="margin-left: 0.25em;"> \
                {{=it.name}} \
            </strong> \
            <span style="margin-left: auto;"> \
                <span class="block-notification-container"> \
                    {{=it._block_notification_html}} \
                </span> \
                <span> \
                    <a href="#block-modal" role="button" class="btn btn-mini" data-toggle="modal"><i class="fas fa-ellipsis-h"></i></a> \
                </span> \
            </span> \
        </div> \
        <div class="muted" class="description" style="margin-bottom: 0.5em;">{{=it.description}}</div> \
        {{=it._block_param_html}} \
    </div> \
</div>')

var dotBlock_trigger = dotBlock_default

var dotBlock_IF = doT.template(' \
<div class="canvas-workflow-block" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%;"> \
        <div class="default-main-container"> \
            <i class="fa-fw fa-{{=it.icon}} {{=it.icon_class}}"></i> \
            <strong style="margin-left: 0.25em;"> \
                {{=it.name}} \
            </strong> \
            <span style="margin-left: auto;"> \
                <span class="block-notification-container"> \
                    {{=it._block_notification_html}} \
                </span> \
                <span> \
                    <a href="#block-modal" role="button" class="btn btn-mini" data-toggle="modal"><i class="fas fa-ellipsis-h"></i></a> \
                </span> \
            </span> \
        </div> \
        {{=it._block_param_html}} \
    </div> \
</div>')

var dotBlock_parallel = doT.template(' \
<div class="canvas-workflow-block" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%;"> \
        <div class="default-main-container"> \
            <i class="fa-fw fa-{{=it.icon}} {{=it.icon_class}}"></i> \
            <strong style="margin-left: 0.25em;"> \
                {{=it.name}} \
            </strong> \
            <span style="margin-left: auto;"> \
                <span class="block-notification-container"> \
                    {{=it._block_notification_html}} \
                </span> \
                <span> \
                    <a href="#block-modal" role="button" class="btn btn-mini" data-toggle="modal"><i class="fas fa-ellipsis-h"></i></a> \
                </span> \
            </span> \
        </div> \
        {{=it._block_param_html}} \
        <div class="muted" class="description" style="margin-bottom: 0.5em;">{{=it.description}}</div> \
    </div> \
</div>')

var classBySeverity = {
    'info': 'info',
    'warning': 'warning',
    'error': 'danger',
}
var iconBySeverity = {
    'info': 'fa-times-circle',
    'warning': 'fa-exclamation-triangle',
    'error': 'fa-exclamation-circle',
}
var severities = ['info', 'warning', 'error']

var workflow_id = 0
var contentChanged = false
var lastModified = 0
var graphPooler

function sanitizeObject(obj) {
    var newObj = {}
    for (var key of Object.keys(obj)) {
        var newVal = $('</p>').text(obj[key]).html()
        newObj[key] = newVal
    }
    return newObj
}


function initDrawflow() {
    workflow_id = $drawflow.data('workflowid')
    editor = new Drawflow($drawflow[0]);
    editor.start();

    editor.on('nodeCreated', function() {
        invalidateContentCache()
        toggleTriggersDraggableState()
    })
    editor.on('nodeRemoved', function () {
        invalidateContentCache()
        toggleTriggersDraggableState()
    })
    editor.on('nodeDataChanged', invalidateContentCache)
    editor.on('nodeMoved', invalidateContentCache)
    editor.on('connectionCreated', function() {
        invalidateContentCache()
        if (!editor.isLoading) {
            graphPooler.do()
        }
    })
    editor.on('connectionRemoved', function() {
        invalidateContentCache()
        if (!editor.isLoading) {
            graphPooler.do()
        }
    })

    $('#block-tabs a').click(function (e) {
        e.preventDefault();
        $(this).tab('show');
    })

    $chosenWorkflows.chosen()
        .on('change', function (evt, param) {
            var selection = param.selected
            window.location = '/workflows/editor/' + selection
        });
    $chosenBlocks.chosen()
        .on('change', function (evt, param) {
            var selection = param.selected
            var selected_module = all_blocks_by_id[selection]
            var canvasBR = $canvas[0].getBoundingClientRect()
            var position = {
                top: canvasBR.height / 2 - canvasBR.top,
                left: canvasBR.left + canvasBR.width / 2
            }
            addNode(selected_module, position)
        });

    $('.sidebar-workflow-block').each(function () {
        var $block = $(this)
        all_blocks.forEach(function (block) {
            if ($block[0].id == block['id']) {
                $block.data('block', block)
            }
        });
    })

    $('.sidebar-workflow-block').each(function() {
        if ($(this).data('block').disabled) {
            $(this).addClass('disabled')
        }
        $(this).draggable({
            helper: "clone",
            scroll: false,
            disabled: $(this).data('block').disabled,
            start: function (event, ui) {
            },
            stop: function (event, ui) {
            }
        });
    })

    $canvas.droppable({
        drop: function (event, ui) {
            addNode(ui.draggable.data('block'), ui.position)
        }
    });

    graphPooler = new TaskScheduler(checkGraphProperties, {
        interval: 10000,
        slowInterval: 60000,
    })

    loadWorkflow().then(function() {
        graphPooler.start(undefined)
    })
    $saveWorkflowButton.click(saveWorkflow)
    $importWorkflowButton.click(importWorkflow)
    $exportWorkflowButton.click(exportWorkflow)
    $blockModal.on('show', function (evt) {
        var selectedBlock = getSelectedBlock()
        buildModalForBlock(selectedBlock.id, selectedBlock.data)
    })
    $blockModalDeleteButton.click(function() {
        if (confirm('Are you sure you want to remove this block?')) {
            deleteSelectedNode()
            $blockModal.modal('hide')
        }
    })

}

function buildModalForBlock(node_id, block) {
    var html = genBlockParamHtml(block)
    $blockModal
        .data('selected-block', block)
        .data('selected-node-id', node_id)
    $blockModal.find('.modal-body').empty().append(html)
}

function buildNotificationModalForBlock(node_id, block) {
    var html = genBlockNotificationForModalHtml(block)
    $blockNotificationModal
        .data('selected-block', block)
        .data('selected-node-id', node_id)
    $blockNotificationModal.find('.modal-body').empty().append(html)
}

function showNotificationModalForBlock(clicked) {
    var selectedBlock = getSelectedBlock()
    buildNotificationModalForBlock(selectedBlock.id, selectedBlock.data)
    $blockNotificationModal.modal('show')
}

function showNotificationModalForModule(module_id, data) {
    buildNotificationModalForBlock(module_id, data)
    $blockNotificationModal.modal('show')
}

function showNotificationModalForSidebarModule(clicked) {
    var $block = $(clicked).closest('.sidebar-workflow-block')
    var blockID = $block.data('blockid')
    showNotificationModalForModule(blockID, all_blocks_by_id[blockID])
}

function invalidateContentCache() {
    changeDetectedMessage1 = "[unsaved]"
    changeDetectedMessage2 = " Last saved change: "
    contentTimestamp = true
    toggleSaveButton(true)
    $lastModifiedField
        .removeClass('label-success')
        .addClass('label-important')
        .text(changeDetectedMessage1 + changeDetectedMessage2 + moment(parseInt(lastModified)).fromNow())
}

function revalidateContentCache() {
    changeDetectedMessage1 = "[saved]"
    changeDetectedMessage2 = " Last saved change: "
    contentChanged = false
    toggleSaveButton(false)
    $lastModifiedField
        .removeClass('label-important')
        .addClass('label-success')
        .text(changeDetectedMessage1 + changeDetectedMessage2 + moment(parseInt(lastModified)).fromNow())
}


function addNode(block, position) {
    var node_uid = uid() // only used for UI purposes
    block['node_uid'] = node_uid
    var canvasPosition = $canvas[0].getBoundingClientRect()
    
    var adjsutedPosition = {
        left: position.left - canvasPosition.left,
        top: position.top,
    }

    // TODO: Take into account zoon level
    // pos_x = pos_x * (editor.precanvas.clientWidth / (editor.precanvas.clientWidth * editor.zoom)) - (editor.precanvas.getBoundingClientRect().x * (editor.precanvas.clientWidth / (editor.precanvas.clientWidth * editor.zoom)));
    // pos_y = pos_y * (editor.precanvas.clientHeight / (editor.precanvas.clientHeight * editor.zoom)) - (editor.precanvas.getBoundingClientRect().y * (editor.precanvas.clientHeight / (editor.precanvas.clientHeight * editor.zoom)));

    block['_block_param_html'] = genBlockParamHtml(block)
    block['_block_notification_html'] = genBlockNotificationHtml(block)
    var html = getTemplateForBlock(block)
    var blockClass = block.class === undefined ? [] : block.class
    blockClass = !Array.isArray(blockClass) ? [blockClass] : blockClass
    blockClass.push('block-type-' + (block.html_template !== undefined ? block.html_template : 'default'))
    editor.addNode(
        block.name,
        block.inputs === undefined ? 1 : block.inputs,
        block.outputs === undefined ? 1 : block.outputs,
        adjsutedPosition.left,
        adjsutedPosition.top,
        blockClass.join(' '),
        block,
        html
    );
}

function toggleTriggersDraggableState() {
    if (editor.isLoading) {
        return
    }
    var data = Object.values(getEditorData())
    var registeredTriggers = {}
    for (var i = 0; i < data.length; i++) {
        var node = data[i];
        if (node.data.module_type == 'trigger') {
            registeredTriggers[node.data.id] = true
        }
    }
    $blockContainerTriggers.find('.sidebar-workflow-block')
        .filter(function () {
            return !$(this).hasClass('ui-draggable-dragging')
                && $(this).data('block').disabled === undefined
        })
        .draggable('option', { disabled: false })
        .removeClass(['disabled', 'disabled-one-instance'])
        .attr('title', '')
    for (var i = 0; i < data.length; i++) {
        var node = data[i];
        if (node.data.module_type == 'trigger') {
            $blockContainerTriggers.find('#'+node.data.id + '.sidebar-workflow-block')
                .filter(function () {
                    return !$(this).hasClass('ui-draggable-dragging')
                        && $(this).data('block').disabled === undefined
                        && registeredTriggers[$(this).data('block').id] !== undefined
                })
                .draggable('option', { disabled: true })
                .addClass(['disabled', 'disabled-one-instance'])
                .attr('title', 'Only one instance of this trigger is allowed per workflow')
        }
    }
}

function getEditorData() {
    var data = {} // Make sure nodes are index by their internal IDs
    var editorExport = editor.export().drawflow.Home.data
    editorExport = Array.isArray(editorExport) ? editorExport : Object.values(editorExport)
    editorExport.forEach(function(node) {
        if (node !== null) { // for some reason, the editor create null nodes
            data[node.id] = node
        }
    })
    return data
}

function loadWorkflow() {
    return new Promise(function (resolve, reject) {
        editor.isLoading = true
        fetchWorkflow(workflow_id, function(workflow) {
            lastModified = workflow.timestamp + '000'

            // We cannot rely on the editor's import function as it recreates the nodes with the saved HTML instead of rebuilding them
            // We have to manually add the nodes and their connections
            Object.values(workflow.data).forEach(function(block) {
                var node_uid = uid() // only used for UI purposes
                block.data['node_uid'] = node_uid
                block.data['_block_param_html'] = genBlockParamHtml(block.data)
                block.data['_block_notification_html'] = genBlockNotificationHtml(block.data)
                var html = getTemplateForBlock(block.data)
                editor.nodeId = block.id // force the editor to use the saved id of the block instead of generating a new one
                editor.addNode(
                    block.name,
                    Object.values(block.inputs).length,
                    Object.values(block.outputs).length,
                    block.pos_x,
                    block.pos_y,
                    block.class,
                    block.data,
                    html
                );
            })
            Object.values(workflow.data).forEach(function (block) {
                for (var input_name in block.inputs) {
                    block.inputs[input_name].connections.forEach(function(connection) {
                        editor.addConnection(connection.node, block.id, connection.input, input_name)
                    })
                }
            })
            editor.isLoading = false
            toggleTriggersDraggableState()
            revalidateContentCache()
            resolve()
        })
    })
}


/* API */
function fetchWorkflow(id, callback) {
    var url = '/workflows/view/' + id + '.json'
    $.ajax({
        beforeSend: function () {
            toggleEditorLoading(true, 'Loading workflow')
        },
        success: function (workflow, textStatus) {
            if (workflow) {
                workflow = workflow.Workflow
                showMessage('success', 'Workflow fetched');
                if (callback !== undefined) {
                    callback(workflow)
                }
            }
        },
        error: function (jqXHR, textStatus, errorThrown) {
            showMessage('fail', saveFailedMessage + ': ' + errorThrown);
            if (callback !== undefined) {
                callback(false)
            }
        },
        complete: function () {
            toggleEditorLoading(false)
        },
        type: "post",
        url: url
    })
}

function saveWorkflow(confirmSave, callback) {
    saveConfirmMessage = 'Confirm saving the current state of the workflow'
    saveFailedMessage = 'Failed to save the workflow'
    confirmSave = confirmSave === undefined ? true : confirmSave
    if (confirmSave && !confirm(saveConfirmMessage)) {
        return
    }
    var url = baseurl + "/workflows/edit/" + workflow_id
    fetchFormDataAjax(url, function (formHTML) {
        $('body').append($('<div id="temp" style="display: none"/>').html(formHTML))
        var $tmpForm = $('#temp form')
        var formUrl = $tmpForm.attr('action')
        $tmpForm.find('[name="data[Workflow][data]"]').val(JSON.stringify(getEditorData()))

        $.ajax({
            data: $tmpForm.serialize(),
            beforeSend: function () {
                toggleLoadingInSaveButton(true)
            },
            success: function (workflow, textStatus) {
                if (workflow) {
                    showMessage('success', workflow.message);
                    if (workflow.data !== undefined) {
                        lastModified = workflow.data.Workflow.timestamp + '000'
                        revalidateContentCache()
                    }
                }
            },
            error: function (jqXHR, _, _) {
                errorThrown = jqXHR.responseJSON.errors
                showMessage('fail', saveFailedMessage + ': ' + errorThrown);
            },
            complete: function () {
                $('#temp').remove();
                toggleLoadingInSaveButton(false)
                if (callback !== undefined) {
                    callback()
                }
            },
            type: "post",
            url: formUrl
        })
    })
}

function checkGraphProperties() {
    var url = baseurl + "/workflows/hasAcyclicGraph/"
    var graphData = getEditorData()
    $.ajax({
        data: graphData,
        success: function (data, textStatus) {
            highlightGraphIssues(data);
            graphPooler.unthrottle()
        },
        error: function (jqXHR, textStatus, errorThrown) {
            if (jqXHR.status === 401) {
                graphPooler.throttle()
            }
            showMessage('fail', 'Could not check graph properties')
        },
        type: "post",
        url: url,
    });
}

function importWorkflow() {
    showMessage('fail', 'Import workflow: to be implemented')
}

function exportWorkflow() {
    showMessage('fail', 'Export workflow: to be implemented')
}

function getSelectedNodeID() {
    return editor.node_selected.id // Couldn't find a better way to get the selected node
}

function getSelectedNodeIDInteger() {
    return parseInt(getSelectedNodeID().split('-')[1]) // Couldn't find a better way to get the selected node
}

function getSelectedBlock() {
    return editor.getNodeFromId(getSelectedNodeIDInteger())
}

function deleteSelectedNode() {
    editor.removeNodeId(getSelectedNodeID())
}

/* UI Utils */
function toggleSaveButton(enabled) {
    $saveWorkflowButton
        .prop('disabled', !enabled)
}

function toggleLoadingInSaveButton(saving) {
    // TODO: Use I18n strings instead
    toggleSaveButton(!saving)
    if (saving) {
        $saveWorkflowButton.find('.loading-span').show();
        toggleEditorLoading(true, 'Saving workflow')
    } else {
        $saveWorkflowButton.find('.loading-span').hide();
        toggleEditorLoading(false)
    }
}

function toggleEditorLoading(loading, message) {
    loadingSpanAnimation = '<span class="fa fa-spin fa-spinner loading-span"></span>'
    if (loading) {
        $loadingBackdrop.show()
        $loadingBackdrop.append(
            $('<div/>').css({
                'font-size': '20px',
                'color': 'white'
            }).append(
                $(loadingSpanAnimation).css({
                    'margin-right': '0.5em'
                }),
                $('<span/>').text(message)
            )
        )
    } else {
        $loadingBackdrop.empty().hide()
    }
}

function getTemplateForBlock(block) {
    var html = ''
    block.icon_class = block.icon_class !== undefined ? block.icon_class : 'fas'
    if (block.html_template !== undefined) {
        if (window['dotBlock_' + block.html_template] !== undefined) {
            html = window['dotBlock_' + block.html_template](block)
        } else {
            html = 'Wrong HTML template'
            console.error('Wrong HTML template for block', block)
        }
    } else {
        html = dotBlock_default(block)
    }
    return html
}

function genBlockParamHtml(block) {
    if (!block.params) {
        return ''
    }
    var html = ''
    block.params.forEach(function (param) {
        param['param_id'] = getIDForBlockParameter(block, param)
        paramHtml = ''
        switch (param.type) {
            case 'input':
                paramHtml = genInput(param)[0].outerHTML
                break;
            case 'textarea':
                paramHtml = genInput(param, true)[0].outerHTML
                break;
            case 'select':
                paramHtml = genSelect(param)[0].outerHTML
                break;
            case 'checkbox':
                paramHtml = genCheckbox(param)[0].outerHTML
                break;
            case 'radio':
                paramHtml = genRadio(param)[0].outerHTML
                break;
            default:
                break;
        }
        html += paramHtml
    })
    return html
}

function genSelect(options) {
    var $container = $('<div>')
    var $label = $('<label>')
        .css({
            marginLeft: '0.25em',
            marginBbottom: 0,
        })
        .append($('<span>').text(options.label))
    var $select = $('<select>').css({
        width: '100%',
    })
    var selectOptions = options.options
    if (!Array.isArray(selectOptions)) {
        selectOptions = Object.keys(options.options).map((k) => { return { name: options.options[k], value: k } })
    }
    selectOptions.forEach(function (option) {
        var optionValue = ''
        var optionName = ''
        if (typeof option === 'string') {
            optionValue = option
            optionName = option
        } else {
            optionValue = option.value
            optionName = option.name
        }
        var $option = $('<option>')
            .val(optionValue)
            .text(optionName)
        $select.append($option)
    })
    if (options.value !== undefined) {
        $select.attr('value', options.value)
    } else {
        $select.attr('value', options.default)
    }
    $select
        .attr('data-paramid', options.param_id)
        .attr('onchange', 'handleSelectChange(this)')
    $label.append($select)
    $container.append($label)
    return $container
}

function genInput(options, isTextArea) {
    var $container = $('<div>')
    var $label = $('<label>')
        .css({
            marginLeft: '0.25em',
            marginBbottom: 0,
        })
        .append($('<span>').text(options.label))
    var $input
    if (isTextArea) {
        $input = $('<textarea>').attr('rows', 4).css({resize: 'none'})
    } else {
        $input = $('<input>').css({height: '30px'})
    }
    $input.css({
        width: '100%',
        'box-sizing': 'border-box',
    })
    $input
        .attr('type', 'text')
        .attr('oninput', 'handleInputChange(this)')
        .attr('data-paramid', options.param_id)
    if (options.value !== undefined) {
        $input.attr('value', options.value)
    } else {
        $input.attr('value', options.default)
    }
    if (options.placeholder !== undefined) {
        $input.attr('placeholder', options.placeholder)
    }
    $label.append($input)
    $container.append($label)
    return $container
}

function genCheckbox(options) {
    var $label = $('<label>')
        .css({
            marginLeft: '0.25em',
            marginBbottom: 0,
        })
        .text(options.label)
    var $input = $('<input>')
    $input
        .attr('type', 'checkbox')
        .attr('oninput', 'handleInputChange(this)')
        .attr('data-paramid', options.param_id)
    if (options.value !== undefined) {
        if (options.value) {
            $input.attr('checked', '')
        }
    } else if (options.default) {
        $input.attr('checked', '')
    }
    $label.append($input)
    var $container = $('<div>')
        .addClass('checkbox')
        .append($label)
    return $container
}

function genRadio(options) {
    var $container = $('<div>')
    var $rootLabel = $('<label>')
        .css({
            marginLeft: '0.25em',
            marginBbottom: 0,
        })
        .append($('<span>').text(options.label))
    var selectOptions = options.options
    if (!Array.isArray(selectOptions)) {
        selectOptions = Object.keys(options.options).map((k) => { return { name: options.options[k], value: k } })
    }
    var u_id = uid()
    selectOptions.forEach(function (option) {
        var optionValue = ''
        var optionName = ''
        if (typeof option === 'string') {
            optionValue = option
            optionName = option
        } else {
            optionValue = option.value
            optionName = option.name
        }
        var $input = $('<input>')
            .attr('type', 'radio')
            .attr('name', 'option-radio-' + u_id)
            .val(optionValue)
            .attr('data-paramid', options.param_id)
            .attr('onchange', 'handleInputChange(this)')
        if (options.value !== undefined) {
            if (optionValue == options.value) {
                $input.attr('checked', '')
            }
        } else if (options.default) {
            $input.attr('checked', '')
        }
        var $label = $('<label>')
            .addClass('radio')
            .css({
                marginLeft: '0.25em',
                marginBbottom: 0,
            })
        $label
            .append($input)
            .append($('<span>').text(optionName))
        $container.append($label)
    })
    $container.prepend($rootLabel)
    return $container
}

function handleInputChange(changed) {
    var $input = $(changed)
    var node = getNodeFromNodeInput($input)
    var node_data = setParamValueForInput($input, node.data)
    editor.updateNodeDataFromId(node.id, node_data)
    invalidateContentCache()
}

function handleSelectChange(changed) {
    var $input = $(changed)
    var node = getNodeFromNodeInput($input)
    var node_data = setParamValueForInput($input, node.data)
    editor.updateNodeDataFromId(node.id, node_data)
    invalidateContentCache()
}

function getIDForBlockParameter(block, param) {
    if (param.id !== undefined) {
        return param.id + '-' + block.node_uid
    }
    return param.label.toLowerCase().replace(' ', '-') + '-' + block.node_uid
}

function getNodeFromNodeInput($input) {
    var node_id = 0
    if ($input.closest('.modal').length > 0) {
        node_id = $input.closest('.modal').data('selected-node-id')
        var $relatedInputInNode = $drawflow.find('#node-'+node_id).find('[data-paramid="' + $input.data('paramid') + '"]')
        if ($relatedInputInNode.attr('type') == 'checkbox') {
            $relatedInputInNode.prop('checked', $input.is(':checked'))
        } else if ($relatedInputInNode.attr('type') == 'radio') {
            $relatedInputInNode = $relatedInputInNode.filter(function() {
                return $(this).val() == $input.val()
            })
            $relatedInputInNode.prop('checked', $input.is(':checked'))
        } else {
            $relatedInputInNode.val($input.val())
        }
    } else {
        node_id = $input.closest('.drawflow-node')[0].id.split('-')[1]
    }
    var node = editor.getNodeFromId(node_id)
    return node
}

function setParamValueForInput($input, node_data) {
    var param_id = $input.data('paramid')
    for (let i = 0; i < node_data.params.length; i++) {
        const param = node_data.params[i];
        if (param.param_id == param_id) {
            var newValue = ''
            if ($input.attr('type') == 'checkbox') {
                newValue = $input.is(':checked')
            } else {
                newValue = $input.val()
            }
            node_data.params[i].value = newValue
        }
    }
    return node_data
}

function genBlockNotificationHtml(block) {
    var module = all_blocks_by_id[block.id]
    var html = ''
    var $notificationContainer = $('<span></span>')
    severities.forEach(function(severity) {
        if (module.notifications[severity] && module.notifications[severity].length > 0) {
            var notificationTitles = module.notifications[severity].map(function (notification) {
                return notification.text
            }).join('&#013;')
            var $notification = $('<button class="btn btn-mini" role="button" onclick="showNotificationModalForBlock(this)"></button>')
                .attr({
                    'title': notificationTitles,
                    'data-blockid': block.id,
                })
                .addClass('btn-' + classBySeverity[severity])
                .css({
                    'vertical-align': 'middle',
                    'margin-right': '0.25em',
                })
                .append(
                    $('<i class="fas"></i>').addClass(iconBySeverity[severity]),
                    $('<strong></strong>').text(' '+module.notifications[severity].length)
                )
            $notificationContainer.append($notification)
        }
    })
    html = $notificationContainer[0].outerHTML
    return html
}

function genBlockNotificationForModalHtml(block) {
    var module = all_blocks_by_id[block.id]
    var html = ''
    var $notificationMainContainer = $('<div></div>')
    var reversedSeverities = [].concat(severities)
    reversedSeverities.reverse()
    reversedSeverities.forEach(function (severity) {
        if (module.notifications[severity] && module.notifications[severity].length > 0) {
            var $notificationSeverityContainer = $('<div></div>')
                .addClass(['alert', 'alert-'+classBySeverity[severity]])
            module.notifications[severity].forEach(function(notification) {
                var $notification = $('<div></div>')
                $notification.append(
                    $('<i class="fas"></i>').addClass(iconBySeverity[severity]),
                    $('<strong></strong>').text(' '+notification.text),
                    $('<p></p>').addClass('muted').text(notification.description),
                )
                if (notification.details.length > 0) {
                    var notificationDetails = notification.details.map(function(detail) {
                        return $('<li></li>').text(detail)
                    })
                    notificationDetails = $('<ul></ul>').addClass('muted').append(notificationDetails)
                    $notification.append(notificationDetails)
                }
                $notificationSeverityContainer.append($notification)
            })
            $notificationMainContainer.append($notificationSeverityContainer)
        }
    })
    html = $notificationMainContainer[0].outerHTML
    return html
}

function getPathForEdge(from_id, to_id) {
    return $drawflow.find('svg.connection').filter(function() {
        return $(this).hasClass('node_out_node-' + from_id) && $(this).hasClass('node_in_node-' + to_id)
    }).find('path.main-path')
}

// generate unique id for the inputs
function uid() {
    return (performance.now().toString(36) + Math.random().toString(36)).replace(/\./g, "")
}

function highlightGraphIssues(graphProperties) {
    if (!graphProperties.is_acyclic) {
        graphProperties.cycles.forEach(function(cycle) {
            getPathForEdge(cycle[0], cycle[1])
                .addClass('connection-danger')
                .empty()
                .append($(document.createElementNS('http://www.w3.org/2000/svg', 'title')).text(cycle[2]))
        })
    } else {
        $drawflow.find('svg.connection > path.main-path')
            .removeClass('connection-danger')
            .empty()
    }
}