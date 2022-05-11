var dotBlockDefault = doT.template(' \
<div class="canvas-workflow-block" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%;"> \
        <div class="default-main-container"> \
            <i class="fa-fw fa-{{=it.icon}} {{=it.icon_class}}"></i> \
            <strong style="margin-left: 0.25em;"> \
                {{=it.name}} \
            </strong> \
            <span style="margin-left: auto;"> \
                <a href="#block-modal" role="button" class="btn btn-mini" data-toggle="modal"><i class="fas fa-ellipsis-h"></i></a> \
            </span> \
        </div> \
        <div class="muted" class="description" style="margin-bottom: 0.5em;">{{=it.description}}</div> \
        {{=it.block_param_html}} \
    </div> \
</div>')

var dotIF = doT.template(' \
<div class="canvas-workflow-block small" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%; height: 100%;"> \
        <div class="default-main-container-small"> \
            <i class="fa-fw fa-{{=it.icon}} {{=it.icon_class}}"></i> \
            <strong style="margin-left: 0.25em;"> \
                {{=it.name}} \
            </strong> \
            <div class="then-else-container"> \
                <span>then</span> \
                <span>else</span> \
            </div> \
        </div> \
    </div> \
</div>')

var workflow_id = 0
var contentChanged = false
var lastModified = 0

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

    editor.on('nodeCreated', invalidateContentCache)
    editor.on('nodeRemoved', invalidateContentCache)
    editor.on('nodeDataChanged', invalidateContentCache)
    editor.on('nodeMoved', invalidateContentCache)
    editor.on('connectionCreated', invalidateContentCache)
    editor.on('connectionRemoved', invalidateContentCache)

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
            var selected_module = all_blocks.filter(function(block) {
                return block.id == selection
            })
            var canvasBR = $canvas[0].getBoundingClientRect()
            var position = {
                top: canvasBR.height / 2 - canvasBR.top,
                left: canvasBR.left + canvasBR.width / 2
            }
            addNode(selected_module[0], position)
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

    loadWorkflow()
    $saveWorkflowButton.click(saveWorkflow)
    $importWorkflowButton.click(importWorkflow)
    $exportWorkflowButton.click(exportWorkflow)
    $blockModal.on('show', function (evt) {
        var selectedBlock = editor.getNodeFromId(editor.node_selected.id.split('-')[1]) // Couldn't find a better way to get the selected node
        buildModalForBlock(selectedBlock.id, selectedBlock.data)
    })

}

function buildModalForBlock(node_id, block) {
    var html = genBlockParamHtml(block)
    $blockModal
        .data('selected-block', block)
        .data('selected-node-id', node_id)
    $blockModal.find('.modal-body').empty().append(html)
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

    block['block_param_html'] = genBlockParamHtml(block)
    var html = getTemplateForBlock(block)
    editor.addNode(
        block.name,
        block.inputs === undefined ? 1 : block.inputs,
        block.outputs === undefined ? 1 : block.outputs,
        adjsutedPosition.left,
        adjsutedPosition.top,
        block.class === undefined ? '' : block.class,
        block,
        html
    );
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
    fetchWorkflow(workflow_id, function(workflow) {
        lastModified = workflow.timestamp + '000'
        revalidateContentCache()

        // We cannot rely on the editor's import function as it recreates the nodes with the saved HTML instead of rebuilding them
        // We have to manually add the nodes and their connections
        Object.values(workflow.data).forEach(function(block) {
            var node_uid = uid() // only used for UI purposes
            block.data['node_uid'] = node_uid
            block.data['block_param_html'] = genBlockParamHtml(block.data)
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
            error: function (jqXHR, textStatus, errorThrown) {
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

function importWorkflow() {
    showMessage('fail', 'Import workflow: to be implemented')
}

function exportWorkflow() {
    showMessage('fail', 'Export workflow: to be implemented')
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
        html = window['dot' + block.html_template](block)
    } else {
        html = dotBlockDefault(block)
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

function genInput(options) {
    var $container = $('<div>')
    var $label = $('<label>')
        .css({
            marginLeft: '0.25em',
            marginBbottom: 0,
        })
        .append($('<span>').text(options.label))
    var $input = $('<input>').css({
        width: '100%',
        'box-sizing': 'border-box',
        height: '30px',
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

// generate unique id for the inputs
function uid() {
    return (performance.now().toString(36) + Math.random().toString(36)).replace(/\./g, "")
}