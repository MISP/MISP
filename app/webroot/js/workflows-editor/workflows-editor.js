var dotBlockDefault = doT.template(' \
<div class="canvas-workflow-block"> \
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
<div class="canvas-workflow-block small"> \
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
                $(this).addClass('disabled')
            },
            stop: function (event, ui) {
                $(this).removeClass('disabled')
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
        buildModalForBlock(selectedBlock.data)
    })

    $blockModalSave.click(function() {
        saveBlockConfiguration()
    })

}

function saveBlockConfiguration() {
    console.log(
        $blockModal.data('selected-block')
    );
}

function buildModalForBlock(block) {
    var html = genBlockParamHtml(block)
    $blockModal.data('selected-block', block)
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
        // if (workflow.data) {
        //     var editor_data = {
        //         drawflow: {
        //             Home: {
        //                 data: workflow.data
        //             }
        //         }
        //     }
        //     editor.import(editor_data);
        // }
        
        // We cannot rely on the editor's import function as it recreates the nodes with the saved HTML instead of rebuilding them
        // We have to manually add the nodes and their connections
        Object.values(workflow.data).forEach(function(block) {
            block.data['block_param_html'] = genBlockParamHtml(block.data)
            var html = getTemplateForBlock(block.data)
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
        param['param_id'] = getIDForBlockParameter(param)
        paramHtml = ''
        switch (param.type) {
            case 'input':
                paramHtml = genInput(param)[0].outerHTML
                break;
            case 'select':
                paramHtml = genSelect(param)[0].outerHTML
                break;
            default:
                break;
        }
        html += paramHtml
    })
    return html
}

function genSelect(options) {
    var $select = $('<select>').css({
        width: '100%',
    })
    options.options.forEach(function (option) {
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
    return $select
}

function genInput(options) {
    var $label = $('<label>')
        .css({
            marginLeft: '0.25em',
            marginBbottom: 0,
        })
        .text(options.label)
    var $input = $('<input>')
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
    var $container = $('<div>').append($label, $input)
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

function getIDForBlockParameter(param) {
    if (param.id !== undefined) {
        return param.id
    }
    return param.label.toLowerCase().replace(' ', '-')
}

function getNodeFromNodeInput($input) {
    var node = editor.getNodeFromId($input.closest('.drawflow-node')[0].id.split('-')[1])
    return node
}

function setParamValueForInput($input, node_data) {
    var param_id = $input.data('paramid')
    for (let i = 0; i < node_data.params.length; i++) {
        const param = node_data.params[i];
        if (param.param_id == param_id) {
            node_data.params[i].value = $input.val()
        }
    }
    return node_data
}