var dotBlockDefault = doT.template(' \
<div class="canvas-workflow-block"> \
    <div style="width: 100%;"> \
        <div class="default-main-container"> \
            <i class="fas fa-fw fa-{{=it.icon}} {{=it.icon_class}}"></i> \
            <strong style="margin-left: 0.25em;"> \
                {{=it.name}} \
            </strong> \
            <span style="margin-left: auto;"> \
                <a href="#block-modal" role="button" class="btn btn-mini" data-toggle="modal"><i class="fas fa-ellipsis-h"></i></a> \
            </span> \
        </div> \
        <div class="muted" class="description">{{=it.description}}</div> \
        {{=it.block_param_html}} \
    </div> \
</div>')

var dotIF = doT.template(' \
<div class="canvas-workflow-block small"> \
    <div style="width: 100%; height: 100%;"> \
        <div class="default-main-container-small"> \
            <i class="fas fa-fw fa-{{=it.icon}} {{=it.icon_class}}"></i> \
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
            // console.log(param);
        });
    $chosenBlocks.chosen()
        .on('change', function (evt, param) {
            // console.log(param);
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

}

function getTemplateForBlock(block) {
    var html = block.name
    if (block.html !== undefined) {
        html = block.html
    } else {
        if (block.html_template !== undefined) {
            html = window['dot' + block.html_template](block)
        } else {
            html = dotBlockDefault(block)
        }
    }
    return html
}

function genBlockParamHtml(block) {
    if (!block.params) {
        return ''
    }
    var html = ''
    block.params.forEach(function(param) {
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
    options.options.forEach(function(option) {
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
    if (options.default !== undefined) {
        $select.val(options.default)
    }
    return $select
}

function genInput(options) {
    var $input = $('<input>')
    $input.attr('type', 'text')
    if (options.default !== undefined) {
        // $input.val(options.default)
        $input.attr('value', options.default) // wtf why does it not work?!
    }
    if (options.placeholder !== undefined) {
        $input.attr('placeholder', options.placeholder)
    }
    return $input
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

function refreshLastUpdatedField() {
    // lastModifiedMessage = "Last modified: "
    // $lastModifiedField.text(lastModifiedMessage + moment(parseInt(lastModified)).fromNow())
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
    var data = editor.export().drawflow.Home.data
    return data
}

function loadWorkflow() {
    fetchWorkflow(workflow_id, function(workflow) {
        lastModified = workflow.timestamp + '000'
        // refreshLastUpdatedField()
        revalidateContentCache()
        if (workflow.data !== undefined) {
            workflow.data = JSON.parse(workflow.data)
            var editor_data = {
                drawflow: {
                    Home: {
                        data: workflow.data
                    }
                }
            }
            editor.import(editor_data);
        }
    })
}


/* API */
function fetchWorkflow(id, callback) {
    var url = '/workflows/view/' + id + '.json'
    $.ajax({
        beforeSend: function () {
            toggleLoadingInSaveButton(true)
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
            toggleLoadingInSaveButton(false)
        },
        type: "post",
        url: url
    })
}

function saveWorkflow(confirmSave, callback) {
    saveConfirmMessage = 'Confirm saving the current state of the workflow'
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
                        // refreshLastUpdatedField()
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
