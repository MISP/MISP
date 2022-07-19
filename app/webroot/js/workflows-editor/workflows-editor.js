var dotBlock_default = doT.template(' \
<div class="canvas-workflow-block {{? it.is_misp_module }} is-misp-module {{?}}" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%;"> \
        <div class="default-main-container"> \
            {{? it.icon }} \
                <i class="fa-fw fa-{{=it.icon}} {{=it.icon_class}}"></i> \
            {{?}} \
            {{? it.icon_path }} \
                <span style="display: flex;"><img src="/img/{{=it.icon_path}}" alt="Icon of {{=it.name}}" width="18" height="18" style="margin: auto 0; filter: grayscale(1);"></span> \
            {{?}} \
            <strong style="margin-left: 0.25em;"> \
                {{=it.name}} \
            </strong> \
            {{? it.is_misp_module }} \
                <sup class="is-misp-module"></sup> \
            {{?}} \
            {{? it.is_blocking }} \
                <span style="margin-left: 2px;" class="text-error"> \
                    <i title="This module can block execution" class="fa-fw fas fa-stop-circle"></i> \
                </span> \
            {{?}} \
            <span style="margin-left: auto;"> \
                <span class="block-notification-container"> \
                    {{=it._block_notification_html}} \
                </span> \
                <span> \
                    <a href="#block-modal" role="button" class="btn btn-mini" data-toggle="modal"><i class="fas fa-ellipsis-h"></i></a> \
                    {{=it._block_filter_html}} \
                </span> \
            </span> \
        </div> \
        <div class="muted" class="description" style="margin-bottom: 0.5em;">{{=it.description}}</div> \
        {{=it._block_param_html}} \
    </div> \
</div>')

var dotBlock_trigger = doT.template(' \
<div class="canvas-workflow-block" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%;"> \
        <div class="default-main-container" style="border:none;"> \
            {{? it.icon }} \
                <i class="fa-fw fa-{{=it.icon}} {{=it.icon_class}}"></i> \
            {{?}} \
            {{? it.icon_path }} \
                <span style="display: flex;"><img src="/img/{{=it.icon_path}}" alt="Icon of {{=it.name}}" width="18" height="18" style="margin: auto 0;"></span> \
            {{?}} \
            <strong style="margin-left: 0.25em;"> \
                {{=it.name}} \
            </strong> \
            <span style="margin-left: auto;"> \
                <span class="block-notification-container"> \
                    {{=it._block_notification_html}} \
                </span> \
            </span> \
        </div> \
    </div> \
</div>')

var dotBlock_if = doT.template(' \
<div class="canvas-workflow-block" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%;"> \
        <div class="default-main-container"> \
            {{? it.icon }} \
                <i class="fa-fw fa-{{=it.icon}} {{=it.icon_class}}"></i> \
            {{?}} \
            {{? it.icon_path }} \
                <span style="display: flex;"><img src="/img/{{=it.icon_path}}" alt="Icon of {{=it.name}}" width="18" height="18" style="margin: auto 0;"></span> \
            {{?}} \
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
            {{? it.icon }} \
                <i class="fa-fw fa-{{=it.icon}} {{=it.icon_class}}"></i> \
            {{?}} \
            {{? it.icon_path }} \
                <span style="display: flex;"><img src="/img/{{=it.icon_path}}" alt="Icon of {{=it.name}}" width="18" height="18" style="margin: auto 0;"></span> \
            {{?}} \
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

var dotBlock_error = doT.template(' \
<div class="canvas-workflow-block" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%;"> \
        <div class="alert alert-danger">{{=it.error}}</div> \
        <div>Data:</div> \
        <textarea rows=6 style="width: 95%;">{{=it.data}}</textarea> \
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
    })
    editor.on('nodeRemoved', function () {
        invalidateContentCache()
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
    editor.on('keydown', function (evt) {
        if (evt.keyCode == 67 && $drawflow.is(evt.target)) {
            editor.fitCanvas()
        }
        if (evt.keyCode == 83 && evt.ctrlKey && $drawflow.is(evt.target)) {
            saveWorkflow()
            evt.preventDefault()
        }
    })
    editor.translate_to = function (x, y) {
        this.canvas_x = x;
        this.canvas_y = y;
        let storedZoom = this.zoom;
        this.zoom = 1;
        this.precanvas.style.transform = "translate(" + this.canvas_x + "px, " + this.canvas_y + "px) scale(" + this.zoom + ")";
        this.zoom = storedZoom;
        this.zoom_last_value = 1;
        this.zoom_refresh();
    }
    editor.fitCanvas = function () {
        editor.translate_to(0, 0)
        editor.zoom = 1
        editor.zoom_min = 0.3
        editor.zoom_refresh()
        var sidebarWidth = 340
        var parentOffsetY = editor.precanvas.parentElement.getBoundingClientRect().top
        var editor_bcr = editor.container.getBoundingClientRect()
        var offset_x = (editor_bcr.width + sidebarWidth) / 2
        var offset_y = (editor_bcr.height - parentOffsetY) / 2

        var canvasCentroid = getCanvasCentroid()
        var calc_zoom = Math.min(
            1,
            Math.min(
                (editor_bcr.width - sidebarWidth) / ((canvasCentroid.maxX - canvasCentroid.minX) + sidebarWidth),
                editor_bcr.height / ((canvasCentroid.maxY - canvasCentroid.minY) - parentOffsetY)
            ),
        ) // Zoom out if needed
        calc_zoom = calc_zoom * 0.95
        offset_x += 100 * (1 / calc_zoom) // dirty fix to offset the position relative to the sidebar
        offset_y -= 100 * (1 / calc_zoom) // dirty fix to slightly move the graph up
        editor.translate_to(
            offset_x - canvasCentroid.centroidX,
            offset_y - canvasCentroid.centroidY 
        )

        editor.zoom = calc_zoom
        editor.zoom_refresh()
    }

    $('#block-tabs a').click(function (e) {
        e.preventDefault();
        $(this).tab('show');
    })

    $chosenBlocks.chosen({width: '320px'})
        .on('change', function (evt, param) {
            var selection = param.selected
            var selected_module = all_blocks_by_id[selection]
            var canvasBR = $canvas[0].getBoundingClientRect()
            var position = {
                top: canvasBR.height / 2 - canvasBR.top,
                left: canvasBR.left + canvasBR.width / 2
            }
            
            if ($(this).hasClass('blueprint-select')) {
                addWorkflowBlueprint(selection)
            } else {
                addNode(selected_module, position)
            }
        });


    $('.sidebar-workflow-block').each(function() {
        var $block = $(this)
        $block.data('block', all_blocks_by_id[$block[0].id])

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

    $('.sidebar-workflow-blueprints').each(function () {
        var $block = $(this)
        $block.data('blueprint', all_workflow_blueprints_by_id[$block[0].id])

        $(this).draggable({
            helper: "clone",
            scroll: false,
            start: function (event, ui) {
            },
            stop: function (event, ui) {
            }
        });
    })

    $canvas.droppable({
        drop: function (event, ui) {
            ui.position.top += 96 // take padding/marging/position into account
            if (ui.draggable.data('blueprint')) {
                addWorkflowBlueprint(ui.draggable.data('blueprint').WorkflowBlueprint.id)
            } else {
                addNode(ui.draggable.data('block'), ui.position)
            }
        },
    });

    graphPooler = new TaskScheduler(checkGraphProperties, {
        interval: 10000,
        slowInterval: 60000,
    })

    filterBlocks($blockFilterGroup.find('button.active')[0])
    fetchAndLoadWorkflow().then(function() {
        graphPooler.start(undefined)
        editor.fitCanvas()
        // block contextual menu for trigger blocks
        $canvas.find('.canvas-workflow-block').on('contextmenu', function (evt) {
            var selectedNode = getSelectedBlock()
            if (selectedNode !== undefined && selectedNode.data.module_type == 'trigger') {
                evt.stopPropagation();
                evt.preventDefault();
            }
        })
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
        }
        $blockModal.modal('hide')
    })

    $drawflow.on('mousedown', function (evt) {
        if (evt.shiftKey) {
            editor.editor_selected = false
            // evt.stopPropagation()
        }
    })
    editor.on('nodeCreated', function(node_id) {
        $drawflow.find('#node-'+node_id).on('mousedown', function (evt) {
            var selected_ids = selection.getSelection().map(function(e) { return e.id.slice(5) })
            if (selected_ids.indexOf(this.id.slice(5)) !== -1) {
                editor.node_selected = this // Allow moving multiple nodes from any nodes of the selection
            }
        })
    })
    editor.last_x = 0;
    editor.last_y = 0;
    editor.on('mouseMove', function(coordinates) {
        // Credit: https://github.com/jerosoler/Drawflow/issues/322#issuecomment-1133036432
        if (selection.getSelection() && editor.drag) {
            selection.getSelection().forEach(function(node) {
                var node_id = node.id.slice(5)
                if (node_id != editor.node_selected.id.slice(5)) { // Drawflow default behavior will also move the node
                    var xnew = (editor.last_x - coordinates.x) * editor.precanvas.clientWidth / (editor.precanvas.clientWidth * editor.zoom)
                    var ynew = (editor.last_y - coordinates.y) * editor.precanvas.clientHeight / (editor.precanvas.clientHeight * editor.zoom)

                    node.style.top = (node.offsetTop - ynew) + 'px'
                    node.style.left = (node.offsetLeft - xnew) + 'px'

                    editor.drawflow.drawflow[editor.module].data[node_id].pos_x = (node.offsetLeft - xnew)
                    editor.drawflow.drawflow[editor.module].data[node_id].pos_y = (node.offsetTop - ynew)
                    editor.updateConnectionNodes(node.id);
                }
            })
        }
        editor.last_x = coordinates.x
        editor.last_y = coordinates.y 
    })
    editor.on('nodeSelected', function(node_id) {
        $controlDuplicateButton.removeClass('disabled')
        $controlDeleteButton.removeClass('disabled')
        $controlSaveBlocksLi.removeClass('disabled')
        selection.select([getNodeHtmlByID(node_id)])
    })
    editor.on('nodeUnselected', function() {
        selection.getSelection().forEach(function (el) {
            el.classList.remove('selected')
        })
        selection.clearSelection()
        $controlDuplicateButton.addClass('disabled')
        $controlDeleteButton.addClass('disabled')
        $controlSaveBlocksLi.addClass('disabled')
    })

    selection = new SelectionArea({
        selectables: ['#drawflow .drawflow-node'],
        boundaries: ['#drawflow']
    })
        .on('beforestart', function (data) {
            var evt = data.event
            if (!evt.shiftKey) {
                return false
            }
        })
        .on('start', function(data) {
            var store = data.store
            var evt = data.event
            if (!evt.ctrlKey && !evt.metaKey) {
                store.stored.forEach(function(el) {
                    el.classList.remove('selected');
                })
                selection.clearSelection();
            }
        })
        .on('move', function(data) {
            var store = data.store
            var added = store.changed.added
            var removed = store.changed.removed
            added.forEach(function (el) {
                el.classList.add('selected');
            })
            removed.forEach(function (el) {
                el.classList.remove('selected');
            })
        })
        .on('stop', function (data) {
            var store = data.store
            if (store.selected.length > 0) {
                editor.node_selected = store.selected[0]
                editor.dispatch('nodeSelected', editor.node_selected.id.slice(5));
            }
        })
    
    $controlDuplicateButton.click(function() {
        var currentSelection = selection.getSelection()
        var newNodes = duplicateNodesFromHtml(currentSelection)
        selection.clearSelection()
        selection.select(newNodes)
    })
    $controlDeleteButton.click(function() {
        selection.getSelection().forEach(function (node) {
            editor.removeNodeId(node.id)
        })
        editor.dispatch('nodeUnselected')
    })
    $controlSaveBlocksLi.click(function(evt) {
        var $link = $(this).find('a')
        evt.preventDefault()
        saveBlueprint($link.attr('href'))
    })
    $saveBlueprintButton.click(function(evt) {
        evt.preventDefault()
        saveBlueprint($(this).attr('href'))
    })

    $(window).bind('beforeunload', function() {
        if (contentChanged) {
            return false;
        }
    })
}

function saveBlueprint(href) {
    var selectedNodes = selection.getSelection()
    var editorData = getEditorData()
    openGenericModal(href, undefined, function () {
        var nodes = selectedNodes.map(function (nodeHtml) {
            var node = editorData[nodeHtml.id.slice(5)]
            delete node.html
            Object.keys(node.data).forEach(function (k) {
                if (k.startsWith('_')) {
                    delete node.data[k]
                }
            })
            return node
        })
        var $modal = $('#genericModal')
        var $graphData = $modal.find('form #WorkflowBlueprintData')
        $graphData.val(JSON.stringify(nodes))
        $modal.find('.modal-body').append(
            $('<h3></h3>').append(
                $('<span></span').text('Workflow Blueprint Content '),
                $('<a class="fas fa-copy" href="#"></a>')
                    .attr('title', 'Copy Workflow Blueprint to clipboard')
                    .click(function () {
                        var $clicked = $(this)
                        navigator.clipboard.writeText(JSON.stringify(nodes)).then(function () {
                            $clicked.removeClass('fa-copy').addClass('fa-check').addClass('text-success')
                            setTimeout(function () {
                                $clicked.removeClass('fa-check').addClass('fa-copy').removeClass('text-success')
                            }, 2000);
                        }, function (err) {
                            console.error('Async: Could not copy text: ', err);
                        });
                    }),
            )
        )
        var $ul = $('<ul></ul>')
        nodes.forEach(function (node) {
            $ul.append(
                $('<li></li>').append(
                    $('<strong></strong>').text(node.data.name),
                    $('<ul></ul>').append(
                        node.data.saved_filters.length > 0 ? $('<li></li>').text('Has filter') : null,
                        node.data.params.length > 0 ? $('<li></li>').text('Has parameters') : null
                    )
                )
            )
        })
        $modal.find('.modal-body').append($ul)
    })
}

function buildModalForBlock(node_id, block) {
    var html = genBlockParamHtml(block)
    $blockModal
        .data('selected-block', block)
        .data('selected-node-id', node_id)
    $blockModal.find('.modal-body').empty().append(html)
    afterNodeDrawCallback()
}

function buildNotificationModalForBlock(node_id, block) {
    var html = genBlockNotificationForModalHtml(block)
    $blockNotificationModal
        .data('selected-block', block)
        .data('selected-node-id', node_id)
    $blockNotificationModal.find('.modal-body').empty().append(html)
}

function buildFilteringModalForBlock(node_id, block) {
    var html = genModalFilteringHtml(block)
    $blockFilteringModal
        .data('selected-block', block)
        .data('selected-node-id', node_id)
    $blockFilteringModal.find('.modal-body').empty().append(html)
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

function showFilteringModalForBlock(clicked) {
    var selectedBlock = getSelectedBlock()
    buildFilteringModalForBlock(selectedBlock.id, selectedBlock.data)
    $blockFilteringModal.modal('show')
}

function invalidateContentCache() {
    changeDetectedMessage = '  Last saved change: '
    contentChanged = true
    toggleSaveButton(true)
    $workflowSavedIconContainer.removeClass('text-success').addClass('text-error')
    $workflowSavedIconText
        .removeClass('text-success').addClass('text-error')
        .text('not saved')
    $workflowSavedIconTextDetails.text(changeDetectedMessage + moment(parseInt(lastModified)).fromNow())
}

function revalidateContentCache() {
    changeDetectedMessage = '  Last saved change: '
    contentChanged = false
    toggleSaveButton(false)
    $workflowSavedIconContainer.removeClass('text-error').addClass('text-success')
    $workflowSavedIconText
        .removeClass('text-error').addClass('text-success')
        .text('saved')
    $workflowSavedIconTextDetails.text(changeDetectedMessage + moment(parseInt(lastModified)).fromNow())
}


function addNode(block, position) {
    var module = all_blocks_by_id[block.id] || all_triggers_by_id[block.id]
    if (!module) {
        console.error('Tried to add node for unknown module ' + block.data.id + ' (' + block.id + ')')
        return '';
    }

    var node_uid = uid() // only used for UI purposes
    block['node_uid'] = node_uid

    var pos_x = position.left;
    var pos_y = position.top;

    // Credit: Drawflow example page
    pos_x = pos_x * (editor.precanvas.clientWidth / (editor.precanvas.clientWidth * editor.zoom)) - (editor.precanvas.getBoundingClientRect().x * (editor.precanvas.clientWidth / (editor.precanvas.clientWidth * editor.zoom)));
    pos_y = pos_y * (editor.precanvas.clientHeight / (editor.precanvas.clientHeight * editor.zoom)) - (editor.precanvas.getBoundingClientRect().y * (editor.precanvas.clientHeight / (editor.precanvas.clientHeight * editor.zoom)));

    block['_block_param_html'] = genBlockParamHtml(block)
    block['_block_notification_html'] = genBlockNotificationHtml(block)
    block['_block_filter_html'] = genBlockFilteringHtml(block)
    var html = getTemplateForBlock(block)
    var blockClass = block.class === undefined ? [] : block.class
    blockClass = !Array.isArray(blockClass) ? [blockClass] : blockClass
    blockClass.push('block-type-' + (block.html_template !== undefined ? block.html_template : 'default'))
    if (block.module_type == 'logic') {
        blockClass.push('block-type-logic')
    }
    editor.addNode(
        block.name,
        block.inputs === undefined ? 1 : block.inputs,
        block.outputs === undefined ? 1 : block.outputs,
        pos_x,
        pos_y,
        blockClass.join(' '),
        block,
        html
    )
    afterNodeDrawCallback()
}

function getEditorData(cleanInvalidParams) {
    var data = {} // Make sure nodes are index by their internal IDs
    var editorExport = editor.export().drawflow.Home.data
    editorExport = Array.isArray(editorExport) ? editorExport : Object.values(editorExport)
    editorExport.forEach(function(node) {
        if (node !== null) { // for some reason, the editor create null nodes
            if (cleanInvalidParams && node.data.params !== undefined) {
                node.data.params = deleteInvalidParams(node.data.params)
            }
            delete node.html
            delete node.data.notifications
            Object.keys(node.data).forEach(function (k) {
                if (k.startsWith('_')) {
                    delete node.data[k]
                }
            })
            data[node.id] = node
        }
    })
    return data
}

function deleteInvalidParams(params) {
    for (var i = 0; i < params.length; i++) {
        var param = params[i];
        if (param.is_invalid) {
            params.splice(i, 1)
        }
    }
    return params
}

function fetchAndLoadWorkflow() {
    return new Promise(function (resolve, reject) {
        editor.isLoading = true
        fetchWorkflow(workflow_id, function (workflow) {
            lastModified = workflow.timestamp + '000'
            loadWorkflow(workflow)
            editor.isLoading = false
            revalidateContentCache()
            resolve()
        })
    })
}

function loadWorkflow(workflow) {
    editor.clear()
    if (workflow.data.length == 0) {
        var trigger_id = workflow['trigger_id'];
        if (all_triggers_by_id[trigger_id] === undefined) {
            console.error('Unknown trigger');
            showMessage('error', 'Unknown trigger')
        }
        var trigger_block = all_triggers_by_id[trigger_id]
        addNode(trigger_block, {left: 0, top: 0})
    }
    // We cannot rely on the editor's import function as it recreates the nodes with the saved HTML instead of rebuilding them
    // We have to manually add the nodes and their connections
    Object.values(workflow.data).forEach(function (block) {
        var module = all_blocks_by_id[block.data.id] || all_triggers_by_id[block.data.id]
        if (!module) {
            console.error('Tried to add node for unknown module ' + block.data.id + ' (' + block.id + ')')
            var userFriendlyParams = {}
            block.data.params.forEach(function (param) {
                userFriendlyParams[param.label] = (param.value ?? param.default)
            })
            var html = window['dotBlock_error']({
                error: 'Invalid module type `' + block.data.id + '` (' + block.id + ')',
                data: JSON.stringify(userFriendlyParams, null, 2)
            })
            editor.addNode(
                block.name,
                Object.values(block.inputs).length,
                Object.values(block.outputs).length,
                block.pos_x,
                block.pos_y,
                '',
                block.data,
                html
            )
            return '';
        }
        var module_data = Object.assign({}, all_blocks_by_id[block.data.id] || all_triggers_by_id[block.data.id])
        module_data.params = block.data.params
        module_data.saved_filters = block.data.saved_filters
        block.data = module_data
        var node_uid = uid() // only used for UI purposes
        block.data['node_uid'] = node_uid
        block.data['_block_param_html'] = genBlockParamHtml(block.data)
        block.data['_block_notification_html'] = genBlockNotificationHtml(block.data)
        block.data['_block_filter_html'] = genBlockFilteringHtml(block.data)
        var blockClass = block.data.class === undefined ? [] : block.data.class
        blockClass = !Array.isArray(blockClass) ? [blockClass] : blockClass
        blockClass.push('block-type-' + (block.data.html_template !== undefined ? block.data.html_template : 'default'))
        if (block.data.module_type == 'logic') {
            blockClass.push('block-type-logic')
        }
        if (block.data.disabled) {
            blockClass.push('disabled')
        }
        var html = getTemplateForBlock(block.data)
        editor.nodeId = block.id // force the editor to use the saved id of the block instead of generating a new one
        editor.addNode(
            block.name,
            Object.values(block.inputs).length,
            Object.values(block.outputs).length,
            block.pos_x,
            block.pos_y,
            blockClass.join(' '),
            block.data,
            html
        )
    })
    Object.values(workflow.data).forEach(function (block) {
        for (var input_name in block.inputs) {
            block.inputs[input_name].connections.forEach(function (connection) {
                editor.addConnection(connection.node, block.id, connection.input, input_name)
            })
        }
    })
    afterNodeDrawCallback()
}

function filterBlocks(clicked) {
    var $activeButton = $(clicked)
    var selectedFilter
    if ($activeButton.length > 0) {
        selectedFilter = $activeButton.data('type')
    } else {
        selectedFilter = 'enabled'
    }
    var $blocksToShow = $('.sidebar .tab-pane.active').find('.sidebar-workflow-block')
    $blocksToShow.show()
    if (selectedFilter == 'enabled') {
        $blocksToShow.filter(function() {
            return $(this).data('block')['disabled']
        }).hide()
    } else if (selectedFilter == 'misp-module') {
        $blocksToShow.filter(function () {
            return !$(this).data('block')['is_misp_module'] || $(this).data('block')['disabled']
        }).hide()
    } else if (selectedFilter == 'is-blocking') {
        $blocksToShow.filter(function () {
            return !$(this).data('block')['is_blocking'] || $(this).data('block')['disabled']
        }).hide()
    }
}

function duplicateNodesFromHtml(currentSelection) {
    var selectedNodeIDs = currentSelection.map(function (nodeHtml) {
        return nodeHtml.id.slice(5)
    })
    var newNodes = []
    var oldNewIDMapping = {}
    currentSelection.forEach(function (nodeHtml) {
        nodeHtml.classList.remove('selected');
        var node_id = nodeHtml.id.slice(5)
        var node = getEditorData()[node_id]
        if (node.data.module_type == 'trigger') {
            return
        }
        var position = {
            top: nodeHtml.getBoundingClientRect().top - 100 * editor.zoom,
            left: nodeHtml.getBoundingClientRect().left + 100 * editor.zoom,
        }
        var block = Object.assign({}, all_blocks_by_id[node.data.id])
        block.params = node.data.params.slice()
        block.saved_filters = Object.assign({}, node.data.saved_filters)
        addNode(block, position)
        oldNewIDMapping[node_id] = editor.nodeId - 1
        newNodes.push(getNodeHtmlByID(editor.nodeId - 1)) // nodeId is incremented as soon as a new node is created
    })
    selectedNodeIDs.forEach(function (node_id) {
        var node = getEditorData()[node_id]
        Object.keys(node.outputs).forEach(function (outputName) {
            node.outputs[outputName].connections.forEach(function (connection) {
                if (selectedNodeIDs.includes(connection.node)) {
                    editor.addConnection(
                        oldNewIDMapping[node_id],
                        oldNewIDMapping[connection.node],
                        outputName,
                        connection.output
                    )
                }
            });
        })
    })
    return newNodes
}

function addNodesFromWorkflowBlueprint(workflowBlueprint) {
    var newNodes = []
    if (workflowBlueprint.data.length == 0) {
        return counterNodeAdded
    }
    var oldNewIDMapping = {}
    // We need min position to position nodes relatively
    var minX = workflowBlueprint.data[0].pos_x
    var minY = workflowBlueprint.data[0].pos_y
    workflowBlueprint.data.forEach(function(node) {
        minX = node.pos_x < minX ? node.pos_x : minX
        minY = node.pos_y < minY ? node.pos_y : minY
    })

    var canvasCentroid = getCanvasCentroid()
    workflowBlueprint.data.forEach(function(node) {
        if (node.data.module_type == 'trigger') {
            return
        }
        var position = {
            top: ((node.pos_y - Math.abs(minY)) * editor.zoom + canvasCentroid.centroidY),
            left: ((node.pos_x - Math.abs(minX)) * editor.zoom + canvasCentroid.centroidX),
        }
        var block = Object.assign({}, all_blocks_by_id[node.data.id])
        block.params = node.data.params.slice()
        block.saved_filters = Object.assign({}, node.data.saved_filters)
        addNode(block, position)
        oldNewIDMapping[node.id] = editor.nodeId - 1
        newNodes.push(getNodeHtmlByID(editor.nodeId - 1)) // nodeId is incremented as soon as a new node is created
    })
    workflowBlueprint.data.forEach(function (node) {
        Object.keys(node.outputs).forEach(function (outputName) {
            var block = Object.assign({}, all_blocks_by_id[node.data.id])
            if (block.outputs > 0) { // make sure the module configuration didn't change in regards of the outputs
                node.outputs[outputName].connections.forEach(function (connection) {
                    if (oldNewIDMapping[connection.node] !== undefined) {
                        editor.addConnection(
                            oldNewIDMapping[node.id],
                            oldNewIDMapping[connection.node],
                            outputName,
                            connection.output
                        )
                    }
                });
            }
        })
    })
    return newNodes
}

function getCanvasCentroid() {
    var parentOffsetY = editor.precanvas.parentElement.getBoundingClientRect().top
    var maxX = 0, maxY = 0, minX = 9999999, minY = 9999999
    var nodes = $(editor.precanvas).find('.drawflow-node')
    nodes.each(function () {
        var node_bcr = JSON.parse(JSON.stringify(this.getBoundingClientRect()))
        node_bcr.top = node_bcr.top - parentOffsetY // Make bcr relative
        maxX = (node_bcr.left + node_bcr.width) > maxX ? (node_bcr.left + node_bcr.width) : maxX
        maxY = (node_bcr.top + node_bcr.height) > maxY ? (node_bcr.top + node_bcr.height) : maxY
        minX = node_bcr.left < minX ? node_bcr.left : minX
        minY = node_bcr.top < minY ? node_bcr.top : minY
    });
    var centroidX = (Math.abs(maxX) - Math.abs(minX)) / 2
    var centroidY = (Math.abs(maxY) - Math.abs(minY)) / 2
    return {
        centroidX: centroidX,
        centroidY: centroidY,
        minX: minX,
        minY: minY,
        maxX: maxX,
        maxY: maxY,
    }
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
        var editorData = getEditorData(true)
        $tmpForm.find('[name="data[Workflow][data]"]').val(JSON.stringify(editorData))

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
                        loadWorkflow(workflow.data.Workflow)
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
                toggleLoadingInSaveButton(false, true)
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
    var url = baseurl + "/workflows/checkGraph/"
    var graphData = getEditorData()
    $.ajax({
        data: {graph: JSON.stringify(graphData)},
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

function getNodeHtmlByID(node_id) {
    return editor.precanvas.querySelector('#node-' + node_id)
}

function getSelectedBlock() {
    return editor.getNodeFromId(getSelectedNodeIDInteger())
}

function deleteSelectedNode() {
    editor.removeNodeId(getSelectedNodeID())
}

function addWorkflowBlueprint(blueprintId) {
    var workflowBlueprint = all_workflow_blueprints_by_id[blueprintId]
    if (!workflowBlueprint) {
        console.error('Tried to get workflow blueprint ' + blueprintId)
        return '';
    }
    var newNodes = addNodesFromWorkflowBlueprint(workflowBlueprint.WorkflowBlueprint);
    if (newNodes.length > 0) {
        selection.clearSelection()
        selection.select(newNodes)
        editor.dispatch('nodeSelected', newNodes[0].id);
    }
}

/* UI Utils */
function toggleSaveButton(enabled) {
    $saveWorkflowButton
        .prop('disabled', !enabled)
}

function toggleLoadingInSaveButton(saving, ignoreDisabledState) {
    // TODO: Use I18n strings instead
    if (!ignoreDisabledState) {
        toggleSaveButton(!saving)
    }
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
    block.icon_class = block.icon_class ? block.icon_class : 'fas'
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
    var blockParams = block.params !== undefined ? block.params : []
    var module = all_blocks_by_id[block.id]
    var moduleParams = (module === undefined || module.params === undefined) ? [] : module.params
    var moduleParamsByFormattedName = {}
    var blockParamsByFormattedName = {}
    moduleParams.forEach(function(param) {
        moduleParamsByFormattedName[param.label.toLowerCase().replace(' ', '-')] = param
    })
    blockParams.forEach(function(param) {
        blockParamsByFormattedName[param.label.toLowerCase().replace(' ', '-')] = param
    })
    var processedParam = {};
    var html = ''
    var blockAndModuleParams = blockParams.concat(moduleParams)
    blockAndModuleParams.forEach(function (param) {
        var formattedName = param.label.toLowerCase().replace(' ', '-')
        if (processedParam[formattedName]) { // param has already been processed
            return;
        }
        if (moduleParamsByFormattedName[formattedName] === undefined) { // Param do not exist in the module (anymore or never did)
            param.is_invalid = true
        }
        param = Object.assign({}, blockParamsByFormattedName[formattedName], moduleParamsByFormattedName[formattedName])
        if (!param['param_id']) {
            param['param_id'] = getIDForBlockParameter(block, param)
            block.params.map(function(blockParam) { // We also need to update the block config
                if (blockParam.label == param.label) {
                    blockParam['param_id'] = param['param_id']
                }
                return blockParam
            })
        }
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
            case 'picker':
                paramHtml = genPicker(param)[0].outerHTML
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
        processedParam[formattedName] = true
        html += paramHtml
    })
    return html
}

function afterNodeDrawCallback() {
    var $nodes = $drawflow.find('.drawflow-node')
    $nodes.find('.start-chosen').chosen()
}

function genParameterWarning(options) {
    return options.is_invalid ?
        $('<span>').addClass('text-error').css('margin-left', '5px')
            .append(
                $('<i>').addClass('fas fa-exclamation-triangle'),
                $('<span>').text('Invalid parameter')
            )
            .attr('title', 'This parameter does not exist in the associated workflow module and thus will be removed upon saving. Make sure you have the latest version of the this module.') :
        ''
}

function genSelect(options) {
    var $container = $('<div>')
    var $label = $('<label>')
        .css({
            marginLeft: '0.25em',
            marginBbottom: 0,
        })
        .append(
            $('<span>').text(options.label),
            genParameterWarning(options)
        )
    var $select = $('<select>').css({
        width: '100%',
    })
    if (options.multiple) {
        $select.prop('multiple', true)
    }
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
        $select.find('option').filter(function() {
            if (options.multiple) {
                return options.value.includes(this.value)
            } else {
                return this.value == options.value
            }
        }).attr('selected', 'selected')
    } else {
        $select.find('option').filter(function() {
            if (options.multiple && Array.isArray(options.default)) {
                return options.default.includes(this.value)
            } else {
                return this.value == options.default
            }
        }).attr('selected', 'selected')
    }
    $select
        .attr('data-paramid', options.param_id)
        .attr('onchange', 'handleSelectChange(this)')
    $label.append($select)
    $container.append($label)
    return $container
}

function genPicker(options) {
    var $container = genSelect(options)
    var $select = $container.find('select')
    $select.addClass('start-chosen')
    return $container
}

function genInput(options, isTextArea) {
    var $container = $('<div>')
    var $label = $('<label>')
        .css({
            marginLeft: '0.25em',
            marginBbottom: 0,
        })
        .append(
            $('<span>').text(options.label),
            genParameterWarning(options)
        )
    var $input
    if (isTextArea) {
        $input = $('<textarea>').attr('rows', 4).css({resize: 'none'})
    } else {
        $input = $('<input>').attr('type', 'text').css({height: '30px'})
    }
    $input.css({
        width: '100%',
        'box-sizing': 'border-box',
    })
    $input
        .attr('oninput', 'handleInputChange(this)')
        .attr('data-paramid', options.param_id)
    if (isTextArea) {
        $input.text(options.value !== undefined ? options.value : options.default)
    } else {
        $input.attr('value', options.value !== undefined ? options.value : options.default)
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
        .append(
            $('<span>').text(options.label),
            genParameterWarning(options)
        )
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
        .append(
            $('<span>').text(options.label),
            genParameterWarning(options)
        )
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

function saveFilteringForModule() {
    var selector = $blockFilteringModal.find('input#filtering-selector').val()
    var value = $blockFilteringModal.find('input#filtering-value').val()
    var operator = $blockFilteringModal.find('select#filtering-operator').val()
    var path = $blockFilteringModal.find('input#filtering-path').val()
    if (selector && value && operator && path) {
        var node_id = $blockFilteringModal.data('selected-node-id')
        var block = $blockFilteringModal.data('selected-block')
        block.saved_filters = {
            selector: selector,
            value: value,
            operator: operator,
            path: path,
        }
        editor.updateNodeDataFromId(node_id, block)
        invalidateContentCache()
        $blockFilteringModal.modal('hide')
    } else {
        $blockFilteringModal.find('form')[0].reportValidity()
    }
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
        var param = node_data.params[i];
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
    var module = all_blocks_by_id[block.id] || all_triggers_by_id[block.id]
    if (!module) {
        console.error('Tried to get notification of unknown module ' + block.id)
        return '';
    }
    var html = ''
    var $notificationContainer = $('<span></span>')
    severities.forEach(function(severity) {
        var visibleNotifications = module.notifications[severity].filter(function (notification) { return notification
.__show_in_node})
        if (visibleNotifications && visibleNotifications.length > 0) {
            var notificationTitles = visibleNotifications.map(function (notification) {
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
                    $('<strong></strong>').text(' '+visibleNotifications.length)
                )
            $notificationContainer.append($notification)
        }
    })
    html = $notificationContainer[0].outerHTML
    return html
}

function genBlockNotificationForModalHtml(block) {
    var module = all_blocks_by_id[block.id] || all_triggers_by_id[block.id]
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

function genBlockFilteringHtml(block) {
    var module = all_blocks_by_id[block.id] || all_triggers_by_id[block.id]
    var html = ''
    if (module.support_filters) {
        var $link = $('<a></a>')
            .attr({
                href: '#block-filtering-modal',
                role: 'button',
                class: 'btn btn-mini ' + (getFiltersFromNode(block).value ? 'btn-success' : ''),
                onclick: 'showFilteringModalForBlock(this)',
                title: 'Module filtering conditions'
            })
            .append($('<i></i>')
            .addClass('fas fa-filter'))
        html += $link[0].outerHTML
    }
    return html
}

function genModalFilteringHtml(block) {
    var module = all_blocks_by_id[block.id] || all_triggers_by_id[block.id]
    var html = ''
    if (module.support_filters) {
        html += genGenericBlockFilter(block)
    }
    return html
}

function getFiltersFromNode(block) {
    return {
        'selector': block.saved_filters.value ? block.saved_filters.selector : '',
        'value': block.saved_filters.value ? block.saved_filters.value : '',
        'operator': block.saved_filters.operator ? block.saved_filters.operator : '',
        'path': block.saved_filters.path ? block.saved_filters.path : '',
    }
}

function genGenericBlockFilter(block) {
    var operatorOptions = [
        {value: 'in', text: 'In'},
        {value: 'not_in', text: 'Not in'},
        {value: 'equals', text: 'Equals'},
        {value: 'not_equals', text: 'Not equals'},
    ]
    var filters = getFiltersFromNode(block)
    var $div = $('<div></div>').append($('<form></form>').append(
        genGenericInput({ id: 'filtering-selector', label: 'Element selector', type: 'text', placeholder: 'Attribute.{n}', required: true, value: filters.selector}),
        genGenericInput({id: 'filtering-value', label: 'Value', type: 'text', placeholder: 'tlp:white', required: true, value: filters.value}),
        genGenericSelect({ id: 'filtering-operator', label: 'Operator', options: operatorOptions, value: filters.operator}),
        genGenericInput({ id: 'filtering-path', label: 'Hash Path', type: 'text', placeholder: 'AttributeTag.{n}.Tag.name', required: true, value: filters.path}),
    ))
    return $div[0].outerHTML
}

function genGenericInput(options) {
    var $label = $('<label></label>').append(
        $('<span></span>').text(options.label).css({'display': 'block'}),
        $('<input></input>')
            .attr({
                id: options.id,
                type: options.type,
                placeholder: options.placeholder,
                value: options.value
            })
            .prop('required', options.required)
            .css({'width': '100%', 'box-sizing': 'border-box', 'height': '30px'}),
    )
    return $label[0].outerHTML
}

function genGenericSelect(options) {
    var $select = $('<select></select>')
        .attr({id: options.id})
        .css({'width': '100%', 'box-sizing': 'border-box'})
    options.options.forEach(function(option) {
        var $option = $('<option></option>')
            .val(option.value)
            .text(option.text)
        if (options.value == option.value) {
            $option.attr('selected', '')
        }
        $select.append($option)
    })
    var $label = $('<label></label>').append(
        $('<span></span>').text(options.label).css({'display': 'block'}),
        $select
    )
    return $label[0].outerHTML
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

function highlightAcyclic(acyclicData) {
    if (!acyclicData.is_acyclic) {
        acyclicData.cycles.forEach(function (cycle) {
            getPathForEdge(cycle[0], cycle[1])
                .addClass('connection-danger')
                .empty()
                .append($(document.createElementNS('http://www.w3.org/2000/svg', 'title')).text(cycle[2]))
        })
    }
}

function highlightMultipleOutputConnection(connectionData) {
    if (connectionData.has_multiple_output_connection) {
        Object.keys(connectionData.edges).forEach(function (from_id) {
            connectionData.edges[from_id].forEach(function (target_id) {
                getPathForEdge(from_id, target_id)
                    .addClass('connection-danger')
                    .empty()
                    .append($(document.createElementNS('http://www.w3.org/2000/svg', 'title')).text('Multiple connections'))
            })
        })
    }
}

function highlightGraphIssues(graphProperties) {
    $drawflow.find('svg.connection > path.main-path')
        .removeClass('connection-danger')
        .empty()
    highlightAcyclic(graphProperties.is_acyclic)
    highlightMultipleOutputConnection(graphProperties.multiple_output_connection)
    
}