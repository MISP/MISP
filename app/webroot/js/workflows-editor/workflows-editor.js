var dotBlock_default = doT.template(' \
<div class="canvas-workflow-block {{? it.module_data.is_misp_module }} is-misp-module {{?}}" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%;"> \
        <div class="default-main-container"> \
            {{? it.module_data.icon }} \
                <i class="fa-fw fa-{{=it.module_data.icon}} {{=it.module_data.icon_class}}"></i> \
            {{?}} \
            {{? it.module_data.icon_path }} \
                <span style="display: flex; height: 1em;"><img src="/img/{{=it.module_data.icon_path}}" alt="Icon of {{=it.module_data.name}}" width="18" height="18" style="margin: auto 0; filter: grayscale(1);"></span> \
            {{?}} \
            <strong style="margin-left: 0.25em;"> \
                {{=it.module_data.name}} \
            </strong> \
            {{? it.module_data.is_misp_module }} \
                <sup class="is-misp-module"></sup> \
            {{?}} \
            {{? it.module_data.blocking }} \
                <span style="margin-left: 2px;" class="text-error"> \
                    <i title="This module can block execution" class="fa-fw fas fa-stop-circle"></i> \
                </span> \
            {{?}} \
            <span style="margin-left: auto;"> \
                <span class="block-notification-container"> \
                    {{=it._node_notification_html}} \
                </span> \
                <span> \
                    <a href="#block-modal" role="button" class="btn btn-mini" data-toggle="modal"><i class="fas fa-ellipsis-h"></i></a> \
                    {{=it._node_filter_html}} \
                </span> \
            </span> \
        </div> \
        <div class="muted" class="description" style="margin-bottom: 0.5em;">{{=it.module_data.description}}</div> \
        {{=it._node_param_html}} \
    </div> \
</div>')

var dotBlock_trigger = doT.template(' \
<div class="canvas-workflow-block" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%;"> \
        <div class="default-main-container" style="border:none;"> \
            {{? it.module_data.icon }} \
                <i class="fa-fw fa-{{=it.module_data.icon}} {{=it.module_data.icon_class}}"></i> \
            {{?}} \
            {{? it.module_data.icon_path }} \
                <span style="display: flex; height: 1em;"><img src="/img/{{=it.module_data.icon_path}}" alt="Icon of {{=it.module_data.name}}" width="18" height="18" style="margin: auto 0;"></span> \
            {{?}} \
            <strong style="margin-left: 0.25em;"> \
                {{=it.module_data.name}} \
            </strong> \
            <span style="margin-left: auto; display: flex; align-items: center; gap: 3px;"> \
                {{? it.module_data.blocking }} \
                    <span class="label label-important" style="line-height: 20px;" title="This workflow is a blocking worklow and can prevent the default MISP behavior to execute"> \
                        <i class="fa-lg fa-fw fas fa-stop-circle"></i> \
                        Blocking \
                    </span> \
                {{?}} \
                {{? it.module_data.misp_core_format }} \
                    <span class="label" style="min-width: 18px; margin: auto 3px; line-height: 20px; background-color: #009fdc;"> \
                        <img src="/img/misp-logo-no-text.png" alt="MISP Core format" width="18" height="18" style="filter: brightness(0) invert(1);" title="The data passed by this trigger is compliant with the MISP core format"> \
                    </span> \
                {{?}} \
                <span class="block-notification-container"> \
                    {{=it._node_notification_html}} \
                </span> \
            </span> \
        </div> \
    </div> \
</div>')

var dotBlock_if = doT.template(' \
<div class="canvas-workflow-block" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%;"> \
        <div class="default-main-container"> \
            {{? it.module_data.icon }} \
                <i class="fa-fw fa-{{=it.module_data.icon}} {{=it.module_data.icon_class}}"></i> \
            {{?}} \
            {{? it.module_data.icon_path }} \
                <span style="display: flex; height: 1em;"><img src="/img/{{=it.module_data.icon_path}}" alt="Icon of {{=it.module_data.name}}" width="18" height="18" style="margin: auto 0;"></span> \
            {{?}} \
            <strong style="margin-left: 0.25em;"> \
                {{=it.module_data.name}} \
            </strong> \
            <span style="margin-left: auto;"> \
                <span class="block-notification-container"> \
                    {{=it._node_notification_html}} \
                </span> \
                <span> \
                    <a href="#block-modal" role="button" class="btn btn-mini" data-toggle="modal"><i class="fas fa-ellipsis-h"></i></a> \
                </span> \
            </span> \
        </div> \
        {{=it._node_param_html}} \
    </div> \
</div>')

var dotBlock_concurrent = doT.template(' \
<div class="canvas-workflow-block" data-nodeuid="{{=it.node_uid}}"> \
    <div style="width: 100%;"> \
        <div class="default-main-container"> \
            {{? it.module_data.icon }} \
                <i class="fa-fw fa-{{=it.module_data.icon}} {{=it.module_data.icon_class}}"></i> \
            {{?}} \
            {{? it.module_data.icon_path }} \
                <span style="display: flex; height: 1em;"><img src="/img/{{=it.module_data.icon_path}}" alt="Icon of {{=it.module_data.name}}" width="18" height="18" style="margin: auto 0;"></span> \
            {{?}} \
            <strong style="margin-left: 0.25em;"> \
                {{=it.module_data.name}} \
            </strong> \
            <span style="margin-left: auto;"> \
                <span class="block-notification-container"> \
                    {{=it._node_notification_html}} \
                </span> \
                <span> \
                    <a href="#block-modal" role="button" class="btn btn-mini" data-toggle="modal"><i class="fas fa-ellipsis-h"></i></a> \
                </span> \
            </span> \
        </div> \
        {{=it._node_param_html}} \
        <div class="muted" class="description" style="margin-bottom: 0.5em;">{{=it.module_data.description}}</div> \
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

var dotBlock_connectionLabel = doT.template(' \
<span class="label label-{{=it.variant}}" id="{{=it.id}}">{{=it.name}}</span>')

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
var haspathQuickPickMenuElementSelector = [
    { 'name': 'All Attributes', 'path': 'Event._AttributeFlattened.{n}' },
    { 'name': 'All tags attached to all Attributes', 'path': 'Event._AttributeFlattened.{n}.Tag.{n}.name' },
    { 'name': 'All tags attached to the Event', 'path': 'Event.Tag.{n}.name' },
]
var haspathQuickPickMenuSubElementSelector = [
    { 'name': 'Attribute type', 'path': 'type' },
    { 'name': 'All tags', 'path': 'Tag.{n}.name' },
    { 'name': 'Warnings from warninglists', 'path': 'warnings.{n}.warninglist_category' },
    { 'name': 'Feed correlation', 'path': 'Feed.{n}.name' },
    { 'name': 'All enrichments', 'path': 'enrichment.{n}' },
]

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
    editor.on('frameNodeCreated', function (framenodeUuid) {
        invalidateContentCache()
        var frameNodeFullUuid = 'framenode-' + framenodeUuid
        $('#' + frameNodeFullUuid).find('.drawflow-framenode-text').dblclick(function() {
            var existingText = $(this).text()
            var newText = prompt('Edit frame node text', existingText)
            editor.updateFramenode(frameNodeFullUuid, {text: newText})
        })
    })
    editor.on('frameNodeUpdated', function () {
        invalidateContentCache()
    })
    editor.on('frameNodeRemoved', function () {
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
        if (evt.keyCode == 46 && $drawflow.is(evt.target)) {
            deleteSelectedNodes(true)
        }
        if (evt.keyCode == 68 && evt.ctrlKey && $drawflow.is(evt.target)) {
            duplicateSelection()
            evt.preventDefault()
        }
        if (evt.keyCode == 70 && $drawflow.is(evt.target)) {
            createFrameNodeForSelected()
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
        var calc_zoom = Math.min(1, Math.min(
                (editor_bcr.width - sidebarWidth) / ((canvasCentroid.maxX - canvasCentroid.minX) + sidebarWidth),
                editor_bcr.height / ((canvasCentroid.maxY - canvasCentroid.minY) - parentOffsetY)
            ),
        ) // Zoom out if needed
        calc_zoom = calc_zoom > 0 ? calc_zoom : 1
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
            var selected_module = all_modules_by_id[selection]
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
        $block.data('module', all_modules_by_id[$block[0].id])

        if ($(this).data('module').disabled) {
            $(this).addClass('disabled')
        }
        $(this).draggable({
            helper: "clone",
            scroll: false,
            disabled: $(this).data('module').disabled,
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
            if (event.pageX < 340) { // dirty hack to avoid drops on the sidebar
                return
            }
            ui.position.top += 96 // take padding/marging/position into account
            if (ui.draggable.data('blueprint')) {
                addWorkflowBlueprint(ui.draggable.data('blueprint').WorkflowBlueprint.id, ui.position)
            } else {
                var node = addNode(ui.draggable.data('module'), ui.position)
                var fakeUi = {
                    draggable: ui.helper,
                    position: { left: ui.helper[0].getBoundingClientRect().left, top: ui.helper[0].getBoundingClientRect().top }
                }
                var link = getLinkUnderElement(fakeUi)
                if (link !== undefined) {
                    insertNodeOnLink(node, link)
                }
            }
        },
        activate: function (event, ui) {
            var $pathsWithClass = $()
            ui.helper.mousemove(function (event) {
                var fakeUi = {
                    draggable: $(this),
                    position: {left: this.getBoundingClientRect().left, top: this.getBoundingClientRect().top}
                }
                var links = getLinkUnderElement(fakeUi)
                $pathsWithClass.removeClass('link-hover-for-insertion')
                if (links) {
                    $paths = $(links).find('path')
                    $paths.addClass('link-hover-for-insertion')
                    $pathsWithClass = $paths
                }
            })
        },
    });

    graphPooler = new TaskScheduler(checkGraphProperties, {
        interval: 10000,
        slowInterval: 60000,
    })

    filterModules($blockFilterGroup.find('button.active')[0])
    fetchAndLoadWorkflow().then(function() {
        graphPooler.start(undefined)
        editor.fitCanvas()
        // block contextual menu for trigger blocks
        $canvas.find('.canvas-workflow-block').on('contextmenu', function (evt) {
            var selectedNode = getSelectedNode()
            if (selectedNode !== undefined && selectedNode.data.module_data.module_type == 'trigger') {
                evt.stopPropagation();
                evt.preventDefault();
            }
        })
    })
    $saveWorkflowButton.click(saveWorkflow)
    $importWorkflowButton.click(importWorkflow)
    $exportWorkflowButton.click(exportWorkflow)
    $toggleWorkflowButton.click(enabledDebugMode)
    $runWorkflowButton.click(runWorkflow)
    $blockModal
        .on('show', function (evt) {
            var selectedNode = getSelectedNode()
            buildModalForBlock(selectedNode.id, selectedNode)
        })
        .on('shown', function (evt) {
            afterModalShowCallback()
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
        $controlFrameNodeButton.removeClass('disabled')
        $controlDeleteButton.removeClass('disabled')
        $controlSaveBlocksLi.removeClass('disabled')
        $controlEditBlocksLiContainer.removeClass('disabled').find('.dropdown-menu')
        selection.select([getNodeHtmlByID(node_id)])
    })
    editor.on('nodeUnselected', function() {
        selection.getSelection().forEach(function (el) {
            el.classList.remove('selected')
        })
        selection.clearSelection()
        $controlDuplicateButton.addClass('disabled')
        $controlFrameNodeButton.addClass('disabled')
        $controlDeleteButton.addClass('disabled')
        $controlSaveBlocksLi.addClass('disabled')
        $controlEditBlocksLiContainer.addClass('disabled').find('.dropdown-menu')
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
        duplicateSelection()
    })
    $controlFrameNodeButton.click(function() {
        createFrameNodeForSelected()
    })
    $controlDeleteButton.click(function() {
        deleteSelectedNodes(false)
    })
    $controlSaveBlocksLi.click(function(evt) {
        var $link = $(this).find('a')
        evt.preventDefault()
        if (!$(this).hasClass('disabled')) {
            saveBlueprint($link.attr('href'))
        }
    })
    $controlEditBlocksLis.click(function(evt) {
        var $link = $(this).find('a')
        evt.preventDefault()
        if (!$(this).hasClass('disabled')) {
            saveBlueprint($link.attr('href'))
        }
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
    var editorData = getEditorData(true)
    openGenericModal(href, undefined, function () {
        var trigger_id = (all_triggers_by_id[workflowTriggerId] || { id: 'unknown-trigger' }).id
        var nodes = selectedNodes.map(function (nodeHtml) {
            var node = editorData[nodeHtml.id.slice(5)]
            return node
        })
        var $modal = $('#genericModal')
        var $graphData = $modal.find('form #WorkflowBlueprintData')
        var $graphDescription = $modal.find('form #WorkflowBlueprintDescription')
        $graphData.val(JSON.stringify(nodes))
        if ($graphDescription.val().length == 0 ) {
            $graphDescription.val('[' + trigger_id + ']\n')
        }
        var $modalBody = $modal.find('.modal-body')
        $modalBody.append(
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
            var validParams = {}
            Object.entries(node.data.indexed_params).forEach(function (e) {
                var k = e[0], v = e[1]
                if (v) {
                    validParams[k] = v
                }
            })
            var validFilters = {}
            Object.entries(node.data.saved_filters).forEach(function (e) {
                var k = e[0], v = e[1]
                if (v) {
                    validFilters[k] = v
                }
            })
            $ul.append(
                $('<li></li>').append(
                    $('<strong></strong>').text(node.data.name),
                    $('<ul></ul>').append(
                        Object.values(validFilters).length == 0 ? null : $('<li></li>').text('Has filter').attr('title', JSON.stringify(validFilters, null, 4)),
                        Object.values(validParams).length == 0 ? null : $('<li></li>').text('Has ' + Object.values(validParams).length + ' parameters').attr('title', JSON.stringify(validParams, null, 4))
                    )
                )
            )
        })
        $modalBody.append($ul)
    })
}

function duplicateSelection() {
    var currentSelection = selection.getSelection()
    var newNodes = duplicateNodesFromHtml(currentSelection)
    selection.clearSelection()
    selection.select(newNodes)
}

function createFrameNodeForSelected() {
    var text = prompt('Enter text for the frame node')
    var selectedNodesHtml = selection.getSelection()
    var selectedIDs = selectedNodesHtml.map(function(nodeHtml) {
        return parseInt(nodeHtml.id.slice(5))
    })
    createFrameForNodes(selectedIDs, text)
    selection.clearSelection()
    invalidateContentCache()
}

function createFrameForNodes(nodesIDs, text) {
    const frameNode = {
        nodes: nodesIDs,
        text: text,
        class: "",
    }
    editor.addFrameNode(frameNode)
}

function buildModalForBlock(node_id, node) {
    var html = genNodeParamHtml(node, false)
    $blockModal
        .data('selected-block', node.data)
        .data('selected-node-id', node_id)
    $blockModal.find('.modal-body').empty().append(html)
}

function buildNotificationModalForBlock(node_id, data) {
    var html = genBlockNotificationForModalHtml(data)
    $blockNotificationModal
        .data('selected-block', data)
        .data('selected-node-id', node_id)
    $blockNotificationModal.find('.modal-body').empty().append(html)
}

function buildFilteringModalForNode(node_id, node) {
    var html = genModalFilteringHtml(node)
    $blockFilteringModal
        .data('selected-block', node.data)
        .data('selected-node-id', node_id)
    $blockFilteringModal.find('.modal-body').empty().append(html)
}

function showNotificationModalForBlock() {
    var selectedNode = getSelectedNode()
    buildNotificationModalForBlock(selectedNode.id, selectedNode.data)
    $blockNotificationModal.modal('show')
}

function showNotificationModalForModule(module_id, data) {
    buildNotificationModalForBlock(module_id, {module_data: data})
    $blockNotificationModal.modal('show')
}

function showNotificationModalForSidebarModule(clicked) {
    var $block = $(clicked).closest('.sidebar-workflow-block')
    var blockID = $block.data('blockid')
    showNotificationModalForModule(blockID, all_modules_by_id[blockID])
}

function showFilteringModalForNode() {
    var selectedNode = getSelectedNode()
    buildFilteringModalForNode(selectedNode.id, selectedNode)
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


function addNode(block, position, additionalData={}) {
    var module = all_modules_by_id[block.id] || all_triggers_by_id[block.id]
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

    var module_data = Object.assign({}, module)
    var newNode = {name: block.name, data: {}}
    if (additionalData.indexed_params) {
        newNode.data.indexed_params = additionalData.indexed_params
    }
    if (additionalData.saved_filters) {
        newNode.data.saved_filters = additionalData.saved_filters
    }
    newNode = mergeNodeAndModule(newNode, module_data)

    newNode.data['_node_param_html'] = genNodeParamHtml(newNode)
    newNode.data['_node_notification_html'] = genNodeNotificationHtml(newNode.data)
    newNode.data['_node_filter_html'] = genNodeFilteringHtml(newNode)
    var html = getTemplateForNode(newNode)
    var blockClass = newNode.data.module_data.class === undefined ? [] : newNode.data.module_data.class
    blockClass = !Array.isArray(blockClass) ? [blockClass] : blockClass
    blockClass.push('block-type-' + (newNode.data.module_data.html_template !== undefined ? newNode.data.module_data.html_template : 'default'))
    if (newNode.data.module_data.module_type == 'logic') {
        blockClass.push('block-type-logic')
    }
    if (newNode.data.module_data.expect_misp_core_format) {
        blockClass.push('expect-misp-core-format')
    }
    editor.addNode(
        newNode.name,
        module.inputs === undefined ? 1 : module.inputs,
        module.outputs === undefined ? 1 : module.outputs,
        pos_x,
        pos_y,
        blockClass.join(' '),
        newNode.data,
        html
    )
    afterNodeDrawCallback()
    return editor.getNodeFromId(editor.nodeId-1)
}

function getEditorData(cleanNodes) {
    var data = {} // Make sure nodes are index by their internal IDs
    var editorExport = editor.export().drawflow.Home.data
    var frameNodes = editorExport._frames !== undefined ? editorExport._frames : {}
    delete editorExport._frames
    editorExport = Array.isArray(editorExport) ? editorExport : Object.values(editorExport)
    editorExport.forEach(function(node) {
        if (node !== null) { // for some reason, the editor create null nodes
            if (cleanNodes && node.data.params !== undefined) {
                node.data.params = deleteInvalidParams(node.data.params)
                cleanedIndexedParams = {}
                node.data.params.forEach(function(param) {
                    cleanedIndexedParams[param.id] = param.value !== undefined ? param.value : param.default
                })
                node.data.indexed_params = cleanedIndexedParams
            }
            if (cleanNodes) {
                delete node.html
                delete node.data.module_data
                delete node.data.params
            }
            Object.keys(node.data).forEach(function (k) {
                if (k.startsWith('_')) {
                    delete node.data[k]
                }
            })
            data[node.id] = node
        }
    })
    data._frames = frameNodes
    return data
}

function deleteInvalidParams(params) {
    return params.filter(function(param) {
        return !param.is_invalid
    })
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
        console.error('Workflow doesn\'t have a trigger.')
        showMessage('fail', 'Workflow doesn\'t have a trigger.')
        return
    }
    // We cannot rely on the editor's import function as it recreates the nodes with the saved HTML instead of rebuilding them
    // We have to manually add the nodes and their connections
    Object.entries(workflow.data).forEach(function (entry) {
        var i = entry[0]
        var node = entry[1]
        if (i == '_frames') {
            return
        }
        var module = all_modules_by_id[node.data.id] || all_triggers_by_id[node.data.id]
        if (!module) {
            console.error('Tried to add node for unknown module ' + node.data.id + ' (' + node.id + ')')
            var html = window['dotBlock_error']({
                error: 'Invalid module id`' + node.data.id + '` (' + node.id + ')',
                data: JSON.stringify(node.data.indexed_params, null, 2)
            })
            editor.addNode(
                node.name,
                Object.values(node.inputs).length,
                Object.values(node.outputs).length,
                node.pos_x,
                node.pos_y,
                '',
                node.data,
                html
            )
            return
        }
        var module_data = Object.assign({}, module)
        var newNode = mergeNodeAndModule(node, module_data)
        newNode.data['_node_param_html'] = genNodeParamHtml(newNode)
        newNode.data['_node_notification_html'] = genNodeNotificationHtml(newNode.data)
        newNode.data['_node_filter_html'] = genNodeFilteringHtml(newNode)
        var nodeClass = newNode.data.module_data.class === undefined ? [] : newNode.data.module_data.class
        nodeClass = !Array.isArray(nodeClass) ? [nodeClass] : nodeClass
        nodeClass.push('block-type-' + (newNode.data.module_data.html_template !== undefined ? newNode.data.module_data.html_template : 'default'))
        if (newNode.data.module_data.module_type == 'logic') {
            nodeClass.push('block-type-logic')
        }
        if (newNode.data.module_data.expect_misp_core_format) {
            nodeClass.push('expect-misp-core-format')
        }
        if (newNode.data.module_data.disabled) {
            nodeClass.push('disabled')
        }
        var html = getTemplateForNode(newNode)
        editor.nodeId = newNode.id // force the editor to use the saved id of the node instead of generating a new one
        editor.addNode(
            newNode.data.name,
            Object.values(newNode.inputs).length,
            Object.values(newNode.outputs).length,
            newNode.pos_x,
            newNode.pos_y,
            nodeClass.join(' '),
            newNode.data,
            html
        )
    })
    afterNodeDrawCallback()
    Object.values(workflow.data).forEach(function (node) {
        for (var input_name in node.inputs) {
            node.inputs[input_name].connections.forEach(function (connection) {
                connection.labels = connection.labels === undefined ? [] : connection.labels;
                var labels = connection.labels.map(function(labelConf) {
                    return dotBlock_connectionLabel(labelConf)
                })
                editor.addConnection(connection.node, node.id, connection.input, input_name, labels)
            })
        }
    })
    var frameNodes = workflow.data._frames || {}
    Object.values(frameNodes).forEach(function (frameNode) {
        editor.addFrameNode(frameNode)
    })
}

function filterModules(clicked) {
    var $activeButton = $(clicked)
    var selectedFilter
    if ($activeButton.length > 0) {
        selectedFilter = $activeButton.data('type')
    } else {
        selectedFilter = 'enabled'
    }
    var $modulesToShow = $('.sidebar .tab-pane.active').find('.sidebar-workflow-block')
    $modulesToShow.show()
    if (selectedFilter == 'enabled') {
        $modulesToShow.filter(function() {
            return $(this).data('module')['disabled']
        }).hide()
    } else if (selectedFilter == 'misp-module') {
        $modulesToShow.filter(function () {
            return !$(this).data('module')['is_misp_module'] || $(this).data('module')['disabled']
        }).hide()
    } else if (selectedFilter == 'is-blocking') {
        $modulesToShow.filter(function () {
            return !$(this).data('module')['blocking'] || $(this).data('module')['disabled']
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
        if (node.data.module_data.module_type == 'trigger') {
            return
        }
        var position = {
            top: nodeHtml.getBoundingClientRect().top - 100 * editor.zoom,
            left: nodeHtml.getBoundingClientRect().left + 100 * editor.zoom,
        }
        var newNode = Object.assign({}, all_modules_by_id[node.data.module_data.id])
        var additionalData = {
            indexed_params: node.data.indexed_params,
            saved_filters: node.data.saved_filters,
        }
        addNode(newNode, position, additionalData)
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
                        connection.output,
                        []
                    )
                }
            });
        })
    })
    return newNodes
}

function addNodesFromBlueprint(workflowBlueprint, cursorPosition) {
    var newNodes = []
    if (workflowBlueprint.data.length == 0) {
        return counterNodeAdded
    }
    var oldNewIDMapping = {}
    // We position all nodes relatively based on the left most node
    var minX = workflowBlueprint.data[0].pos_x
    var matchingY = workflowBlueprint.data[0].pos_y
    workflowBlueprint.data.forEach(function(node) {
        minX = node.pos_x < minX ? node.pos_x : minX
        matchingY = node.pos_x < minX ? node.pos_y : matchingY
    })
    workflowBlueprint.data.forEach(function(node) {
        if (node.data.module_type == 'trigger') {
            return
        }
        var position = {
            top: (node.pos_y - matchingY) * editor.zoom + cursorPosition.top,
            left: (node.pos_x - minX) * editor.zoom + cursorPosition.left,
        }
        if (all_modules_by_id[node.data.id] === undefined) {
            var errorMessage = 'Invalid ' + node.data.module_type + ' module id `' + node.data.id + '` (' + node.id + ')'
            var html = window['dotBlock_error']({
                error: errorMessage,
                data: JSON.stringify(node.data.indexed_params, null, 2)
            })
            editor.addNode(
                node.name,
                Object.values(node.inputs).length,
                Object.values(node.outputs).length,
                node.pos_x,
                node.pos_y,
                '',
                node.data,
                html
            )
        } else {
            additionalData = {
                indexed_params: node.data.indexed_params,
                saved_filters: node.data.saved_filters,
            }
            addNode(all_modules_by_id[node.data.id], position, additionalData)
        }
        oldNewIDMapping[node.id] = editor.nodeId - 1
        newNodes.push(getNodeHtmlByID(editor.nodeId - 1)) // nodeId is incremented as soon as a new node is created
    })
    workflowBlueprint.data.forEach(function (node) {
        Object.keys(node.outputs).forEach(function (outputName) {
            var outputCount = all_modules_by_id[node.data.id] !== undefined ? all_modules_by_id[node.data.id].outputs : Object.keys(node.outputs).length
            if (outputCount > 0) { // make sure the module configuration didn't change in regards of the outputs
                node.outputs[outputName].connections.forEach(function (connection) {
                    if (oldNewIDMapping[connection.node] !== undefined) {
                        editor.addConnection(
                            oldNewIDMapping[node.id],
                            oldNewIDMapping[connection.node],
                            outputName,
                            connection.output,
                            []
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

function mergeNodeAndModule(node, module_data) {
    if (node.data === undefined) {
        node.data = {}
    }
    node.data.node_uid = uid() // only used for UI purposes
    node.data.params = node.data.params !== undefined ? node.data.params : []
    node.data.indexed_params = node.data.indexed_params !== undefined ? node.data.indexed_params : {}
    node.data.saved_filters = node.data.saved_filters !== undefined ? node.data.saved_filters : {}
    node.data.module_type = module_data.module_type
    node.data.id = module_data.id
    node.data.name = node.data.name ? node.data.name : module_data.name
    node.data.module_data = module_data
    node.data.multiple_output_connection = module_data.multiple_output_connection
    node.data.previous_module_version = node.data.module_version ? node.data.module_version : '?'
    node.data.module_version = module_data.version
    node.data.params = mergeNodeAndModuleParams(node, module_data.params)
    node.data.indexed_params = getIndexedParams(node, module_data.params)
    node.data.saved_filters = mergeNodeAndModuleFilters(node, module_data.saved_filters)
    return node
}

function mergeNodeAndModuleParams(node, moduleParams) {
    var moduleParamsById = {}
    var nodeParamsById = {}
    moduleParams.forEach(function (param, i) {
        if (param.id === undefined) { // Param id is not set in the module definition.
            param.id = 'param-' + i
            param.no_id = true
        }
        moduleParamsById[param.id] = param
    })
    Object.entries(node.data.indexed_params).forEach(function (e) {
        var param_id = e[0], val = e[1]
        nodeParamsById[param_id] = {
            id: param_id,
            label: param_id,
            type: 'input',
            value: val
        }
    })
    var procesedParams = {}
    var finalParams = []
    var fakeNodeFullParams = Object.values(nodeParamsById)
    var nodeAndModuleParams = moduleParams.concat(fakeNodeFullParams)
    nodeAndModuleParams.forEach(function (param) {
        var finalParam
        if (procesedParams[param.id]) { // param has already been processed
            return;
        }
        procesedParams[param.id] = true
        if (moduleParamsById[param.id] === undefined) { // Param do not exist in the module (anymore or never did)
            param.is_invalid = true
            finalParam = Object.assign({}, nodeParamsById[param.id])
        } else {
            finalParam = Object.assign({}, moduleParamsById[param.id])
            finalParam.value = node.data.indexed_params[param.id]
        }
        if (!finalParam['param_id']) {
            finalParam['param_id'] = getIDForNodeParameter(node, finalParam)
        }
        finalParams.push(finalParam)
    })
    return finalParams
}

function getIndexedParams(node, moduleParams) {
    var finalParams = {}
    moduleParams.forEach(function (param, i) {
        if (param.id === undefined) { // Param id is not set in the module definition.
            param.id = 'param-' + i
            param.no_id = true
        }
        finalParams[param.id] = node.data.indexed_params[param.id] ? node.data.indexed_params[param.id] : (param.default ? param.default : '')
    })
    return finalParams
}

function mergeNodeAndModuleFilters(node, moduleFilters) {
    node.saved_filters = node.data.saved_filters ? node.data.saved_filters : []
    var finalFilters = {}
    moduleFilters.forEach(function(filter) {
        finalFilters[filter.text] = node.data.saved_filters[filter.text] ? node.data.saved_filters[filter.text] : filter.value
    })
    return finalFilters
}

/* API */
function fetchWorkflow(id, callback) {
    var url = baseurl + '/workflows/view/' + id + '.json'
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

function enabledDebugMode() {
    var $clicked = $(this)
    enableWorkflowDebugMode(workflow_id, $clicked.data('enabled'), function(result) {
        if (result.saved) {
            $clicked.data('enabled', !$clicked.data('enabled'))
            if ($clicked.data('enabled')) {
                $clicked.removeClass('btn-primary').addClass('btn-success')
            } else {
                $clicked.removeClass('btn-success').addClass('btn-primary')
            }
            $clicked.find('.state-text').text($clicked.find('.state-text').data($clicked.data('enabled') ? 'on' : 'off'))
            $runWorkflowButton.prop('disabled', $clicked.data('enabled') ? false : true)
        }
    })
}

function runWorkflow() {
    var html = '<div style="width: 350px;"><textarea rows=15 style="width: 100%; box-sizing: border-box;" placeholder="Enter data to be sent to the workflow"></textarea><div style="display: flex;"><button class="btn btn-primary" style="margin: 0 0 0 auto;"><i class="fa fa-spin fa-spinner hidden"></i> Run Workflow</button></div><pre style="margin-top: 0.75em;"></pre></div>'
    var popoverOptions = {
        html: true,
        placement: 'bottom',
        trigger: 'click',
        content: html,
        container: 'body',
        template: '<div class="popover" role="tooltip"><div class="arrow"></div><h3 class="popover-title"></h3><div class="popover-content"><div class="data-content"></div></div></div>'
    }
    if ($runWorkflowButton.data().popover === undefined) {
        $runWorkflowButton
            .popover(popoverOptions)
            .on('shown.bs.popover', function () {
                var $popover = $runWorkflowButton.data('popover').tip()
                $popover.find('button').click(function() {
                    var url = baseurl + "/workflows/executeWorkflow/" + workflow.Workflow.id
                    fetchFormDataAjax(url, function (formHTML) {
                        $('body').append($('<div id="temp" style="display: none"/>').html(formHTML))
                        var $tmpForm = $('#temp form')
                        var formUrl = $tmpForm.attr('action')
                        data = $popover.find('textarea').val()
                        $tmpForm.find('[name="data[Workflow][data]"]').val(data)

                        $.ajax({
                            data: $tmpForm.serialize(),
                            beforeSend: function() {
                                $popover.find('pre').empty()
                                $popover.find('button i').removeClass('hidden')
                            },
                            success: function (data) {
                                $popover.find('pre').text(data)
                            },
                            error: xhrFailCallback,
                            complete: function () {
                                $('#temp').remove();
                                $popover.find('button i').addClass('hidden')
                            },
                            type: 'post',
                            cache: false,
                            url: formUrl,
                        })
                    })
                })
            })
            .popover('show')
    }
}

function getSelectedNodeID() {
    return editor.node_selected !== null ? editor.node_selected.id : null // Couldn't find a better way to get the selected node
}

function getSelectedNodeIDInteger() {
    var nodeId = getSelectedNodeID()
    return nodeId ? parseInt(nodeId.split('-')[1]) : null // Couldn't find a better way to get the selected node
}

function getNodeHtmlByID(node_id) {
    return editor.precanvas.querySelector('#node-' + node_id)
}

function getSelectedNode() {
    var nodeId = getSelectedNodeIDInteger()
    return nodeId ? editor.getNodeFromId(nodeId) : [];
}

function deleteSelectedNode() {
    deleteNodeByID(getSelectedNodeID())
}

function deleteNodeByID(nodeId) {
    nodeIdInt = nodeId.slice(5)
    editorData = getEditorData()
    if (all_triggers_by_id[editorData[nodeIdInt].data.id]) {
        return
    }
    editor.removeNodeId(nodeId)
}

function getNodeFromContainedHtml(htmlNode) {
    var $drawflowNode = $(htmlNode).closest('.drawflow-node')
    var nodeStringId = $drawflowNode.attr('id')
    var nodeId = nodeStringId ? parseInt(nodeStringId.split('-')[1]) : null 
    return nodeId !== null ? editor.getNodeFromId(nodeId) : null
}

function deleteSelectedNodes(fromDelKey) {
    selection.getSelection().forEach(function(node) {
        if (fromDelKey && getSelectedNodeID() !== null && getSelectedNodeID() == node.id) {
            return // This node will be removed by drawflow delete callback
        }
        deleteNodeByID(node.id)
    })
    editor.dispatch('nodeUnselected')
}

function addWorkflowBlueprint(blueprintId, cursorPosition) {
    var workflowBlueprint = all_workflow_blueprints_by_id[blueprintId]
    if (!workflowBlueprint) {
        console.error('Tried to get workflow blueprint ' + blueprintId)
        return '';
    }
    if (!cursorPosition) {
        var centroid = getCanvasCentroid()
        cursorPosition = {
            top: centroid.centroidY,
            left: centroid.centroidX,
        }
    }
    var newNodes = addNodesFromBlueprint(workflowBlueprint.WorkflowBlueprint, cursorPosition);
    if (newNodes.length > 0) {
        selection.clearSelection()
        selection.select(newNodes)
        var newNodeIDs = newNodes.map(function(node) {
            return node.id.slice(5)
        })
        createFrameForNodes(newNodeIDs, workflowBlueprint.WorkflowBlueprint.name)

        editor.dispatch('nodeSelected', newNodes[0].id);
    }
}

function getLinkUnderElement(ui) {
    var orig_pos_x = ui.position.left
    var orig_pos_y = ui.position.top
    var elementHeight = ui.draggable[0].clientHeight
    var elementCenterY = ui.position.top + ui.draggable[0].clientHeight / 2

     // Credit: Drawflow example page
    var transpositionFactorX = (editor.precanvas.clientWidth / (editor.precanvas.clientWidth * editor.zoom))
    var transpositionOffsetX = -(editor.precanvas.getBoundingClientRect().x * (editor.precanvas.clientWidth / (editor.precanvas.clientWidth * editor.zoom)))
    var transpositionFactorY = (editor.precanvas.clientHeight / (editor.precanvas.clientHeight * editor.zoom))
    var transpositionOffsetY = -(editor.precanvas.getBoundingClientRect().y * (editor.precanvas.clientHeight / (editor.precanvas.clientHeight * editor.zoom)))

    var pos_x = orig_pos_x * transpositionFactorX + transpositionOffsetX
    var pos_y = orig_pos_y * transpositionFactorY + transpositionOffsetY
    var transposedHeight = (orig_pos_y + elementHeight) * transpositionFactorY + transpositionOffsetY
    var transposedCenterY = elementCenterY * transpositionFactorY + transpositionOffsetY

    var $allConnectionMiddlePoint = $drawflow.find('svg.connection > foreignObject')
    var allValidLinks = []
    $allConnectionMiddlePoint.each(function() {
        var middlePointY = this.y.baseVal.value
        if (pos_y <= middlePointY && middlePointY <= transposedHeight) {
            var $svg = this.parentElement.childNodes[0]
            var svgBR = $svg.getBoundingClientRect()
            var linkTransposedLeftPosition = svgBR.x * transpositionFactorX + transpositionOffsetX
            var linkTransposedRightPosition = (svgBR.x + svgBR.width) * transpositionFactorX + transpositionOffsetX
            if (linkTransposedLeftPosition <= pos_x && pos_x <= linkTransposedRightPosition) {
                allValidLinks.push(this.parentElement)
            }
        }
    })

    if (allValidLinks.length == 1) {
        return allValidLinks[0]
    } else if (allValidLinks.length > 1) {
        // sort based on distance between link middle point and element input
        function calcDistance(pt1, pt2) {
            return Math.sqrt((pt2.x - pt1.x)**2 + (pt2.y - pt1.y)**2)
        }
        var elementInputPosition = { x: pos_x, y: transposedCenterY }
        var allValidLinksSorted = allValidLinks.sort(function (link1, link2) {
            var middlePoint1 = {
                x: $(link1).find('foreignObject')[0].x.baseVal.value,
                y: $(link1).find('foreignObject')[0].y.baseVal.value,
            }
            var middlePoint2 = {
                x: $(link2).find('foreignObject')[0].x.baseVal.value,
                y: $(link2).find('foreignObject')[0].y.baseVal.value,
            }
            var distance1 = calcDistance(elementInputPosition, middlePoint1)
            var distance2 = calcDistance(elementInputPosition, middlePoint2)
            return distance1 <= distance2 ? -1 : 1
        });
        return allValidLinksSorted[0]
    }
    return
}

function insertNodeOnLink(newNode, link) {
    var defaultConnectionName = 'output_1'
    var ids = getIDsFromSvgLink(link)
    var nodeIn = ids.nodeIn
    var inConnectionName = ids.inConnectionName
    var nodeOut = ids.nodeOut
    var outConnectionName = ids.outConnectionName
    editor.addConnection(nodeOut, newNode.id, outConnectionName, inConnectionName, [])
    editor.addConnection(newNode.id, nodeIn, defaultConnectionName, inConnectionName, [])
    editor.removeSingleConnection(nodeOut, nodeIn, outConnectionName, inConnectionName)
}

function getIDsFromSvgLink(link) {
    return {
        'nodeIn': parseInt(Array.from(link.classList).filter(c => c.startsWith('node_in_node-'))[0].replace('node_in_node-', '')),
        'inConnectionName': Array.from(link.classList).filter(c => c.startsWith('input_'))[0],
        'nodeOut': parseInt(Array.from(link.classList).filter(c => c.startsWith('node_out_node-'))[0].replace('node_out_node-', '')),
        'outConnectionName': Array.from(link.classList).filter(c => c.startsWith('output_'))[0],
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

function getTemplateForNode(node) {
    var html = ''
    node.data.module_data.icon_class = node.data.module_data.icon_class ? node.data.module_data.icon_class : 'fas'
    if (node.data.module_data.html_template !== undefined) {
        if (window['dotBlock_' + node.data.module_data.html_template] !== undefined) {
            html = window['dotBlock_' + node.data.module_data.html_template](node.data)
        } else {
            html = 'Wrong HTML template'
            console.error('Wrong HTML template for node', node)
        }
    } else {
        html = dotBlock_default(node.data)
    }
    return html
}

function genNodeParamHtml(node, forNode = true) {
    var nodeParams = node.data.params !== undefined ? node.data.params : []
    var html = ''
    nodeParams.forEach(function (param) {
        paramHtml = ''
        switch (param.type) {
            case 'input':
                paramHtml = genInput(param, false, forNode)[0].outerHTML
                break;
            case 'hashpath':
                paramHtml = genHashpathInput(param, false, forNode)[0].outerHTML
                break;
            case 'textarea':
                paramHtml = genInput(param, true, forNode)[0].outerHTML
                break;
            case 'select':
                paramHtml = genSelect(param, forNode)[0].outerHTML
                break;
            case 'picker':
                paramHtml = genPicker(param, forNode)[0].outerHTML
                break;
            case 'checkbox':
                paramHtml = genCheckbox(param, forNode)[0].outerHTML
                break;
            case 'radio':
                paramHtml = genRadio(param, forNode)[0].outerHTML
                break;
            default:
                break;
        }
        html += paramHtml
    })
    return html
}

function afterNodeDrawCallback() {
    var $nodes = $drawflow.find('.drawflow-node')
    $nodes.find('.start-chosen').each(function() {
        var chosenOptions = $(this).data('chosen_options')
        $(this).chosen(chosenOptions).trigger('change')
    })
    toggleDisplayOnFields()
    enablePickerCreateNewOptions()
    enableHashpathPicker()
}

function afterModalShowCallback() {
    $blockModal.find('.start-chosen').each(function() {
        var chosenOptions = $(this).data('chosen_options')
        $(this).chosen(chosenOptions).trigger('change')
    })
    var cmOptions = {
        theme: 'default',
        lineNumbers: true,
        indentUnit: 4,
        showCursorWhenSelecting: true,
        lineWrapping: true,
        autoCloseBrackets: true,
        extraKeys: {
            "Esc": function () {
            },
        },
    }
    $blockModal.find('.start-codemirror').each(function() {
        CodeMirror.fromTextArea(this, cmOptions).on('change', function(cm, e) {
            cm.save()
            handleInputChange(cm.getTextArea())
        })
    })
}

function toggleDisplayOnFields() {
    var $nodes = $drawflow.find('.drawflow-node')
    $nodes.find('div.node-param-container.display-on').each(function() {
        var $container = $(this)
        var node = getNodeFromContainedHtml($container)
        var param_id = $container.attr('param-id')
        var node_param_config = node.data.module_data.params.filter(function(param_config) {
            return param_config.id == param_id
        })
        var showContainer = false
        if (node_param_config) {
            node_param_config = node_param_config[0]
            Object.keys(node_param_config.display_on).forEach(function(target_param_id) {
                var target_param_values = node_param_config.display_on[target_param_id]
                var node_param_value = node.data.indexed_params[target_param_id]
                if (Array.isArray(target_param_values) && target_param_values.includes(node_param_value)) {
                    showContainer = true
                } else if (target_param_values == node_param_value) {
                    showContainer = true
                }
            });
        }
        if (showContainer) {
            $container.show()
        } else {
            $container.hide()
        }
    })
}

function enablePickerCreateNewOptions() {
    var $nodes = $drawflow.find('.drawflow-node')
    $nodes.find('.start-chosen[picker_create_new="1"]').each(function () {
        var $select = $(this)
        var $input = $select.parent().find('.chosen-search-input')

        $input.on('keydown', function(evt) {
            if (evt.which == 13) { // <ENTER>
                var newVal = $input.val()
                var optionExists = $select.find('option').filter(function () {
                    return $(this).val() == newVal
                }).length > 0
                if (!optionExists) {
                    var $newOption = $('<option>')
                        .val(newVal)
                        .text(newVal)
                    $select.append($newOption);
                    $select.trigger('chosen:updated');
                }
            }
        })
    })
}

function enableHashpathPicker() {
    var $nodes = $drawflow.find('.drawflow-node')
    $nodes.find('.hashpath-picker-container').each(function () {
        $(this).find('.hashpath-quick-picker').click(function () {
            $(this).closest('.input-append').find('input')
                .val($(this).data('hashpath'))
                .trigger('input')
            
        })
        $(this).find('.hashpath-format-picker').click(function() {
            toggleCoreFormatPicker(this)
        })
    })
}

function redrawFormatPicker(json, associatedParamId) {
    var jsonData = JSON.parse(json)
    var $customDataInput = genCustomDataInputForHashpathPicker(associatedParamId)
    var UIPicker = generateCoreFormatUI(jsonData, associatedParamId)
    var $modalBody = $('<div>').attr('style', 'display: flex; flex-direction: column').append($customDataInput, UIPicker)
    $('#core-format-picker').parent().html($modalBody[0])
}

function genCustomDataInputForHashpathPicker(associatedParamId) {
    return $('<input>')
        .attr({
            id: 'hashpath-custom-format-input',
            type: 'text',
            placeholder: 'Provide a custom JSON',
            onchange: 'redrawFormatPicker(this.value, "' + associatedParamId + '")',
            style: 'flex-grow: 1; width: unset;'
        })
}

function toggleCoreFormatPicker(btn) {
    var associatedParamId = $(btn).closest('.input-append').find('input').data('paramid')
    var sample = JSON.parse($('#misp-core-format-sample').text())
    var UIPicker = generateCoreFormatUI(sample, associatedParamId)
    var $customDataInput = genCustomDataInputForHashpathPicker(associatedParamId)
    var $selectedPath = $('<input>')
        .attr({
            id: 'selected-hashpath-input',
            type: 'text',
            placeholder: 'Click on a elemet on the JSON to show the path',
            onchange: 'setValueOnAssociatedInput(this.value, "' + associatedParamId + '")',
        })
        .css({ margin: '0 0.75em 0 0', 'flex-grow': 2 })
    var $selectedPathOperators = $('<select>')
        .attr({
            id: 'selected-hashpath-operator',
            onchange: 'setHashpathOnInput(this, "' + associatedParamId + '")',
        })
        .css({margin: '0', 'max-width': '15%'})
    var pathOperators = [
        { name: 'Has key []', stringToFormat: '[{$key}]' },
        { name: 'Match [=]', stringToFormat: '[{$key}={$value}]', default: true },
        { name: 'Match [!=]', stringToFormat: '[{$key}!={$value}]' },
        { name: 'Match [>]', stringToFormat: '[{$key}>{$value}]' },
        { name: 'Match [>=]', stringToFormat: '[{$key}>={$value}]' },
        { name: 'Match [<]', stringToFormat: '[{$key}<{$value}]' },
        { name: 'Match [<=]', stringToFormat: '[{$key}<={$value}]' },
        { name: 'Regex match [/.../]', stringToFormat: '[{$key}=/\S*\{$value}\S*/]' },
    ]
    pathOperators.forEach((opt) => {
        var $option = $('<option>')
            .val(opt.stringToFormat)
            .text(opt.name)
        if (opt.default === true) {
            $option.attr('selected', 'selected')
        }
        $selectedPathOperators.append($option)
    })
    $pathGroup = $('<span>').css({'display': 'flex', 'width': '100%'})
        .append($selectedPathOperators, $selectedPath)
    var $closeButton = $('<div>').append($('<a href="#" class="btn" data-dismiss="modal">Close</a>'))
    var $footer = $('<div>').css({display: 'flex'}).append($pathGroup, $closeButton)
    var $modalBody = $('<div>').attr('style', 'display: flex; flex-direction: column').append($customDataInput, UIPicker)
    openModal('Pick Hash path', $modalBody[0].outerHTML, $footer[0].outerHTML, undefined, undefined, 'max-height: 70vh;', 'modal-lg')
}

function genParameterWarning(options) {
    var text = '', text_short = ''
    if (options.is_invalid) {
        text = 'This parameter does not exist in the associated module and thus will be removed upon saving. Make sure you have the latest version of this module.'
        text_short = 'Invalid parameter'
    } else if (options.no_id) {
        text = 'This parameter does not have an ID in the associated module and thus will be ignored. Make sure you have the latest version of this module.'
        text_short = 'parameter has no ID'
    }
    if (text || text_short) {
        return $('<span>').addClass('text-error').css('margin-left', '5px')
            .append(
                $('<i>').addClass('fas fa-exclamation-triangle'),
                $('<span>').text(text_short)
            )
            .attr('title', text)
    }
    return ''
}

function genJinjaIconIfSupported(options) {
    if (!options.jinja_supported) {
        return ''
    }
    return $('<img/>').attr({
        src: "/img/jinja.png",
        alt: "Jinja icon",
        title: "This input supports Jinja2 templating",
        width: "36",
        height: "12",
    })
}

function genSelect(options, forNode = true) {
    var $container = $('<div>')
        .addClass('node-param-container')
        .attr('param-id', options.id)
    if (options.display_on) {
        $container.addClass('display-on')
    }
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
        $select.attr('size', 1)
    }
    if (options.picker_create_new) {
        options.multiple = true
        $select.attr('picker_create_new', 1)
        $select.prop('multiple', true)
        if (!options.options) {
            options.options = []
        }
        if (options.value) {
            if (Array.isArray(options.value)) {
                options.options = options.options.concat(options.value)
            } else {
                options.options.push(options.value)
            }
        }
    }
    if (options.disabled !== undefined) {
        $select.prop('disabled', options.disabled == true)
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
            if (options.multiple && Array.isArray(options.value)) {
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

function genPicker(options, forNode = true) {
    var $container = genSelect(options)
    var $select = $container.find('select')
    $select.addClass('start-chosen')
    var pickerOptions = options.picker_options ?? {}
    pickerOptions['max_shown_results'] = 100
    $select.attr('data-chosen_options', JSON.stringify(pickerOptions))
    return $container
}

function genInput(options, isTextArea, forNode = true) {
    var $container = $('<div>')
        .addClass('node-param-container')
        .attr('param-id', options.id)
    if (options.display_on) {
        $container.addClass('display-on')
    }
    var $label = $('<label>')
        .css({
            marginLeft: '0.25em',
            marginBbottom: 0,
        })
        .append(
            genJinjaIconIfSupported(options),
            $('<span>').text(options.label),
            genParameterWarning(options)
        )
    var $input
    if (isTextArea) {
        if (forNode) {
            $input = $('<textarea>').attr('rows', 1).prop('disabled', true).css({ resize: 'none' }).attr('title', 'Can only be edited in node settings')
        } else {
            $input = $('<textarea>').attr('rows', 4).css({resize: 'none'}).addClass('start-codemirror')
        }
    } else {
        $input = $('<input>').attr('type', 'text').css({height: '30px'})
    }
    if (options['jinja_supported']) {
        $input.addClass('jinja')
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
    if (options.disabled !== undefined) {
        $input.prop('disabled', options.disabled == true)
    }
    $label.append($input)
    $container.append($label)
    return $container
}

function genHashpathInput(options, forNode = true) {
    function hashPathGenDropdownMenu(hashpathOptions) {
        var haspathQuickPickMenu = hashpathOptions.is_sub_selector ? haspathQuickPickMenuSubElementSelector : haspathQuickPickMenuElementSelector
        var $divider = $('<li>').addClass('divider')
        var $dropdownMenu = $('<ul>').addClass('dropdown-menu pull-right')
        var $liPicker = $('<li>').append(
            $('<a>')
                .attr({
                    'tabindex': '-1',
                    'href': '#',
                })
                .addClass('hashpath-format-picker')
                .text('Show picker')
        )
        $dropdownMenu.append($liPicker)
        $dropdownMenu.append($divider)
        haspathQuickPickMenu.forEach((entry) => {
            var $li = $('<li>').append(
                $('<a>')
                    .attr({
                        'tabindex': '-1',
                        'href': '#',
                        'data-hashpath': entry.path
                    })
                    .addClass('hashpath-quick-picker')
                    .text(entry.name)
            )
            $dropdownMenu.append($li)
        })
        return $dropdownMenu
    }

    var $container = $('<div>')
        .addClass('node-param-container')
        .attr('param-id', options.id)
    if (options.display_on) {
        $container.addClass('display-on')
    }
    var $addonContainer = $('<div>')
        .addClass('input-append')
        .css({'display': 'flex'})
    var $label = $('<label>')
        .css({
            marginLeft: '0.25em',
            marginBbottom: 0,
        })
        .append(
            $('<span>').text(options.label),
            genParameterWarning(options)
        )
    var $input = $('<input>').attr('type', 'text').css({ height: '30px' })
    $input.css({
        'flex-grow': '1',
        'box-sizing': 'border-box',
    })
    $input
        .attr('oninput', 'handleInputChange(this)')
        .attr('data-paramid', options.param_id)
    $input.attr('value', options.value !== undefined ? options.value : options.default)
    if (options.placeholder !== undefined) {
        $input.attr('placeholder', options.placeholder)
    }
    if (options.disabled !== undefined) {
        $input.prop('disabled', options.disabled == true)
    }
    var $dropdownContainer = $('<div>').addClass(['btn-group', 'hashpath-picker-container'])
    var $dropdownButton = $('<button>')
        .addClass(['btn', 'dropdown-toggle'])
        .attr('data-toggle', 'dropdown')
        .text('Pick ')
        .append($('<span>').addClass('caret'))
    var $dropdownMenu = hashPathGenDropdownMenu(options.hashpath ? options.hashpath : {})
    $dropdownContainer.append($dropdownButton, $dropdownMenu)
    $addonContainer.append($input, $dropdownContainer)
    $container.append($label, $addonContainer)
    return $container
}

function genCheckbox(options, forNode = true) {
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
    if (options.disabled !== undefined) {
        $input.prop('disabled', options.disabled == true)
    }
    $label.append($input)
    var $container = $('<div>')
        .addClass('node-param-container')
        .data('param-id', options.id)
        .addClass('checkbox')
        .append($label)
    if (options.display_on) {
        $container.addClass('display-on')
    }
    return $container
}

function genRadio(options, forNode = true) {
    var $container = $('<div>')
        .addClass('node-param-container')
        .data('param-id', options.id)
    if (options.display_on) {
        $container.addClass('display-on')
    }
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
        if (options.disabled !== undefined) {
            $input.prop('disabled', options.disabled == true)
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
    toggleDisplayOnFields()
    invalidateContentCache()
}

function handleSelectChange(changed) {
    var $input = $(changed)
    var node = getNodeFromNodeInput($input)
    var node_data = setParamValueForInput($input, node.data)
    editor.updateNodeDataFromId(node.id, node_data)
    toggleDisplayOnFields()
    invalidateContentCache()
}

function saveFilteringForModule() {
    var selector = $blockFilteringModal.find('input#element_selector').val()
    var value = $blockFilteringModal.find('input#value').val()
    var operator = $blockFilteringModal.find('select#operator').val()
    var path = $blockFilteringModal.find('input#hash_path').val()
    if (selector.length > 0 && (value.length == 0 || operator.length == 0 || path.length == 0)) {
        $blockFilteringModal.find('.modal-body').append(
            $('<div></div>').addClass('alert alert-danger').text('Some fields cannot be empty')
        )
    } else {
        if (selector.length == 0 && value.length == 0 && path.length == 0) {
            operator = ''
        }
        var node_id = $blockFilteringModal.data('selected-node-id')
        var block = $blockFilteringModal.data('selected-block')
        block.saved_filters = {
            selector: selector,
            value: value,
            operator: operator,
            path: path,
        }
        editor.updateNodeDataFromId(node_id, block)
        if (selector.length > 0) {
            $drawflow.find('#node-' + node_id).find('.filtering-button').addClass('btn-success')
        } else {
            $drawflow.find('#node-' + node_id).find('.filtering-button').removeClass('btn-success')
        }
        invalidateContentCache()
        $blockFilteringModal.modal('hide')
    }
}

function getIDForNodeParameter(node, param) {
    if (param.id !== undefined) {
        return param.id + '-' + node.data.node_uid
    }
    return param.id + '-' + node.data.node_uid
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
            node_data.indexed_params[param.id] = newValue
        }
    }
    return node_data
}

function genNodeNotificationHtml(block) {
    // var module = all_modules_by_id[block.id] || all_triggers_by_id[block.id]
    var module = all_modules_by_id[block.module_data.id] || all_triggers_by_id[block.module_data.id]
    if (!module) {
        console.error('Tried to get notification of unknown module ' + block.module_data.id)
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
                    'data-blockid': block.module_data.id,
                })
                .addClass('btn-' + classBySeverity[severity])
                .css({
                    'vertical-align': 'middle',
                    'margin-right': '0.25em',
                    'white-space': 'nowrap',
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
    // var module = all_modules_by_id[block.id] || all_triggers_by_id[block.id]
    var module = all_modules_by_id[block.module_data.id] || all_triggers_by_id[block.module_data.id]
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

function genNodeFilteringHtml(node) {
    var module = all_modules_by_id[node.data.module_data.id] || all_triggers_by_id[node.data.module_data.id]
    var html = ''
    if (module.support_filters) {
        var $link = $('<a></a>')
            .attr({
                href: '#block-filtering-modal',
                role: 'button',
                class: 'filtering-button btn btn-mini ' + (getFiltersFromNode(node).value ? 'btn-success' : ''),
                onclick: 'showFilteringModalForNode(this)',
                title: 'Module filtering conditions'
            })
            .append($('<i></i>')
            .addClass('fas fa-filter'))
        html += $link[0].outerHTML
    }
    return html
}

function genModalFilteringHtml(node) {
    var module = all_modules_by_id[node.data.module_data.id] || all_triggers_by_id[node.data.module_data.id]
    var html = ''
    if (module.support_filters) {
        html += genGenericBlockFilter(node)
    }
    return html
}

function getFiltersFromNode(node) {
    return {
        'selector': node.data.saved_filters.selector ? node.data.saved_filters.selector : '',
        'value': node.data.saved_filters.value ? node.data.saved_filters.value : '',
        'operator': node.data.saved_filters.operator ? node.data.saved_filters.operator : '',
        'path': node.data.saved_filters.path ? node.data.saved_filters.path : '',
    }
}

function genGenericBlockFilter(node) {
    var operatorOptions = [
        {value: 'in', text: 'In'},
        {value: 'not_in', text: 'Not in'},
        {value: 'equals', text: 'Equals'},
        {value: 'not_equals', text: 'Not equals'},
    ]
    var filters = getFiltersFromNode(node)
    var $div = $('<div></div>').append($('<form></form>').append(
        genGenericInput({ id: 'filtering-selector', id: 'element_selector', label: 'Element selector', type: 'text', placeholder: 'Event._AttributeFlattened.{n}', required: false, value: filters.selector}),
        genGenericInput({ id: 'filtering-value', id: 'value', label: 'Value', type: 'text', placeholder: 'tlp:white', required: false, value: filters.value}),
        genGenericSelect({ id: 'filtering-operator', id: 'operator', label: 'Operator', options: operatorOptions, value: filters.operator}),
        genGenericInput({ id: 'filtering-path', id: 'hash_path', label: 'Hash Path', type: 'text', placeholder: 'Tag.{n}.name', required: false, value: filters.path}),
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

function highlightPathWarning(pathWarningData) {
    if (pathWarningData.has_path_warnings) {
        pathWarningData.edges.forEach(function (edge) {
            getPathForEdge(edge[0], edge[1])
                .addClass('connection-warning')
                .empty()
                .append($(document.createElementNS('http://www.w3.org/2000/svg', 'title')).text(edge[2]))
        })
    }
}

function highlightGraphIssues(graphProperties) {
    $drawflow.find('svg.connection > path.main-path')
        .removeClass(['connection-danger', 'connection-warning'])
        .empty()
    highlightAcyclic(graphProperties.is_acyclic)
    highlightMultipleOutputConnection(graphProperties.multiple_output_connection)
    highlightPathWarning(graphProperties.path_warnings)
}

function setHashpathOnInput(clicked, associatedParamId, isValue) {
    var path = $(clicked).data('hashpath')
    if (isValue === true) {
        var key = $(clicked).data('hashpath-key')
        var value = $(clicked).data('hashpath-value')
        path += getPathFiltering(key, value)
    }
    $('#selected-hashpath-input').val(path)
    setValueOnAssociatedInput(associatedParamId, path)
}

function setValueOnAssociatedInput(associatedParamId, value) {
    var $associatedInput = $drawflow.find('input[data-paramid="' + associatedParamId + '"]')
    $associatedInput.val(value)
    $associatedInput.trigger('input')
}

function getPathFiltering(key, value) {
    var stringToFormat = $('#selected-hashpath-operator').val()
    var filter = stringToFormat
        .replace('{$key}', key)
        .replace('{$value}', value)
    return filter
}

function generateCoreFormatUI(event, associatedParamId) {
    var indent_size = 'calc(1.25em)'
    var color_key = '#005cd5'
    var color_index = '#727272'
    var color_string = '#cf5900'
    var color_null = '#747474'
    var color_bool = '#004bad'
    var color_brace = '#727272'
    var color_column = '#727272'
    var color_collapse = '#727272'
    var defaultCollapseList = ['Org', 'Orgc']

    function generate(item, depth, path, forceObjectCollaspe) {
        if (Array.isArray(item)) {
            var $container = $('<span>').append(
                depth == 1 ? '' : braceOpen(true),
                depth == 1 ? '' : childrenCount(item),
                genArray(item, depth, path),
                depth == 1 ? '' : braceClose(true),
            )
            if (depth > 2) {
                $container.children("div").toggleClass("hidden")
            }
        } else if (typeof item === 'object' && item !== null) {
            var $container = $('<span>').append(
                depth == 1 ? '' : braceOpen(),
                depth == 1 ? '' : childrenCount(item),
                genObject(item, depth, path),
                depth == 1 ? '' : braceClose(),
            )
            if (forceObjectCollaspe === true) {
                $container.children("div").toggleClass("hidden")
            }
        } else {
            var $container = genValue(item, path)
        }
        return $container
    }

    function genArray(arr, depth, path) {
        var $container = $('<div>')
        arr.forEach(function (v, i) {
            var nextPath = path + '.{n}'
            var $index = genIndex(i, nextPath)
            var $value = generate(v, depth + 1, nextPath)
            var $div = $('<div>')
            $div.append($index, column(), $value)
            $container.append($div)
        })
        setDepth($container, depth, path)
        return $container
    }

    function genObject(obj, depth, path) {
        var $container = $('<div>')
        Object.keys(obj).forEach(function (k) {
            var nextPath = path + '.' + k
            var v = obj[k]
            var forceCollaspe = defaultCollapseList.includes(k)
            var $key = genKey(k, nextPath)
            var $value = generate(v, depth+1, nextPath, forceCollaspe)
            var $div = $('<div>')
            var $collase = ''
            if (isIterable(v)) {
                $collase = collapseIcon()
                if (depth > 1 && (Array.isArray(v) || forceCollaspe)) {
                    $collase.addClass('fa-rotate-270')
                }
            }
            $div.append($collase, $key, column(), $value)
            $container.append($div)
        })
        setDepth($container, depth)
        return $container
    }

    function genValue(val, path) {
        var exploded_path = path.split('.')
        var path_without_last_key = exploded_path.slice(0, -1).join('.')
        var key = exploded_path.pop()
        var path_filtered_by_value = path_without_last_key
        var $value
        if (val === null) {
            $value = $('<span>').text('null').css({'color': color_null })
        } else if (typeof val === 'boolean') {
            $value = $('<span>').text(val).css({'color': color_bool })
        } else {
            $value = $('<span>').text(val).css({'color': color_string })
        }
        $value
            .addClass('selectable-value')
            .attr('data-hashpath-key', key)
            .attr('data-hashpath-value', val)
            .attr('data-hashpath', path_filtered_by_value.slice(1))
            .attr('onclick', 'setHashpathOnInput(this, "' + associatedParamId + '", true)')
        return $value
    }

    function genKey(key, path) {
        return $('<span>')
            .text(key)
            .css({ 'color': color_key })
            .addClass('selectable-key')
            .attr('data-hashpath', path.slice(1))
            .attr('onclick', 'setHashpathOnInput(this, "' + associatedParamId + '")')
    }

    function genIndex(i, path) {
        return $('<span>')
            .text(i)
            .addClass('selectable-key')
            .css({ 'color': color_index })
            .attr('data-hashpath', path.slice(1))
            .attr('onclick', 'setHashpathOnInput(this, "' + associatedParamId + '")')
    }

    function header() {
        return $('<div>').append(braceOpen())
    }

    function footer() {
        return $('<div>').append(braceClose())
    }

    function collapseIcon() {
        return $('<i>')
            .addClass(['fas fa-caret-down', 'collaspe-button'])
            .css({ 'color': color_collapse, 'margin-right': '0.25rem', 'font-size': '1.25em' })
            .attr('onclick', '$(this).toggleClass("fa-rotate-270").parent().children().last().children("div").toggleClass("hidden")')
    }
    function childrenCount(iterable) {
        var count = getChildrenCount(iterable)
        var $span = $('<span>').text(count).addClass('children-counter')
        if (count === 0) {
            $span.css('background-color', '#a3a3a3')
        }
        return $span
    }

    function braceOpen(isArray) {
        return $('<span>').text(isArray ? '[' : '{').css({ 'color': color_brace, margin: '0 0.25em' })
    }
    function braceClose(isArray) {
        return $('<span>').text(isArray ? ']' : '}').css({ 'color': color_brace, margin: '0 0.25em' })
    }
    function column() {
        return $('<span>').text(':').css({ 'color': color_column, margin: '0 0.25em' })
    }

    function setDepth($obj) {
        $obj.css('margin-left', 'calc( ' + indent_size + ' )')
    }

    function isIterable(obj) {
        return typeof obj === 'object' && obj !== null
    }
    function getChildrenCount(iterable) {
        var count = 0
        if (Array.isArray(iterable)) {
            count = iterable.length
        } else if (typeof iterable === 'object') {
            count = Object.keys(iterable).length
        }
        return count
    }

    var $mainContainer = $('<div id="core-format-picker">')
    $mainContainer.append(header(), generate(event, 1, ''), footer())
    return $mainContainer
}