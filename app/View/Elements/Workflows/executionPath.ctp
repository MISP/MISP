<div class="root-container">
    <div class="main-container">
        <div class="canvas">
            <div id="drawflow" data-workflowid="<?= h($workflow['id']) ?>"></div>
        </div>
    </div>
</div>

<?php
echo $this->element('genericElements/assetLoader', [
    'css' => ['drawflow.min', 'drawflow-default'],
    'js' => ['drawflow.min', 'doT'],
]);
?>


<script>
    (function() {
        var $root_container = $('.root-container')
        var $canvas = $('.root-container .canvas')
        var $drawflow = $('#drawflow')
        var editor = false
        var workflow = false
        <?php if (!empty($workflow)) : ?>
            var workflow = <?= json_encode($workflow) ?>;
        <?php endif; ?>

        var dotBlock_default = doT.template(' \
<div class="canvas-workflow-block""> \
    <div style="width: 100%;"> \
        <div class="default-main-container"> \
            {{? it.icon }} \
                <i class="fa-fw fa-{{=it.icon}} {{=it.icon_class}}"></i> \
            {{?}} \
            {{? it.icon_path }} \
                <span><img src="/img/{{=it.icon_path}}" alt="Icon of {{=it.name}}" width="18" height="18" style="margin: auto 0; filter: grayscale(1);"></span> \
            {{?}} \
            <strong style="margin-left: 0.25em;"> \
                {{=it.name}} \
            </strong> \
            {{? it.is_misp_module }} \
                <sup class="is-misp-module"></sup> \
            {{?}} \
        </div> \
    </div> \
</div>')
        var dotBlock_trigger = dotBlock_default
        var dotBlock_if = dotBlock_default
        var allTemplates = {
            'dotBlock_default': dotBlock_default,
            'dotBlock_trigger': dotBlock_trigger,
            'dotBlock_if': dotBlock_if,
        }

        $(document).ready(function() {
            initDrawflowOverview()
        })

        function initDrawflowOverview() {
            editor = new Drawflow($drawflow[0]);
            editor.editor_mode = 'view'
            editor.draggable_inputs = false
            editor.zoom_min = 0.4
            editor.translate_to = function(x, y) {
                this.canvas_x = x;
                this.canvas_y = y;
                let storedZoom = this.zoom;
                this.zoom = 1;
                this.precanvas.style.transform = "translate(" + this.canvas_x + "px, " + this.canvas_y + "px) scale(" + this.zoom + ")";
                this.zoom = storedZoom;
                this.zoom_last_value = 1;
                this.zoom_refresh();
            }
            editor.start();
            loadWorkflow(workflow.data)
            fitCanvas()
        }

        function fitCanvas() {
            var editor_bcr = editor.container.getBoundingClientRect()
            var offset_x = editor_bcr.width / 2
            var offset_y = editor_bcr.height / 2
            var offset_block_y = 40 / 2 // 40 is the max-height of the block defined in --dfNodeMinHeight
            var offset_block_x = 160 / 5 // 160 is the max-width of the block defined in --dfNodeMinWidth;

            var sumX = 0,
                sumY = 0,
                maxX = 0,
                maxY = 0
            var nodes = Object.values(editor.drawflow.drawflow.Home.data)
            nodes.forEach(function(node) {
                sumX += node.pos_x
                sumY += node.pos_y
                maxX = node.pos_x > maxX ? node.pos_x : maxX
                maxY = node.pos_y > maxY ? node.pos_y : maxY
            });
            var centroidX = sumX / nodes.length
            var centroidY = sumY / nodes.length
            var calc_zoom = Math.min(Math.min(editor_bcr.width / maxX, editor_bcr.height / maxY), 1) // Zoom out if needed
            editor.translate_to(
                offset_x - centroidX + offset_block_x,
                offset_y - centroidY - offset_block_y
            )
            editor.zoom = calc_zoom
            editor.zoom_refresh()
        }

        function loadWorkflow(data) {
            Object.values(data).forEach(function(block) {
                var html = getTemplateForBlock(block.data, allTemplates)
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
            Object.values(data).forEach(function(block) {
                for (var input_name in block.inputs) {
                    block.inputs[input_name].connections.forEach(function(connection) {
                        editor.addConnection(connection.node, block.id, connection.input, input_name)
                    })
                }
            })
        }

        function getTemplateForBlock(block, allTemplates) {
            var html = ''
            block.icon_class = block.icon_class !== undefined ? block.icon_class : 'fas'
            if (block.html_template !== undefined) {
                if (allTemplates['dotBlock_' + block.html_template] !== undefined) {
                    html = allTemplates['dotBlock_' + block.html_template](block)
                } else {
                    html = 'Wrong HTML template'
                    console.error('Wrong HTML template for block', block)
                }
            } else {
                html = dotBlock_default(block)
            }
            return html
        }
    })()
</script>

<style>
    #drawflow {
        height: 400px;
        width: 100%;
        position: relative;
    }

    .canvas {
        border: 1px solid #ddd;
        border-radius: 5px;
    }

    .canvas-workflow-block {
        display: flex;
        background-color: #fff;
        border-radius: 5px;
        padding: 0.25em 0.75em;
        box-shadow: 0px 3px 6px 2px #33333333;
    }

    .canvas-workflow-block br {
        width: 100%;
        height: 1px;
        background-color: #e9e9e9;
    }

    .canvas-workflow-block>.icon {
        width: 1.25em;
        align-items: flex-start;
        display: flex;
        font-size: large;
        padding: 0 0.25em;
    }

    :root {
        --dfNodeHoverBoxShadowColor: #ffffff;
        --dfInputHeight: 5px;
        --dfInputWidth: 5px;
        --dfOutputHeight: 5px;
        --dfOutputWidth: 5px;

        --dfInputHeightHover: 5px;
        --dfInputWidthHover: 5px;
        --dfInputLeftHover: -7px;
        --dfOutputHeightHover: 5px;
        --dfOutputWidthHover: 5px;
        --dfOutputRightHover: 6px;

        --dfLineWidth: 3px;
    }

    .drawflow .drawflow-node .input,
    .drawflow .drawflow-node .output {
        cursor: default;
    }
</style>