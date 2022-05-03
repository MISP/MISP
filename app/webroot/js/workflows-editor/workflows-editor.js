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

function sanitizeObject(obj) {
    var newObj = {}
    for (var key of Object.keys(obj)) {
        var newVal = $('</p>').text(obj[key]).html()
        newObj[key] = newVal
    }
    return newObj
}


function initDrawflow() {
    editor = new Drawflow($drawflow[0]);
    editor.start();

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
                // addNode($(this).data('block'), ui.position)
            }
        });
    })

    $canvas.droppable({
        drop: function (event, ui) {
            // console.log(event)
            // console.log(ui)
            addNode(ui.draggable.data('block'), ui.position)
        }
    });

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


function addNode(block, position) {
    var canvasPosition = $canvas[0].getBoundingClientRect()
    var adjsutedPosition = {
        left: position.left - canvasPosition.left,
        top: position.top,
    }
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