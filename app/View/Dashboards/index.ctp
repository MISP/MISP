<?php
// Tell layout to include GridStack assets
$this->viewVars["additionalCss"] = ["gridstack.min"];
$this->viewVars["additionalJs"]  = ["gridstack.all"];
?>
<div class="index">
    <div class="grid-stack">
        <?php
        foreach ($widgets as $k => $widget) {
            echo $this->element('/dashboard/widget', ['widget' => $widget, 'k' => $k]);
        }
        ?>
    </div>
    <div class="hidden" id="last-element-counter" data-element-counter="<?= h($k) ?>"></div>
</div>

<?= $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'dashboard', 'menuItem' => 'dashboardIndex']); ?>

<script>
var grid = null;

/**
 * Turn server-rendered .widget-wrapper children into real GridStack items.
 */
function hydrateInitialWidgets() {
    document.querySelectorAll('.grid-stack > .widget-wrapper').forEach(function (el) {
        var w = parseInt(el.getAttribute('gs-w') || '2', 10);
        var h = parseInt(el.getAttribute('gs-h') || '2', 10);
        var x = parseInt(el.getAttribute('gs-x') || '0', 10);
        var y = parseInt(el.getAttribute('gs-y') || '0', 10);

        var widgetType = el.getAttribute('widget') || '';
        var config     = el.getAttribute('config') || '[]';

        // detach original node from DOM
        el.parentNode.removeChild(el);

        // create empty grid item
        var item = grid.addWidget({x: x, y: y, w: w, h: h});

        // inject widget-wrapper into grid-stack-item-content
        var container = item.querySelector('.grid-stack-item-content');
        container.appendChild(el);

        // propagate metadata to the grid item
        item.setAttribute('widget', widgetType);
        item.setAttribute('config', config);
    });
}

/**
 * Ajax-render widget contents (used on load and after config changes).
 * `el` can be any descendant; we normalize to the grid item.
 */
function updateDashboardWidget(el) {
    var $root = $(el).closest('.grid-stack-item');
    if (!$root.length) return;

    var config     = $root.attr('config') || '[]';
    var widgetName = $root.attr('widget');

    var $wrapper   = $root.find('.widget-wrapper').first();
    var $titleText = $root.find('.widgetTitleText').first();
    var $inner     = $root.find('.widgetContent').first();

    var cfgObj = {};
    try { cfgObj = JSON.parse(config); } catch (e) {}

    if (cfgObj.alias) {
        $titleText.text(cfgObj.alias);
    }

    var widgetId = $wrapper.attr('id').replace('widget_', '');

    $.ajax({
        type: 'POST',
        url: baseurl + '/dashboards/renderWidget/' + widgetId,
        data: {
            config: config,
            widget: widgetName
        },
        success: function (data) {
            $inner.html(data);
            $wrapper.removeAttr('config');
        }
    });
}

/**
 * Called from the modal when adding a new widget.
 * Uses /dashboards/getEmptyWidget/<widget>/<k+1> which returns the widget element above.
 */
function submitDashboardAddWidget() {
    var widget     = $('#DashboardWidget').val();
    var rawConfig  = $('#DashboardConfig').val() || '[]';
    var width      = parseInt($('#DashboardWidth').val(), 10);
    var height     = parseInt($('#DashboardHeight').val(), 10);
    var k          = $('#last-element-counter').data('element-counter') || 0;

    try {
        rawConfig = JSON.stringify(JSON.parse(rawConfig));
    } catch (error) {
        showMessage('fail', error.message);
        return;
    }

    $.ajax({
        url: baseurl + '/dashboards/getEmptyWidget/' + widget + '/' + (k + 1),
        type: 'GET',
        success: function (html) {
            var tmp = document.createElement('div');
            tmp.innerHTML = html.trim();

            var wrapper = tmp.querySelector('.widget-wrapper');
            if (!wrapper) {
                showMessage('fail', 'Returned widget HTML does not contain .widget-wrapper');
                return;
            }

            var item = grid.addWidget({
                w: width,
                h: height,
                autoPosition: true
            });

            var container = item.querySelector('.grid-stack-item-content');
            container.appendChild(wrapper);

            wrapper.removeAttribute('config');

            item.setAttribute('widget', widget);
            item.setAttribute('config', rawConfig);

            // load widget content
            updateDashboardWidget(item);

            // persist new layout
            saveDashboardState();
        },
        complete: function () {
            $('#genericModal').modal('hide');
        },
        error: function () {
            handleGenericAjaxResponse({
                saved: false,
                errors: ['Could not fetch empty widget.']
            });
        }
    });
}


/**
 * Initialize GridStack and wire everything together.
 */
$(function () {
    // 1) init grid once
    grid = GridStack.init({ margin: 10 }, '.grid-stack');

    // 2) hydrate pre-rendered widgets
    hydrateInitialWidgets();

    // 3) let your existing helper adjust options if needed
    if (typeof resetDashboardGrid === 'function') {
        resetDashboardGrid(grid, false);
    }

    // 4) save layout on change
    grid.on('change', function (event, items) {
        if (typeof saveDashboardState === 'function') {
            saveDashboardState();
        }
    });

    // 5) keep any helper state in sync on add
    grid.on('added', function (event, items) {
        if (typeof resetDashboardGrid === 'function') {
            resetDashboardGrid(grid, false);
        }
    });

    // 6) propagate resize events to widgets (old + new)
    grid.on('resizestop', function (event, el) {
        var $item = $(el);
        $item.find('.widgetContentInner').trigger('widget-resized');
        $item.find('.widgetContent').trigger('widget-resized');
    });

    // 7) initial content load for all widgets
    $('.grid-stack .grid-stack-item').each(function () {
        updateDashboardWidget(this);
    });
});
</script>
