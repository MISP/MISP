<div class="index">
    <div class="grid-stack" data-gs-min-row:"10">
        <?php
            $layout = '';
            foreach ($widgets as $k => $widget) {
                $layout .= $this->element('/dashboard/widget', array('widget' => $widget, 'k' => $k));
            }
            echo $layout;
        ?>
    </div>
    <div class="hidden" id="last-element-counter" data-element-counter="<?= h($k) ?>"></div>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'dashboard', 'menuItem' => 'dashboardIndex'));
?>
<script type="text/javascript">

function resetDashboardGrid(grid) {
    $('.grid-stack-item').each(function() {
        updateDashboardWidget(this);
    });
    saveDashboardState();
    $('.edit-widget').click(function() {
        el = $(this).closest('.grid-stack-item');
        data = {
            id: el.attr('id'),
            config: JSON.parse(el.attr('config')),
            widget: el.attr('widget'),
            alias: el.attr('alias')
        }
        openGenericModalPost(baseurl + '/dashboards/getForm/edit', data);
    });
    $('.remove-widget').click(function() {
        el = $(this).closest('.grid-stack-item');
        grid.removeWidget(el);
        saveDashboardState();
    });
}

$(document).ready(function () {
    var grid = GridStack.init();
    resetDashboardGrid(grid);
    grid.on('change', function(event, items) {
        saveDashboardState();
    });
    grid.on('added', function(event, items) {
        resetDashboardGrid(grid);
    });
});
</script>
