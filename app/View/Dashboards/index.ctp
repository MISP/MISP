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

var grid = false;
$(document).ready(function () {
    grid = GridStack.init({verticalMargin: 2});
    resetDashboardGrid(grid);
    grid.on('change', function(event, items) {
        saveDashboardState();
    });
    grid.on('added', function(event, items) {
        resetDashboardGrid(grid);
    });
    grid.on('gsresizestop', function(event, element) {
        $(element).find('.widgetContentInner').trigger('widget-resized')
    });
});
</script>
