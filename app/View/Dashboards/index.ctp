<?php
// Include addation CSS and scripts to layout
$this->viewVars["additionalCss"] = ["gridstack.min"];
$this->viewVars["additionalJs"] = ["gridstack.all"];
?>
<div class="index">
    <div class="grid-stack">
        <?php
            foreach ($widgets as $k => $widget) {
                echo $this->element('/dashboard/widget', array('widget' => $widget, 'k' => $k));
            }
        ?>
    </div>
    <div class="hidden" id="last-element-counter" data-element-counter="<?= h($k) ?>"></div>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'dashboard', 'menuItem' => 'dashboardIndex')); ?>
<script>
var grid = false;
$(function () {
    grid = GridStack.init({verticalMargin: 2});
    resetDashboardGrid(grid, false);
    grid.on('change', function(event, items) {
        saveDashboardState();
    });
    grid.on('added', function(event, items) {
        resetDashboardGrid(grid, false);
    });
    grid.on('gsresizestop', function(event, element) {
        $(element).find('.widgetContentInner').trigger('widget-resized')
    });
});
</script>
