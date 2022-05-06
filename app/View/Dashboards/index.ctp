<div class="index">
    <div class="grid-stack" data-gs-min-row:"10">
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
        resetDashboardGrid(grid);
    });
    grid.on('gsresizestop', function(event, element) {
        $(element).find('.widgetContentInner').trigger('widget-resized')
    });
});
</script>
