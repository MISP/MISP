<div class="index">
    <div id="restSearchExportResult">
        <?php
        if (!empty($renderView)) {
            echo $this->render('/Events/module_views/' . $renderView, false);
        }
        ?>
    </div>
</div>
<?php
    if (!$ajax) echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event_restsearch_export', 'menuItem' => 'result'));
