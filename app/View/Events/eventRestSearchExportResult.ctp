<?php
    $showLinebreak = in_array($responseType, ['txt', 'xml']);
?>
<div class="index">
    <div id="restSearchExportResult" style="<?= $showLinebreak ? 'white-space: pre;' : '' ?>">
<?php
if (!empty($renderView)) {
    echo $this->render('/Events/module_views/' . $renderView, false);
}
?>
    </div>
</div>
<?php
    if (!$ajax) echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event_restsearch_export', 'menuItem' => 'result'));
