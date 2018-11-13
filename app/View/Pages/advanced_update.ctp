<?php
if (!$isSiteAdmin) exit();
?>
<div class="actions">
    <ol class="nav nav-list">

    </ol>
</div>
<div class="index">
    <h2><?php echo __('Advanced Manual Update');?></h2>
    <div class="advancedUpdateBlock">
        <h4>First seen/Last seen Attribute table</h4>
        <?php echo __('Update the Attribute table to support first_seen and last_seen feature, with a microsecond resolution.');?>
        <div class="alert alert-block">
            <i class="icon-warning-sign"></i> <?php echo('Running this script may take a very long depending of the size of your database. It is adviced that you back your database up before running it.')?>
        </div>
        <div class="alert alert-info">
            <i class="icon-question-sign"></i> <?php echo('Running this script will make this instance unusable during the time of upgrade.')?>
        </div>
        <?php
            echo $this->Form->create(false, array( 'url' => $baseurl . '/servers/updateDatabase/seenOnAttribute/1' ));
            echo $this->Form->submit(__('Update first/last_seen Attribute table'), array('class' => 'btn btn-warning'));
            echo $this->Form->end();
        ?>
    </div>

</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>
