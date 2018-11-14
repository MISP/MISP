<?php
if (!$isSiteAdmin) exit();
?>

<div class="index">
    <h2><?php echo __('Advanced Manual Update'); ?></h2>
    
    <div style="margin-bottom: 10px;">
        <a class="btn btn-inverse" href="<?php echo $baseurl; ?>/servers/updateProgress/"><?php echo __('Show Update Progress Page'); ?></a>
    </div>

    <?php foreach($advancedUpdates as $i => $update): ?>
        <div class="headerUpdateBlock">
            <h4><?php echo ($i+1) . '. ' . h($update['title']); ?></h4>
        </div>
        <div class="bodyUpdateBlock">
            <h5><?php echo h($update['description']); ?></h5>

            <?php if (!$update['done']): ?>
                <?php if ($update['recommendBackup']): ?>
                <div class="alert alert-block">
                    <i class="icon-warning-sign"></i> <?php echo __('Running this script may take a very long time depending of the size of your database. It is adviced that you <b>back your database up</b> before running it.'); ?>
                </div>
                <?php endif; ?>

                <?php if ($update['liveOff']): ?>
                <div class="alert alert-info">
                    <i class="icon-question-sign"></i> <?php echo __('Running this script will make this instance unusable during the time of upgrade.'); ?>
                </div>
                <?php endif; ?>

                <?php
                    $url_param = $update['liveOff'] ? '1' : '';
                    $url_param .= $update['exitOnError'] ? '/1' : '';
                    echo $this->Form->create(false, array( 'url' => $baseurl . $update['url'] . $url_param ));
                    echo $this->Form->submit(__('Update: ') . $update['title'], array('class' => 'btn btn-warning'));
                    echo $this->Form->end();
                ?>
            <?php else: ?>
                <div class="alert alert-success">
                    <i class="fa fa-check-square"></i> <?php echo __('This update has been done.'); ?>
                </div>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>
