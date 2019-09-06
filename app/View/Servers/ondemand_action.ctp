<?php
if (!$isSiteAdmin) exit();
$disabledBtnText = $updateLocked ? 'title="' . __('An action is already in progress...') . '" disabled' : 'title=' . __('Action');
?>

<div class="index">
    <h2><?php echo __('Administrator On-demand Action'); ?></h2>

    <?php if ($updateLocked): ?>
        <div class='alert alert-danger'>
            <?php echo __('An action is already in progress. Starting new actions is not possible until completion of the current action process.'); ?>
        </div>
    <?php endif; ?>

    <div style="margin-bottom: 10px;">
        <a id="btnShowProgress" class="btn btn-inverse" href="<?php echo $baseurl; ?>/servers/updateProgress/"><?php echo __('Show Update Progress Page'); ?></a>
    </div>

    <?php $i = 0; ?>
    <?php foreach($actions as $id => $action): ?>
        <div class="headerUpdateBlock">
            <h4><?php echo ($i+1) . '. ' . h($action['title']); ?></h4>
        </div>
        <div class="bodyUpdateBlock">
            <h5><?php echo h($action['description']); ?></h5>

            <?php if (!$action['done']): ?>

                <?php if ($action['requirements'] !== ''): ?>
                <div class="alert alert-warning">
                    <i class="icon-warning-sign"></i> <?php echo h($action['requirements']); ?>
                </div>
                <?php endif; ?>

                <?php if ($action['recommendBackup']): ?>
                <div class="alert alert-block">
                    <i class="icon-warning-sign"></i> <?php echo __('Running this script may take a very long time depending of the size of your database. It is adviced that you <b>back your database up</b> before running it.'); ?>
                </div>
                <?php endif; ?>

                <?php if ($action['liveOff']): ?>
                <div class="alert alert-info">
                    <i class="icon-question-sign"></i> <?php echo __('Running this script will make this instance unusable for all users (not site-admin) during the time of upgrade.'); ?>
                </div>
                <?php endif; ?>

                <?php
                    $url_param = $action['liveOff'] ? '1' : '';
                    $url_param .= $action['exitOnError'] ? '/1' : '';
                    echo $this->Form->create(false, array( 'url' => $baseurl . $action['url'] . $url_param ));
                ?>

                    <button class="btn btn-warning <?php echo isset($action['redirectToUpdateProgress']) && $action['redirectToUpdateProgress'] ? 'submitButton' : 'submitButtonToUpdateProgress'; ?>" <?php echo $disabledBtnText; ?> role="button" tabindex="0" aria-label="<?php echo __('Submit'); ?>"><?php echo __('Action: ') . h($action['title']); ?></button>

                <?php
                    echo $this->Form->end();
                ?>
            <?php else: ?>
                <div class="alert alert-success">
                    <i class="fa fa-check-square"></i> <?php echo __('This action has been done and cannot be run again.'); ?>
                </div>
            <?php endif; ?>
        </div>
        <?php $i++; ?>
    <?php endforeach; ?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>
