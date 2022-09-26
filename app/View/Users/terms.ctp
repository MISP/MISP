<div class="users form">
<h2><?php echo __('MISP Terms and Conditions');?></h2>
    <?php if ($termsDownload): ?>
    <a href="<?= $baseurl ?>/users/downloadTerms" class="btn btn-inverse"><?= __('Download Terms and Conditions');?></a>
    <?php elseif (!$termsContent): ?>
    <p><?= __("Terms and Conditions file not found.") ?></p>
    <?php else: ?>
    <?= $termsContent ?>
    <?php endif; ?>
    <?php
    if (!$termsaccepted) {
        echo "<br><br>";
        echo $this->Form->create('User');
        echo $this->Form->hidden('termsaccepted', array('default' => '1'));
        echo $this->Form->submit(__('Accept Terms'), array('class' => 'btn btn-primary'));
        echo $this->Form->end();
    }
    ?>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'terms'));

