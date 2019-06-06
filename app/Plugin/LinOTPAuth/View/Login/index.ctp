<div class="flash">
    <?php echo $this->Session->flash('auth'); ?>
</div>

<?php echo $this->Form->create('LinOTPUserPassword'); ?>

<div style="width: 460px; margin: 0 auto 20px;">

    <?php if (Configure::read('MISP.welcome_text_top')) : ?>
        <div class="welcome_text_top" style="font-size:18px; padding-bottom: 15px">
            <?php echo h(Configure::read('MISP.welcome_text_top')); ?>
        </div>
    <?php endif; ?>

    <div class="main_logo">
        <?php if (Configure::read('MISP.main_logo') && file_exists(APP . '/webroot/img/custom/' . Configure::read('MISP.main_logo'))) : ?>
            <img src="<?php echo $baseurl ?>/img/custom/<?php echo h(Configure::read('MISP.main_logo')); ?>" style="width:100%" />
        <?php else : ?>
            <img src="/img/misp-logo.png" style="width:100%" />
        <?php endif; ?>
    </div>

    <?php if (Configure::read('MISP.welcome_text_bottom')) : ?>
        <div class="welcome_text_bottom" style="text-align:right; font-size:18px; padding-top: 15px">
            <?php echo h(Configure::read('MISP.welcome_text_bottom')); ?>
        </div>
    <?php endif; ?>

    <legend style="width:450px;"><?php echo __('Login'); ?></legend>

    <?php
    echo $this->Form->input('email', array('autocomplete' => 'off', 'autofocus'));
    echo $this->Form->input('password', array('autocomplete' => 'off'));
    ?>

    <div class="clear"></div>

    <?php
        if ($linotpBaseUrl != null):
    ?>
            <p>Go to <a href="<?php echo $linotpBaseUrl; ?>/selfservice-v2/">LinOTP Selfservice</a> to manage your second factor access tokens.</p>
    <?php
        endif;
    ?>

    <?php echo $this->Form->button(__('Login'), array('class' => 'btn btn-primary')); ?>

</div>

<?php echo $this->Form->end(); ?>