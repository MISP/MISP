<div class="misp-error-container">
<?php
if ($message !== 'The request has been black-holed'):
    ?>
    <h2><?php echo $message; ?></h2>
    <p class="error">
        <strong><?php echo __d('cake', 'Error'); ?>: </strong>
        <?php printf(
            __d('cake', 'The requested address %s was not found on this server.'),
            "<strong>'$url'</strong>"
        ); ?>
    </p>
    <?php
    if (Configure::read('debug') > 0):
        echo $this->element('exception_stack_trace');
    endif;
else:
?>
    <h2><?php echo __('You have tripped the cross-site request forgery protection of MISP');?></h2>
    <p class="error">
        <strong><?php echo __('CSRF error');?>:</strong>
        <?php echo __('This happens usually when you try to resubmit the same form with invalidated CSRF tokens or you had a form open too long and the CSRF tokens simply expired. Just go back to the previous page and refresh the form (by reloading the same url) so that the tokens get refreshed.');?>
    </p>
    <p>
        <?php echo __('Alternatively, click <a href="%s">here</a> to continue to the start page.', $baseurl);?>
    </p>
    <?php
    if (Configure::read('debug') > 0):
        echo $this->element('exception_stack_trace');
    endif;
endif;
?>
</div>
