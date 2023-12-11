<div class="misp-error-container">
    <?php
    if ($message !== 'The request has been black-holed'):
        ?>
        <h2><?= $message; ?></h2>
        <p class="error">
            <strong><?= __d('cake', 'Error'); ?>: </strong>
            <?php
            switch ($error->getCode()) {
                case 404:
                    echo __d('cake', 'The requested address %s was not found on this server.', "<strong>'$url'</strong>");
                    break;
                case 405:
                    echo __d('cake', 'You don\'t have permission to access %s.', "<strong>'$url'</strong>");
                    break;
            }
            ?>
        </p>
        <?php
        if (Configure::read('debug') > 0):
            echo $this->element('exception_stack_trace');
        endif;
    else:
        ?>
        <h2><?= __('You have tripped the cross-site request forgery protection of MISP');?></h2>
        <p class="error">
            <strong><?= __('CSRF error') ?>:</strong>
            <?= __('This happens usually when you try to resubmit the same form with invalidated CSRF tokens or you had a form open too long and the CSRF tokens simply expired. Just go back to the previous page and refresh the form (by reloading the same url) so that the tokens get refreshed.');?>
        </p>
        <p>
            <?= __('Alternatively, click <a href="%s">here</a> to continue to the start page.', $baseurl);?>
        </p>
        <?php
        if (Configure::read('debug') > 0):
            echo $this->element('exception_stack_trace');
        endif;
    endif;
    ?>
</div>
