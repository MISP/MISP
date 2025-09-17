<div class="misp-error-container">
<h2><?php echo $message; ?></h2>
<p class="error">
    <strong><?php echo __d('cake', 'Error'); ?>: </strong>
    <?php echo __d('cake', 'An Internal Error Has Occurred. please try your action again. If the problem persists, contact your administrator. For administrators, refer to the error.log (normally found at MISP/app/tmp/logs/error.log)'); ?>
</p>
<?php
if (Configure::read('debug') > 0 ):
    echo $this->element('exception_stack_trace'); 
endif;
?>
</div>
