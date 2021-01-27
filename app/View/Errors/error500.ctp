<div class="misp-error-container">
<h2><?php echo $message; ?></h2>
<p class="error">
    <strong><?php echo __d('cake', 'Error'); ?>: </strong>
    <?php echo __d('cake', 'An Internal Error Has Occurred. Please try your action again. If the problem persists, please contact administrator.'); ?>
</p>
<?php
if (Configure::read('debug') > 0 ):
    echo $this->element('exception_stack_trace'); 
endif;
?>
</div>
