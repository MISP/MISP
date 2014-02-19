<?php
// $type is passed from the controller and can be:
// alert-success, alert-warning, alert-info, alert-error
// see: Session::setFlash() & bootstrap docs
// http://api.cakephp.org/2.4/class-SessionComponent.html#_setFlash
// http://getbootstrap.com/2.3.2/components.html#alerts
?>
<div class="alert <?php echo $type;?>">
    <button type="button" class="close" data-dismiss="alert">&times;</button>
    <strong><?php echo $message;?></strong>
</div>