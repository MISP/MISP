<?php echo $this->Flash->render(); ?>

<div class="actions sideMenu">
  <div style="padding: 10px;">
    <p><?php echo __("Your account requires an TOTP token to login. (Time-Based One-Time Password)");?></p>
  </div>
</div>

<?php
echo $this->element('/genericElements/Form/genericForm', array(
  "form" => $this->Form,
  "data" => array(
    "title" => __("Validate your One Time Password"),
    "fields" => array(
      array(
        "field" => "otp",
        "label" => __("One Time Password"),
        "type" => "text",
        "placeholder" => __("Enter your OTP here"),
      ),
    ),
    "submit" => array (
      "action" => "totp",
    ),
)));
?>
