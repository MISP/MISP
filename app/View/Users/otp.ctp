<?php echo $this->Flash->render(); ?>

<div class="actions sideMenu">
  <div style="padding: 10px;">
    <p><?php echo __("Your account requires an OTP token to login. (One-Time Password)");?></p>
  </div>
</div>

<?php
$label = __("Enter either your TOTP or paper based Single Use Token number ") . $hotp_counter;

echo $this->element('/genericElements/Form/genericForm', array(
  "form" => $this->Form,
  "data" => array(
    "title" => __("Validate your One Time Password"),
    "fields" => array(
      array(
        "field" => "otp",
        "label" => $label,
        "type" => "text",
        "placeholder" => __("Enter your OTP here"),
        "autofocus" => 1
      )
    ),
    "submit" => array (
      "action" => "otp",
    ),
)));
?>
