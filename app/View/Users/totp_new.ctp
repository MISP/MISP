<?php echo $this->Flash->render(); ?>

<div class="actions sideMenu">
  <div style="padding: 10px;">
    <p><?php echo __("Generate a new TOTP token to login. (Time-Based One-Time Password)");?></p>
    <p><?php echo __("Please scan the following QR code with your TOTP application.");?></p>
  </div>
</div>

<div>
<?php
// FIXME chri - make it visually attractive
echo $qrcode;
?>
<p>Alternatively you can enter the following secret in your TOTP application: <pre><?php echo $secret; ?></pre>
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
        "placeholder" => __("Enter your OTP code here"),
      )
    ),
    "submit" => array (
      "action" => "totp",
    ),
)));
?>
</div>
