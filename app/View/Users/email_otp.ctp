<?php echo $this->Flash->render(); ?>

<div class="actions sideMenu">
  <div style="padding: 10px;">
    <p> <?php echo __("Your administrator has turned on an additional authentication step which
      requires you to enter a OTP (one time password) you have received via email.");?>
    </p>
    <p> <?php echo __("Make sure to check your SPAM folder.");?> </p>
    <a href='<?php echo $baseurl; ?>/users/email_otp'> <button class='btn'> <?php echo __("Resend"); ?> </button></a>
  </div>
</div>

<?php
echo $this->element('/genericElements/Form/genericForm', array(
  "form" => $this->Form,
  "data" => array(
    "title" => __("Validate your OTP"),
    "fields" => array(
      array(
        "field" => "otp",
        "label" => __("One Time Password"),
        "type" => "text",
        "placeholder" => __("Enter your OTP here"),
      ),
    ),
    "submit" => array (
      "action" => "EmailOtp",
    ),
)));
?>
