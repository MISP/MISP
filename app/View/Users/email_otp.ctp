<?php echo $this->Flash->render(); ?>

<div class="actions sideMenu">
  <div style="padding: 10px;">
    <p> Your administrator has turned on an additional authentication step which
      requires you to enter a OTP (one time password) you have received via email.
    </p>
    <p> Make sure to check your SPAM folder. </p>
    <a href='<?php echo $baseurl; ?>/users/email_otp'> <button class='btn'> Resend </button></a>
  </div>
</div>

<?php
echo $this->element('/genericElements/Form/genericForm', array(
  "form" => $this->Form,
  "data" => array(
    "title" => "Validate your OTP",
    "fields" => array(
      array(
        "field" => "otp",
        "label" => "One Time Password",
        "type" => "text",
        "placeholder" => __("Enter your OTP here"),
      ),
    ),
    "submit" => array (
      "action" => "EmailOtp",
    ),
)));
?>
