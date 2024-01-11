<?php echo $this->Flash->render(); ?>
<?php
$detailsHtml = __("To enable TOTP for your account, scan the following QR code with your TOTP application (for example Google authenticator or KeepassXC) and validate the token.");;
$secretHtml = __("Alternatively you can enter the following secret in your TOTP application. This can be particularly handy in case you don't have a supported application in your working environment. Once the verification is done you'll also get 50 \"paper-based\" login tokens so you don't have to use a TOTP application each time: ") . "<pre>" . $secret . "</pre>";

echo $this->element('/genericElements/Form/genericForm', array(
  "form" => $this->Form,
  "data" => array(
    "title" => __("Validate your One Time Password"),
    "fields" => array(
      array(
        "type" => 'html',
        "field" => "html",
        "html" => $detailsHtml
      ),
      array(
        "type" => 'html',
        "field" => 'qrcode',
        "html" => $qrcode
      ),
      array(
        "type" => 'html',
        "field" => "secret",
        "html" => $secretHtml
      ),
      array(
        "field" => "otp",
        "label" => __("One Time Password verification"),
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
