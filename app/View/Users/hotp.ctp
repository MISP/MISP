<div class="users form">
<h2><?php echo __('Paper based Single Use Tokens');?></h2>
    <p><?php echo __('The following list contains the next tokens in case you do not have your phone/software. <br />Make sure you print these out.');?></p>
    <pre><?php 
    $count = count($hotp_codes);
    $rows = round($count / 5);  // 5 rows
    $i = 1;
    foreach ($hotp_codes as $key => $value) {
      if ($key < 10) print(" ");
      print("$key: $value");
      if ($i == 5) {
        print("\n");
        $i = 1;
      } else {
        print("    ");
        $i++;
      }

    }
    ?>
    </pre>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'view'));

