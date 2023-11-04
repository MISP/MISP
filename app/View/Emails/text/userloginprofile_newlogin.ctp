Hello,

Your account on MISP <?= $misp_org; ?> was just signed into from a new device or location.

- Operating System: <?= $userLoginProfile['ua_platform']; ?>

- Browser: <?= $userLoginProfile['ua_browser']; ?>

- Location: <?= $userLoginProfile['geoip']; ?>

- IP: <?= $userLoginProfile['ip']; ?>


Follow this link to confirm if was you: <?php echo $baseurl . '/users/view_auth_history/'; ?>

I you don't recognize this activity, please follow this link and reset your password: <?php echo $baseurl . '/users/change_pw'; ?>
