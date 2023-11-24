Hello,

Your account on MISP <?= $misp_org; ?> was just signed into from a new device or location.

- When: <?= $date_time; ?>

- Operating System: <?= $userLoginProfile['ua_platform']; ?>

- Browser: <?= $userLoginProfile['ua_browser']; ?>

- Location: <?= $userLoginProfile['geoip']; ?>

- IP: <?= $userLoginProfile['ip']; ?>


Follow this link to confirm if was you: <?php echo $baseurl . '/users/view_login_history/'; ?>

I you don't recognize this activity, please markt the login as suspicious and IMMEDIATELY to reset your password. 

