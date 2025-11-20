Hello,

Your account on <?= $misp_org; ?> MISP was just accessed from a new device or location.

- When: <?= $date_time; ?>

- Operating System: <?= $userLoginProfile['ua_platform']; ?>

- Browser: <?= $userLoginProfile['ua_browser']; ?>

- Location: <?= $userLoginProfile['geoip']; ?>

- IP: <?= $userLoginProfile['ip']; ?>


Follow this link to confirm it was you or report as malicious: <?php echo $baseurl . '/users/view_login_history/'; ?>

If you don't recognize this activity, please mark the login as malicious and IMMEDIATELY reset your password. 

