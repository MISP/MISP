Hello,

A suspicious login happened with your account on MISP <?= $misp_org; ?>.

We believe it is suspicious because: <?= $suspiciousness_reason; ?>


The following information relates to the login:
- When: <?= $date_time; ?>

- Account used: <?= $username; ?>

- Operating System: <?= $userLoginProfile['ua_platform']; ?>

- Browser: <?= $userLoginProfile['ua_browser']; ?>

- Location: <?= $userLoginProfile['geoip']; ?>

- IP: <?= $userLoginProfile['ip']; ?>


Follow this link to confirm if was you: <?php echo $baseurl . '/users/view_login_history/'; ?>

I you don't recognize this activity, please markt the login as suspicious and IMMEDIATELY to reset your password. 

