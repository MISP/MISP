Dear Organisational MISP admin,

A suspicious login happened with an account in your organisation on MISP <?= $misp_org; ?>.

We believe it is suspicious because: <?= $suspiciousness_reason; ?>


The following information relates to the login:
- When: <?= $date_time; ?>

- Account used: <?= $username; ?>

- Operating System: <?= $userLoginProfile['ua_platform']; ?>

- Browser: <?= $userLoginProfile['ua_browser']; ?>

- Location: <?= $userLoginProfile['geoip']; ?>

- IP: <?= $userLoginProfile['ip']; ?>


The affected user was informed and asked to validate the connection. 
You will be informed in an additional email if the user confirms it as malicious.

