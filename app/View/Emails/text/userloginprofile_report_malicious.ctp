Dear Organisational MISP admin,

Please know that a user from your organisation reported a suspicious or malicious login with their account on MISP <?= $misp_org; ?>.

The following information relates to the login:
- When: <?= $date_time; ?>

- Account used: <?= $username; ?>

- Operating System: <?= $userLoginProfile['ua_platform']; ?>

- Browser: <?= $userLoginProfile['ua_browser']; ?>

- Location: <?= $userLoginProfile['geoip']; ?>

- IP: <?= $userLoginProfile['ip']; ?>


The affected user was forced to change their password.

