<?php

include __DIR__ . '../../../../../../Config/config.php';

function printColored($text, $color = "default")
{
    $colors = [
        "default" => "\033[0m",
        "red" => "\033[31m",
        "green" => "\033[32m",
        "yellow" => "\033[33m",
        "blue" => "\033[34m",
        "magenta" => "\033[35m",
        "cyan" => "\033[36m",
        "white" => "\033[37m",
    ];
    echo $colors[$color] . $text . $colors["default"] . "\n";
}

printColored("################################################", "yellow");
printColored("##           LdapAuth test script             ##", "yellow");
printColored("################################################", "yellow");
printColored("LdapAuth Configuration:", "cyan");
$config['LdapAuth'] = [
    'ldapServer' => $config['LdapAuth']['ldapServer'],
    'ldapDn' => $config['LdapAuth']['ldapDn'],
    'ldapReaderUser' => $config['LdapAuth']['ldapReaderUser'],
    'ldapReaderPassword' => $config['LdapAuth']['ldapReaderPassword'],
    'ldapSearchFilter' => $config['LdapAuth']['ldapSearchFilter'] ?? '',
    'ldapSearchAttribute' => $config['LdapAuth']['ldapSearchAttribute'] ?? 'mail',
    'ldapEmailField' => $config['LdapAuth']['ldapEmailField'] ?? ['mail'],
    'ldapNetworkTimeout' => $config['LdapAuth']['ldapNetworkTimeout'] ?? -1,
    'ldapProtocol' => $config['LdapAuth']['ldapProtocol'] ?? 3,
    'ldapAllowReferrals' => $config['LdapAuth']['ldapAllowReferrals'] ?? true,
    'starttls' => $config['LdapAuth']['starttls'] ?? false,
    'mixedAuth' => $config['LdapAuth']['mixedAuth'] ?? true,
    'ldapDefaultOrgId' => $config['LdapAuth']['ldapDefaultOrgId'] ?? 1,
    'ldapDefaultRoleId' => $config['LdapAuth']['ldapDefaultRoleId'] ?? 3,
    'updateUser' => $config['LdapAuth']['updateUser'] ?? true,
    'debug' => $config['LdapAuth']['debug'] ?? false,
    'ldapTlsRequireCert' => $config['LdapAuth']['ldapTlsRequireCert'] ?? LDAP_OPT_X_TLS_DEMAND,
    'ldapTlsCustomCaCert' => $config['LdapAuth']['ldapTlsCustomCaCert'] ?? false,
    'ldapTlsCrlCheck' => $config['LdapAuth']['ldapTlsCrlCheck'] ?? LDAP_OPT_X_TLS_CRL_PEER,
    'ldapTlsProtocolMin' => $config['LdapAuth']['ldapTlsProtocolMin'] ?? LDAP_OPT_X_TLS_PROTOCOL_TLS1_2,
];
printColored(print_r($config['LdapAuth'], true), "green");

printColored("\nLdapAuth Connection:", "cyan");

ldap_set_option(null, LDAP_OPT_DEBUG_LEVEL, 7);
ldap_set_option(null, LDAP_OPT_NETWORK_TIMEOUT, $config['LdapAuth']['ldapNetworkTimeout']);

if ($config['LdapAuth']['ldapTlsCustomCaCert']) {
    ldap_set_option(null, LDAP_OPT_X_TLS_CACERTDIR, dirname($config['LdapAuth']['ldapTlsCustomCaCert']));
    ldap_set_option(null, LDAP_OPT_X_TLS_CACERTFILE, $config['LdapAuth']['ldapTlsCustomCaCert']);
}

ldap_set_option(null, LDAP_OPT_X_TLS_REQUIRE_CERT, $config['LdapAuth']['ldapTlsRequireCert']);
ldap_set_option(null, LDAP_OPT_X_TLS_CRLCHECK, $config['LdapAuth']['ldapTlsCrlCheck']);
ldap_set_option(null, LDAP_OPT_X_TLS_PROTOCOL_MIN, $config['LdapAuth']['ldapTlsProtocolMin']);

$ldapconn = ldap_connect($config['LdapAuth']['ldapServer']);
if (!$ldapconn) {
    printColored("[Error] LDAP server connection failed.", "red");
    printColored("[*] Check the LdapAuth.ldapServer setting is correct.", "yellow");
    exit(1);
}

ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, $config['LdapAuth']['ldapProtocol']);
ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, $config['LdapAuth']['ldapAllowReferrals']);

if ($config['LdapAuth']['starttls']) {
    if (!ldap_start_tls($ldapconn)) {
        printColored("[Error] Failed to start TLS.", "red");
        exit(1);
    }
}

$ldapbind = ldap_bind($ldapconn, $config['LdapAuth']['ldapReaderUser'],  $config['LdapAuth']['ldapReaderPassword']);
if (!$ldapbind) {
    printColored("[Error] Invalid LDAP reader user credentials: " . ldap_error($ldapconn), "red");
    exit(1);
}
printColored("[Info] LDAP bind with reader user successful.", "green");

$email = readline("Enter the email to search in the LDAP server: ");
$filter = '(' . $config['LdapAuth']['ldapSearchAttribute'] . '=' . $email . ')';
if (!empty($config['LdapAuth']['ldapSearchFilter'])) {
    $filter =  '(&' . $config['LdapAuth']['ldapSearchFilter'] . $filter . ')';
}

printColored("LDAP search filter: $filter", "cyan");

$ldapUser = ldap_search($ldapconn, $config['LdapAuth']['ldapDn'], $filter, $config['LdapAuth']['ldapEmailField']);
if (!$ldapUser) {
    $error = ldap_error($ldapconn);
    printColored("[Error] LDAP user search failed: " . $error, "red");

    if ($error == "Can't contact LDAP server") {
        printColored("[*] Check the `LdapAuth.ldapServer` setting is correct.", "yellow");
        printColored("[*] Check MISP host has network connectivity to the `LdapAuth.ldapServer` host.", "yellow");

        if (str_contains($config['LdapAuth']['ldapServer'], "ldaps://")) {
            printColored("[*] Check the LDAPS server is listening on port 636 or a custom port is defined (for example ldap://ldap.example.com:1636).", "yellow");
            printColored("[*] If the LDAPS server is using self-signed certificates or a custom CA, use the `LdapAuth.ldapTlsCustomCaCert` setting.", "yellow");
        } else {
            printColored("[*] Check the LDAP server is listening on port 389 or a custom port is defined (for example ldap://ldap.example.com:1389).", "yellow");
        }
    }
    exit(1);
}

printColored("[Info] LDAP user search successful.", "green");
$ldapUserData = ldap_get_entries($ldapconn, $ldapUser);
if (!$ldapUserData) {
    printColored("[Error] Failed to retrieve user entries: " . ldap_error($ldapconn), "red");
    exit(1);
}

printColored("User Data:", "cyan");
printColored(print_r($ldapUserData, true), "green");

if (empty($ldapUserData[0]['dn'])) {
    printColored("[Error] LDAP user not found.", "red");
    printColored("[*] Check the user exists on your LDAP directory.", "yellow");
    printColored("[*] Check the LDAP search filter is correct, adjust `LdapAuth.ldapSearchFilter` and `LdapAuth.ldapSearchAttribute`.", "yellow");
    exit(1);
}

printColored("LDAP bind with user: " . $ldapUserData[0]['dn'], "cyan");
$password = readline("Enter password: ");
$ldapbind = ldap_bind($ldapconn, $ldapUserData[0]['dn'], $password);
if (!$ldapbind) {
    printColored("[Error] LDAP user authentication failed: " . ldap_error($ldapconn), "red");
    exit(1);
}

printColored("[Success] LDAP user authentication successful!", "green");
ldap_close($ldapconn);
