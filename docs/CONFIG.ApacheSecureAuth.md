# ApacheSecureAuth
<!---
Ugly diff hack to render text as red using Github's markdown parser
-->
```diff
- BE AWARE: The ApacheSecureAuth / LDAP login code is a 
- 3rd party contribution and untested (including security)
- by the MISP-project team.
```

However, you are free to enable it and report back to the developers if you run into any issues.

## Configuration
### MISP configuration
See the commented sections of [config.default.php](../app/Config/config.default.php) for an example of the MISP configuration variables that the ApacheSecureAuth module requires.

### Webserver configuration
`TODO`

## Logout
### Kerberos
If you have configured you webserver to authenticate users using Kerberos/SPNEGO/Negotiate, 
there is no "log out", other than invalidating the user's Kerberos tickets. 
You can hide the GUI "Log out" link by setting `Plugin.CustomAuth_disable_logout` to `true`.

If you just want to log in as another user, you should be able to do this in an ingonito window. 
Most browser will not allow Kerberos/SPNEGO/Negotiate authentification when in ingognito mode, 
and i.e. Apache will fall back to having  the user input his credentials in a HTTP Basic Auth 
popup, for then to authenticate the user with AD using these credentials.

### LDAP
If you are capturing the user's credentials using HTTP Basic Auth, it can be difficult to make
the browser forget these. 
There is no common or properly defined way of "logging out" after logging in with HTTP Basic Auth.

If the user presses the GUI "Log out" link, this can result in a logout-login loop, where the user
is logged out, but then immediately logged back in by means of the browsers cached HTTP Basic Auth
credentials. This can be observed when a user presses "Log out", for then to be returned to the 
events view with two flash messages - one about a successful logout, and one "Welcome back" login-message.

There are two options to improve the user experience:

#### Option 1 (simple): Hide GUI "Log Out"
As with Kerberos, the admin can hide the GUI "Log out" link by setting `Plugin.CustomAuth_disable_logout` to `true`. 
This is sufficient for many organizations.

#### Options 2 (complicated): Trick the browser into forgetting cached HTTP Basic Auth credentials
The internal path `/users/logout401` in combination with webserver configuration 
can trick most browsers into forgetting cached HTTP Basic Auth credentials.

1. Set `Plugin.CustomAuth_custom_logout` to the internal path `/users/logout401`
2. Modify your webserver configuration. Below is an example for Apache2

````
# Only requiring LDAP auth for the /users/login path will improve the user experience.
#<Location "/">
<Location "/users/login">
  # This block will catch the Ajax logout from /users/logout401 that is required for
  # some browsers, i.e. Firefox. 'Basic bG9nb3V0Og==' equals 'Basic logout:' as
  # used buy the `/users/logout401` endpoint. This will prevent extraneous failed
  # logins a "logout" user on the LDAP server.
  <If "-n %{HTTP:Authorization} && %{HTTP:Authorization} == 'Basic bG9nb3V0Og==' ">
        AuthType Basic
        AuthName "MISP" # Must be same as in LDAP block
        AuthUserFile /dev/null
        Require valid-user
  </If>
    AuthType Basic
    AuthName "MISP"
    AuthBasicProvider ldap
    ...
  </Else>
</Location>
````
