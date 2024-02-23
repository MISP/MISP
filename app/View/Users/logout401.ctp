<div style="width:100%;">
    <script>
        // Chrome/Edge will log you out once it sees the HTTP401.
        // We need to be extra hacky to properly log out on i.e. Firefox.
        <?php
        $split_baseurl = array();
        # We split the baseurl, since we need to add data between the
        # schema and hostname. We *could* use parse_url here, but then
        # we would need a lot of code to rebuild it
        if (preg_match("/(https?:\/\/)(.*)/", $baseurl, $split_baseurl)):
        ?>
            // The following call has to be done in the users browser to properly make
            // Firefox forget HTTP Basic auth credentials. The login with user set to
            // "logout" will be captured by webserver configuration, and not be sendt
            // to LDAP, but will invalidate the old, cached login in the browser.
            // If this is not working, make sure you have configured the webserver
            // as described in docs/CONFIG.ApacheSecureAuth.md Logout => LDAP => Option 2.
            let logoutxhr401 = new XMLHttpRequest()
            logoutxhr401.open("GET", "<?php echo $split_baseurl[1]; ?>logout:@<?php echo $split_baseurl[2]; ?>/users/login")
            logoutxhr401.send()
        <?php
        else:
          echo "// We failed to parse baseurl";
        endif;
        ?>
    </script>
    <table style="margin-left:auto;margin-right:auto;">
        <tr>
        <td style="width:460px">
            <br /><br />
            <div>
            <?php if (Configure::read('MISP.main_logo') && file_exists(APP . '/files/img/custom/' . Configure::read('MISP.main_logo'))): ?>
                <img src="<?= $this->Image->base64(APP . 'files/img/custom/' . Configure::read('MISP.main_logo')) ?>" style=" display:block; margin-left: auto; margin-right: auto;">
            <?php else: ?>
                <img src="<?php echo $baseurl?>/img/misp-logo-s-u.png" style="display:block; margin-left: auto; margin-right: auto;"/>
            <?php endif;?>
            </div>
            <br>
            <?php
            echo sprintf('<h5>%s</h5>',
                __('You have been successfully logged out.')
            );
            ?>
        </td>
        </tr>
    </table>
</div>
