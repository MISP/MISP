<div class="form-signin panel shadow position-absolute start-50 translate-middle">
    <?php
    echo sprintf(
        '<div class="text-center mb-4">%s</div>',
        $this->Html->image('misp-logo.png', [
            'alt' => __('MISP logo'),
            'height' => 100,
            'style' => ['filter: drop-shadow(4px 4px 4px #22222233);']
        ])
    );
    if (!Configure::check('password_auth.enabled') || Configure::read('password_auth.enabled')) {
        echo sprintf('<h4 class="text-uppercase fw-light mb-3">%s</h4>', __('Sign In'));
        echo $this->Form->create('User');
        echo $this->Form->input('email', [
            'label' => 'Email',
            'class' => 'form-control mb-2',
            'placeholder' => __('Email'),
            'div' => [
                'class' => 'form-floating input email'
            ]
        ]);
        echo $this->Form->input('password', [
            'type' => 'password',
            'label' => 'Password',
            'class' => 'form-control mb-3',
            'placeholder' => __('Password'),
            'div' => [
                'class' => 'form-floating input password'
            ]
        ]);
        if (!empty(Configure::read('LinOTPAuth')) && Configure::read('LinOTPAuth.enabled')!== FALSE) {
            echo $this->Form->input('otp', array('autocomplete' => 'off', 'type' => 'password', 'label' => 'OTP'));
            echo "<div class=\"clear\">";
            echo sprintf(
                '%s <a href="%s/selfservice" title="LinOTP Selfservice">LinOTP Selfservice</a> %s',
                __('Visit'),
                h(Configure::read('LinOTPAuth.baseUrl')),
                __('for the One-Time-Password selfservice.')
            );
        }
        echo empty(Configure::read('Security.allow_password_forgotten')) ? '' : sprintf(
            '<a href="%s/users/forgot" title="%s">%s</a>',
            $baseurl,
            __('Initiate a password reset.'),
            __('I have forgotten my password')
        );
        echo $this->Form->input(__('Login'), [
            'type' => 'button',
            'label' => false,
            'class' => 'btn btn-primary',
            'div' => [
                'class' => ' submit d-grid'
            ]
        ]);
        echo $this->Form->end();
        if (!empty(Configure::read('Security.allow_self_registration'))) {
            echo '<div class="text-end">';
                echo sprintf('<span class="text-secondary ms-auto" style="font-size: 0.8rem">%s <a href="/users/register" class="text-decoration-none link-primary fw-bold">%s</a></span>', __('Don\'t have an account?'), __('Sign up'));
            echo '</div>';
        }
        if (!empty(Configure::read('keycloak.enabled'))) {
            echo sprintf('<div class="d-flex align-items-center my-2"><hr class="d-inline-block flex-grow-1"/><span class="mx-3 fw-light">%s</span><hr class="d-inline-block flex-grow-1"/></div>', __('Or'));
        }
        if (Configure::read('ApacheShibbAuth') == true) {
            echo '<div class="clear"></div><a class="btn btn-info" href="/Shibboleth.sso/Login">Login with SAML</a>';
        }
        if (Configure::read('AadAuth') == true) {
            echo '<div class="clear"></div><a class="btn btn-info" href="/users/login?AzureAD=enable">Login with AzureAD</a>';
        }
        if (Configure::read('OidcAuth') == true && Configure::read('OidcAuth.mixedAuth') == true) {
            echo '<div class="clear" style="margin-top: 5px;"></div><a class="btn btn-info" href="/users/login?OidcAuth=enable">Login with OIDC</a>';
        }
    }
    ?>
</div>
