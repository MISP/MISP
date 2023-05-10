<?php
use Cake\Core\Configure;
?>

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
    $template = [
        'inputContainer' => '<div class="form-floating input {{type}}{{required}}">{{content}}</div>',
        'formGroup' => '{{input}}{{label}}',
        'submitContainer' => '<div class="submit d-grid">{{content}}</div>',
    ];
    $this->Form->setTemplates($template);
    if (!Configure::check('password_auth.enabled') || Configure::read('password_auth.enabled')) {
        echo sprintf('<h4 class="text-uppercase fw-light mb-3">%s</h4>', __('Sign In'));
        echo $this->Form->create(null, ['url' => ['controller' => 'users', 'action' => 'login', '?' => ['redirect' => $this->request->getQuery('redirect')],]]);
        echo $this->Form->control('email', ['label' => 'Email', 'class' => 'form-control mb-2', 'placeholder' => __('Email')]);
        echo $this->Form->control('password', ['type' => 'password', 'label' => 'Password', 'class' => 'form-control mb-3', 'placeholder' => __('Password')]);
        echo $this->Form->control(__('Login'), ['type' => 'submit', 'class' => 'btn btn-primary']);
        echo $this->Form->end();
        if (!empty(Configure::read('security.registration.self-registration'))) {
            echo '<div class="text-end">';
                echo sprintf('<span class="text-secondary ms-auto" style="font-size: 0.8rem">%s <a href="/users/register" class="text-decoration-none link-primary fw-bold">%s</a></span>', __('Don\'t have an account?'), __('Sign up'));
            echo '</div>';
        }
        if (!empty(Configure::read('keycloak.enabled'))) {
            echo sprintf('<div class="d-flex align-items-center my-2"><hr class="d-inline-block flex-grow-1"/><span class="mx-3 fw-light">%s</span><hr class="d-inline-block flex-grow-1"/></div>', __('Or'));
        }
    }
    if (!empty(Configure::read('keycloak.enabled'))) {
        echo $this->Form->create(null, [
            'url' => Cake\Routing\Router::url([
                'prefix' => false,
                'plugin' => 'ADmad/SocialAuth',
                'controller' => 'Auth',
                'action' => 'login',
                'provider' => 'keycloak',
                '?' => ['redirect' => $this->request->getQuery('redirect')]
            ]),
        ]);
        echo $this->Bootstrap->button([
            'type' => 'submit',
            'text' => __('Login with Keycloak'),
            'variant' => 'secondary',
            'class' => ['d-block', 'w-100'],
            'image' => [
                'path' => '/img/keycloak_logo.png',
                'alt' => 'Keycloak',
            ],
        ]);
        echo $this->Form->end();
    }
    ?>
</div>
