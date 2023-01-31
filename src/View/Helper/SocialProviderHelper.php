<?php

namespace App\View\Helper;

use Cake\View\Helper;
use Cake\Utility\Hash;

class SocialProviderHelper extends Helper
{
    public $helpers = ['Bootstrap'];

    private $providerImageMapping = [
        'keycloak' => '/img/keycloak_logo.png',
    ];

    public function hasSocialProfile($identity): bool
    {
        return !empty($identity['social_profile']);
    }

    public function getIcon($identity)
    {
        if (!empty($identity['social_profile'])) {
            $provider = $identity['social_profile']['provider'];
            if (!empty($this->providerImageMapping[$provider])) {
                return $this->genImage($this->providerImageMapping[$provider], h($provider));
            }
        }
        return '';
    }

    private function genImage($url, $alt)
    {
        return $this->Bootstrap->genNode('img', [
            'src' => $url,
            'class' => ['img-fluid'],
            'width' => '16',
            'height' => '16',
            'alt' => $alt,
            'title' => __('Authentication provided by {0}', $alt),
        ]);
    }
}
