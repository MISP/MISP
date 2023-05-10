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

    public function getIcon($identity, array $classes=[])
    {
        if (!empty($identity['social_profile'])) {
            $provider = $identity['social_profile']['provider'];
            if (!empty($this->providerImageMapping[$provider])) {
                return $this->genImage($this->providerImageMapping[$provider], h($provider), $classes);
            }
        }
        return '';
    }

    private function genImage($url, $alt, array $classes=[])
    {
        return $this->Bootstrap->node('img', [
            'src' => $url,
            'class' => array_merge(['img-fluid'], $classes),
            'width' => '16',
            'height' => '16',
            'alt' => $alt,
            'title' => __('Authentication provided by {0}', $alt),
        ]);
    }
}
