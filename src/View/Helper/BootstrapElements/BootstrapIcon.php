<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;

/**
 * Creates an icon relying on the FontAwesome library.
 * 
 * # Options:
 * - class: Additional classes to add
 * - title: A title to add to the icon
 * - attrs: Additional HTML parameters to add
 * 
 * # Usage:
 * $this->Bootstrap->icon('eye-slash', [
 *     'class' => 'm-3',
 * ]);
 */
class BootstrapIcon extends BootstrapGeneric
{
    public $helpers = ['Icon'];
    
    private $icon = '';
    private $bsHelper;
    private $defaultOptions = [
        'id' => '',
        'class' => [],
        'title' => '',
        'attrs' => [],
    ];

    function __construct($icon, array $options, $bsHelper)
    {
        if(empty($options)){
            $options = [];
        }
        $this->icon = $icon;
        $this->processOptions($options);
        $this->bsHelper = $bsHelper;
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
        $this->options['class'] = $this->convertToArrayIfNeeded($this->options['class']);
    }

    public function icon(): string
    {
        return $this->genIcon();
    }

    private function genIcon(): string
    {
        $options = [
            'id' => $this->options['id'] ?? '',
            'class' => implode('', $this->options['class']),
            'title' => h($this->options['title']),
        ];
        $options = array_merge($this->options['attrs'], $options);
        if (is_array($this->icon)) {
            $options = array_merge($options, $this->icon);
        } else {
            $options = array_merge($options, ['icon' => $this->icon]);
        }
        $html = $this->bsHelper->Icon->icon($options);
        return $html;
    }
}
