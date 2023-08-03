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
    private $nodeType = 'span';

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
        if (!empty($this->options['attrs']['onclick']) || !empty($this->options['onclick'])) {
            $this->nodeType = 'button';
            $this->options['class'][] = 'btn btn-sm btn-link';
        }
        $this->options['title'] = h($this->options['title']);
        $this->options = array_merge($this->options['attrs'], $this->options);
        unset($this->options['attrs']);
    }

    public function icon(): string
    {
        return $this->genIcon();
    }

    private function genIcon(): string
    {
        $options = [
            'class' => implode('', $this->options['class']),
            'title' => $this->options['title'],
        ];
        if (is_array($this->icon)) {
            $options = array_merge($options, $this->icon);
        } else {
            $options = array_merge($options, ['icon' => $this->icon]);
        }
        $iconHtml = $this->bsHelper->Icon->icon($options);
        $html = $this->node($this->nodeType, $this->options, $iconHtml);
        return $html;
    }
}
