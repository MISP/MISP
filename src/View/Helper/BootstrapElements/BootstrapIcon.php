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
    private $icon = '';
    private $defaultOptions = [
        'id' => '',
        'class' => [],
        'title' => '',
        'attrs' => [],
    ];

    function __construct(string $icon, array $options = [])
    {
        $this->icon = $icon;
        $this->processOptions($options);
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
        $html = $this->node('span', array_merge(
            [
                'id' => $this->options['id'] ?? '',
                'class' => array_merge(
                    $this->options['class'],
                    ["fa fa-{$this->icon}"]
                ),
                'title' => h($this->options['title'])
            ],
            $this->options['attrs']
        ));
        return $html;
    }
}