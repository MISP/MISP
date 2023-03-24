<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;

/**
 * Creates a bootstrap button
 * 
 * # Options:
 * - text: The text content of the button
 * - html: The HTML content of the button
 * - variant: The Bootstrap variant of the button
 * - outline: Should the button be outlined
 * - size: The size of the button. Accepts 'xs', 'sm', 'lg'. Leave empty for normal size
 * - icon: Should the button have an icon right before the text
 * - image: Should the button have an image in place of an icon right before the text
 * - class: Additional class to add to the button
 * - type: The HTML type of the button for forms. Accepts: 'button' (default), 'submit', and 'reset'
 * - nodeType: Allow to use a different HTML tag than 'button'
 * - title: The button title
 * - Badge: Should the button have a badge. Accepts a \BootstrapElement\BootstrapBadge configuration object
 * - onclick: Shorthand to add a onclick listener function
 * - attrs: Additional HTML attributes
 * 
 * # Usage:
 * $this->Bootstrap->button([
 *     'text' => 'Press me!',
 *     'variant' => 'warning',
 *     'icon' => 'exclamation-triangle',
 *     'onclick' => 'alert(1)',
 * ]);
 */
class BootstrapButton extends BootstrapGeneric
{
    private $defaultOptions = [
        'id' => '',
        'text' => '',
        'html' => null,
        'variant' => 'primary',
        'outline' => false,
        'size' => '',
        'icon' => null,
        'image' => null,
        'class' => [],
        'type' => 'button',
        'nodeType' => 'button',
        'title' => '',
        'badge' => false,
        'onclick' => false,
        'attrs' => [],
    ];

    private $bsClasses = [];

    function __construct(array $options)
    {
        $this->allowedOptionValues = [
            'variant' => array_merge(BootstrapGeneric::$variants, ['link', 'text']),
            'size' => ['', 'xs', 'sm', 'lg'],
            'type' => ['button', 'submit', 'reset']
        ];
        $this->processOptions($options);
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->options['class'] = $this->convertToArrayIfNeeded($this->options['class']);
        $this->checkOptionValidity();

        if (!empty($this->options['id'])) {
            $this->options['attrs']['id'] = $this->options['id'];
        }

        $this->bsClasses[] = 'btn';
        if ($this->options['outline']) {
            $this->bsClasses[] = "btn-outline-{$this->options['variant']}";
        } else {
            $this->bsClasses[] = "btn-{$this->options['variant']}";
        }
        if (!empty($this->options['size'])) {
            $this->bsClasses[] = "btn-{$this->options['size']}";
        }
        if ($this->options['variant'] == 'text') {
            $this->bsClasses[] = 'p-0';
            $this->bsClasses[] = 'lh-1';
        }
        if (!empty($this->options['onclick'])) {
            $this->options['attrs']['onclick'] = $this->options['onclick'];
        }
    }

    public function button(): string
    {
        return $this->genButton();
    }

    private function genButton(): string
    {
        $html = $this->nodeOpen($this->options['nodeType'], array_merge($this->options['attrs'], [
            'class' => array_merge($this->options['class'], $this->bsClasses),
            'role' => "alert",
            'type' => $this->options['type'],
            'title' => h($this->options['title']),
        ]));

        $html .= $this->genIcon();
        $html .= $this->genImage();
        $html .= $this->options['html'] ?? h($this->options['text']);
        if (!empty($this->options['badge'])) {
            $bsBadge = new BootstrapBadge($this->options['badge']);
            $html .= $bsBadge->badge();
        }
        $html .= $this->nodeClose($this->options['nodeType']);
        return $html;
    }

    private function genIcon(): string
    {
        if (!empty($this->options['icon'])) {
            $bsIcon = new BootstrapIcon($this->options['icon'], [
                'class' => [(!empty($this->options['text']) ? 'me-1' : '')]
            ]);
            return $bsIcon->icon();
        }
        return '';
    }

    private function genImage(): string
    {
        if (!empty($this->options['image'])) {
            return $this->node('img', [
                'src' => $this->options['image']['path'] ?? '',
                'class' => ['img-fluid', 'me-1'],
                'width' => '26',
                'height' => '26',
                'alt' => $this->options['image']['alt'] ?? ''
            ]);
        }
        return '';
    }
}
