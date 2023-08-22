<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;


/**
 * Creates a Bootstrap badge
 * 
 * # Options:
 * - text: The text content of the badge
 * - html: The HTML content of the badge
 * - variant: The Bootstrap variant of the badge
 * - pill: Should the badge have a Bootstrap pill style
 * - icon: Should the button have an icon right before the text
 * - title: The title of the badge
 * - size: The size of the badge. Accepts 'sm', 'md, 'lg'. Leave empty for normal size
 * - class: Additional class to add to the button
 * - attrs: Additional HTML attributes
 * 
 * # Usage:
 *  echo $this->Bootstrap->badge([
 *    'text' => 'text',
 *    'variant' => 'success',
 *    'pill' => false,
 * ]);
 */
class BootstrapBadge extends BootstrapGeneric
{
    private $defaultOptions = [
        'id' => '',
        'text' => '',
        'html' => null,
        'variant' => 'primary',
        'pill' => false,
        'icon' => false,
        'title' => '',
        'size' => '',
        'class' => [],
        'attrs' => [],
    ];
    private $bsHelper;

    function __construct(array $options, $bsHelper)
    {
        $this->allowedOptionValues = [
            'variant' => BootstrapGeneric::$variants,
            'size' => ['', 'sm', 'md', 'lg'],
        ];
        $this->processOptions($options);
        $this->bsHelper = $bsHelper;
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->options['class'] = $this->convertToArrayIfNeeded($this->options['class']);
        $this->checkOptionValidity();
        if (!empty($this->options['size'])) {
            if ($this->options['size'] == 'sm') {
                $this->options['class'][] = 'fs-7';
            } else if ($this->options['size'] == 'lg') {
                $this->options['class'][] = 'fs-5';
            } else if ($this->options['size'] == 'md') {
                $this->options['class'][] = 'fs-6';
            }
        }
    }

    public function badge(): string
    {
        return $this->genBadge();
    }

    private function genBadge(): string
    {
        $html = $this->node(
            'span',
            array_merge(
                [
                'class' => array_merge(
                    $this->options['class'],
                    [
                    'ms-1',
                    'badge',
                    self::getBGAndTextClassForVariant($this->options['variant']),
                    $this->options['pill'] ? 'rounded-pill' : '',
                    ]
                ),
                'title' => $this->options['title'],
                'id' => $this->options['id'] ?? '',
                ],
                $this->options['attrs']
            ),
            [
            $this->genIcon(),
            $this->options['html'] ?? h($this->options['text'])
            ]
        );
        return $html;
    }

    private function genIcon(): string
    {
        if (!empty($this->options['icon'])) {
            $bsIcon = new BootstrapIcon(
                $this->options['icon'],
                [
                'class' => [(!empty($this->options['text']) ? 'me-1' : '')]
                ],
                $this->bsHelper
            );
            return $bsIcon->icon();
        }
        return '';
    }
}
