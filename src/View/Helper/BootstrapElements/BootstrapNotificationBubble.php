<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;

/**
 * Creates a small colored circle meant to show notifications
 * 
 * # Options
 * - text: Optinal text to be displayed inside the circle
 * - variant: The Bootstrap variant of the notification circle
 * - borderVariant: If set, creates a border around the circle. Typically will hold the value `light` or `dark`
 * - title: The HTML title of the notification
 * - class: Additional classes to be added
 * - attrs: Additional attributes to be added
 * 
 * # Usage
 * $this->Bootstrap->notificationBubble([
 *     'text' => '3',
 *     'variant' => 'warning',
 *     'title' => '3 unread messages',
 * ]);
 */
class BootstrapNotificationBubble extends BootstrapGeneric
{
    private $defaultOptions = [
        'text' => '',
        'variant' => 'warning',
        'borderVariant' => '',
        'title' => '',
        'class' => [],
        'attrs' => [],
    ];

    function __construct(array $options)
    {
        $this->allowedOptionValues = [
            'variant' => BootstrapGeneric::$variants,
            'borderVariant' => array_merge(BootstrapGeneric::$variants, ['']),
        ];
        $this->defaultOptions['title'] =  __('New notifications');
        $this->processOptions($options);
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
        $this->options['class'] = $this->convertToArrayIfNeeded($this->options['class']);
        if (!empty($this->options['borderVariant'])) {
            if (!empty($this->options['attrs']['style'])) {
                $this->options['attrs']['style'] .= 'box-shadow: 0 0.125rem 0.25rem #00000050;';
            } else {
                $this->options['attrs']['style'] = 'box-shadow: 0 0.125rem 0.25rem #00000050;';
            }
        }
    }

    public function notificationBubble(): string
    {
        return $this->genNotificationBubble();
    }

    private function genNotificationBubble(): string
    {
        $tmpId = 'tmp-' . mt_rand();
        $defaultClasses = [
            'position-absolute',
            'top-0',
            'start-100',
            'translate-middle',
            'p-1',
            'rounded-circle',
        ];
        if (!empty($this->options['borderVariant'])) {
            $defaultClasses[] = "border border-2 border-{$this->options['borderVariant']}";
        }
        if (!empty($this->options['variant'])) {
            $defaultClasses[] = "bg-{$this->options['variant']}";
        }

        if (!empty($this->options['text'])) {
            $this->options['attrs']['style'] .= ' min-width: 0.7rem; line-height: 1; box-sizing: content-box;';
            $defaultClasses[] = 'text-center';
            $defaultClasses[] = 'fs-8';
            $defaultClasses[] = 'fw-bold';
        }

        $html = $this->node('span',
            array_merge(
                [
                    'id' => $tmpId,
                    'class' => array_merge(
                        $defaultClasses,
                        $this->options['class']
                    ),
                    'title' => h($this->options['title'])
                ],
                $this->options['attrs']
            ),
            !empty($this->options['text']) ? $this->node('span', [], h($this->options['text'])) : ''
        );
        return $html;
    }
}