<?php

namespace App\View\Helper;

use Cake\View\Helper;
use Cake\Utility\Hash;

class IconHelper extends Helper
{
    public $helpers = ['FontAwesome', 'Bootstrap'];

    public function icon($icon)
    {
        if (!empty($icon['icons'])) {
            return $this->stackedIcons($icon);
        } else if (!empty($icon['image'])) {
            return $this->image($icon['image']);
        } else if (!empty($icon['html'])) {
            return $this->rawHtml($icon['html']);
        }
        return $this->regularIcon($icon);
    }

    public function regularIcon($icon)
    {
        return $this->Bootstrap->node('i', [
            'class' => h($icon['class'] ?? '') . ' ' .$this->FontAwesome->getClass($icon['icon'] ?? $icon),
            'style' => h($icon['style'] ?? ''),
            'title' => h($icon['title'] ?? null)
        ]);
    }

    public function stackedIcons($icons)
    {
        $options = $icons;
        $icons = $icons['icons'];
        $html = $this->Bootstrap->node('span', [
                'class' => sprintf('fa-stack fa-stack-small %s', h($options['class'] ?? '')),
                'style' => h($options['style'] ?? '')
            ],
            implode('', [
                $this->Bootstrap->node('span', [
                    'class' => sprintf('fas fa-stack-2x fa-%s %s', h($icons[0]['icon'] ?? ''), h($icons[0]['class'] ?? '')),
                    'style' => h($icons[0]['style'] ?? ''),
                ]),
                $this->Bootstrap->node('span', [
                    'class' => sprintf('fas fa-stack-1x fa-%s %s', h($icons[1]['icon'] ?? ''), h($icons[1]['class'] ?? '')),
                    'style' => h($icons[1]['style'] ?? ''),
                ])
            ])
        );
        return $html;
    }

    public function image($image)
    {
        return $this->Bootstrap->node('img', [
            'class' => h($image['class'] ?? ''),
            'style' => h($image['style'] ?? ''),
            'src' => h($image['src'] ?? ''),
            'title' => h($image['title'] ?? null)
        ]);
    }

    public function rawHtml($html)
    {
        return $html;
    }
}
