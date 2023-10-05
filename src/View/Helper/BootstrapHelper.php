<?php

/**
 * Bootstrap Helper class to quicly create Bootstrap components
 * 
 * # Usage:
 *    $this->Bootstrap->{$componentName}($options);
 */

namespace App\View\Helper;

use App\View\Helper\BootstrapElements\BootstrapAccordion;
use App\View\Helper\BootstrapElements\BootstrapAlert;
use App\View\Helper\BootstrapElements\BootstrapBadge;
use App\View\Helper\BootstrapElements\BootstrapButton;
use App\View\Helper\BootstrapElements\BootstrapCard;
use App\View\Helper\BootstrapElements\BootstrapCollapse;
use App\View\Helper\BootstrapElements\BootstrapDropdownMenu;
use App\View\Helper\BootstrapElements\BootstrapIcon;
use App\View\Helper\BootstrapElements\BootstrapListGroup;
use App\View\Helper\BootstrapElements\BootstrapListTable;
use App\View\Helper\BootstrapElements\BootstrapModal;
use App\View\Helper\BootstrapElements\BootstrapNotificationBubble;
use App\View\Helper\BootstrapElements\BootstrapProgress;
use App\View\Helper\BootstrapElements\BootstrapProgressTimeline;
use App\View\Helper\BootstrapElements\BootstrapSwitch;
use App\View\Helper\BootstrapElements\BootstrapTable;
use App\View\Helper\BootstrapElements\BootstrapTabs;
use App\View\Helper\BootstrapElements\BootstrapToast;
use Cake\View\Helper;


const COMPACT_ATTRIBUTES = [
    'checked' => true,
    'default' => true,
    'disabled' => true,
    'enabled' => true,
    'hidden' => true,
    'multiple' => true,
    'novalidate' => true,
    'readonly' => true,
    'required' => true,
    'selected' => true,
    'visible' => true,
];

class BootstrapHelper extends Helper
{
    public $helpers = ['FontAwesome', 'Icon'];

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function tabs(array $options): string
    {
        $bsTabs = new BootstrapTabs($options);
        return $bsTabs->tabs();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function alert(array $options): string
    {
        $bsAlert = new BootstrapAlert($options);
        return $bsAlert->alert();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @param array $data See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function table(array $options, array $data = []): string
    {
        $bsTable = new BootstrapTable($options, $data, $this);
        return $bsTable->table();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @param array $data See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function listTable(array $options, array $data = []): string
    {
        $bsListTable = new BootstrapListTable($options, $data, $this);
        return $bsListTable->table();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function button(array $options): string
    {
        $bsButton = new BootstrapButton($options, $this);
        return $bsButton->button();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param $icon The icon options. See IconHelper\icon
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function icon($icon, array $options = []): string
    {
        $bsIcon = new BootstrapIcon($icon, $options, $this);
        return $bsIcon->icon();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function badge(array $options): string
    {
        $bsBadge = new BootstrapBadge($options, $this);
        return $bsBadge->badge();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function modal(array $options): string
    {
        $bsModal = new BootstrapModal($options, $this);
        return $bsModal->modal();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function card(array $options): string
    {
        $bsCard = new BootstrapCard($options);
        return $bsCard->card();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function progress(array $options): string
    {
        $bsProgress = new BootstrapProgress($options);
        return $bsProgress->progress();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @param string $content See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function collapse(array $options, string $content): string
    {
        $bsCollapse = new BootstrapCollapse($options, $content, $this);
        return $bsCollapse->collapse();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @param array $content See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function accordion(array $options, array $content): string
    {
        $bsAccordion = new BootstrapAccordion($options, $content, $this);
        return $bsAccordion->accordion();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function progressTimeline(array $options): string
    {
        $bsProgressTimeline = new BootstrapProgressTimeline($options, $this);
        return $bsProgressTimeline->progressTimeline();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $data See BootstrapElements\BootstrapTabs
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function listGroup(array $data, array $options = []): string
    {
        $bsListGroup = new BootstrapListGroup($data, $options, $this);
        return $bsListGroup->listGroup();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function switch(array $options): string
    {
        $bsSwitch = new BootstrapSwitch($options, $this);
        return $bsSwitch->switch();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function notificationBubble(array $options): string
    {
        $bsNotificationBubble = new BootstrapNotificationBubble($options, $this);
        return $bsNotificationBubble->notificationBubble();
    }

    /**
     * Creates a Bootstrap tabs from the given options
     *
     * @param array $options See BootstrapElements\BootstrapTabs
     * @return string
     */
    public function dropdownMenu(array $options): string
    {
        $bsDropdownMenu = new BootstrapDropdownMenu($options, $this);
        return $bsDropdownMenu->dropdownMenu();
    }

    /**
     * Creates a Bootstrap toast from the given options
     *
     * @param array $options
     * @return string
     */
    public function toast(array $options): string
    {
        $bsToast = new BootstrapToast($options, $this);
        return $bsToast->toast();
    }

    /**
     * Creates a HTML node
     *
     * @param string $tag The tag of the node. Example: `div`, `span`, ...
     * @param array $attrs Optional HTML attributes to be added on the node
     * @param string $content Optional innerHTML of the node
     * @param array $options Optional options to build the node. See BootstrapGeneric\node
     * @return string
     */
    public function node(string $tag, array $attrs = [], string $content = '', array $options = []): string
    {
        return BootstrapGeneric::node($tag, $attrs, $content, $options);
    }

    /**
     * Render the provided template with the given data
     *
     * @param string $template The template to render. See BootstrapGeneric\render
     * @param array $data The data to be used during the template building
     * @param array $options Optional options to build the template
     * @return string
     */
    public function render(string $template, array $data = [], array $options = []): string
    {
        return BootstrapGeneric::render($template, $data, $options);
    }
}
