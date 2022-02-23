<?php

/**
 * Set warnings based on a set of fixed checks
 */
class EventWarningBehavior extends ModelBehavior
{
    private $__warnings = [];

    /**
     * @param Model $Model
     * @param array $event
     * @return array
     */
    public function generateWarnings(Model $Model, array $event)
    {
        $this->__tlpDistributionCheck($event);
        $this->__contextCheck($event);
        $this-> __emptyEventCheck($event);
        return $this->__warnings;
    }

    private function __emptyEventCheck(array $event)
    {
        if (empty($event['Attribute']) && empty($event['objects'])) {
            $this->__warnings[__('Content')][] = __('Your event has neither attributes nor objects, whilst this can have legitimate reasons (such as purely creating an event with an event report or galaxy clusters), in most cases it\'s a sign that the event has yet to be fleshed out.');
        }
    }

    private function __contextCheck(array $event)
    {
        if (empty($event['Galaxy']) && empty($event['EventTag'])) {
            $this->__warnings[__('Contextualisation')][] = __('Your event has neither tags nor galaxy clusters attached - generally adding context to an event allows for quicker decision making and more accurate filtering, it is highly recommended that you label your events to the best of your ability.');
        }
    }

    private function __tlpDistributionCheck(array $event)
    {
        if (!empty($event['EventTag'])) {
            foreach ($event['EventTag'] as $eT) {
                $tagName = $eT['Tag']['name'];
                $this->__tlpTaxonomyCheck($tagName);
                if ($tagName === 'tlp:white' && $event['Event']['distribution'] != Event::DISTRIBUTION_ALL) {
                    $this->__warnings[__('Distribution')][] = __('The event is tagged as tlp:white, yet the distribution is not set to all. Change the distribution setting to something more lax if you wish for the event to propagate further.');
                } else if ($tagName === 'tlp:green' && !in_array($event['Event']['distribution'], [Event::DISTRIBUTION_COMMUNITY, Event::DISTRIBUTION_CONNECTED, Event::DISTRIBUTION_ALL])) {
                    $this->__warnings[__('Distribution')][] = __('The event is tagged as tlp:green, yet the distribution is not set to community, connected communities or all. tlp:green assumes sharing with your entire community - make sure that the selected distribution setting covers that.');
                } else if (in_array($tagName, ['tlp:amber', 'tlp:red'], true) && $event['Event']['distribution'] == Event::DISTRIBUTION_ALL) {
                    $this->__warnings[__('Distribution')][] = __('The event is tagged as %s, yet the distribution is set to all, be aware of potential information leakage.', $tagName);
                }
            }
        }
    }

    /**
     * @param string $tagName
     * @return void
     */
    private function __tlpTaxonomyCheck($tagName)
    {
        $lowerTagName = trim(strtolower($tagName));
        if (substr($lowerTagName, 0, 4) === 'tlp:') {
            if (!in_array($lowerTagName, ['tlp:white', 'tlp:green', 'tlp:amber', 'tlp:red', 'tlp:ex:chr'], true)) {
                $this->__warnings['TLP'][] = __('Unknown TLP tag, please refer to the TLP taxonomy as to what is valid, otherwise filtering rules created by your partners may miss your intent.');
            } else if ($lowerTagName !== $tagName) {
                $this->__warnings['TLP'][] = __('TLP tag with invalid formatting: Make sure that you only use TLP tags from the taxonomy. Custom tags with invalid capitalisation, white spaces or other artifacts will break synchronisation and filtering rules intended for the correct taxonomy derived tags.');
            }
        }
    }
}
