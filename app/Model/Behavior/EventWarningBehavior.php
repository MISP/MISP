<?php

/**
 * Set warnings based on a set of fixed checks
 *
 */
class EventWarningBehavior extends ModelBehavior
{
    private $__warnings = [];

    public function generateWarnings(Model $Model, $event)
    {
        $this->__tlpDistributionCheck($event);
        $this->__contextCheck($event);
        $this-> __emptyEventCheck($event);
        return $this->__warnings;
    }

    private function __emptyEventCheck($event)
    {
        if (empty($event['Attribute']) && empty($event['objects'])) {
            $this->__warnings[__('Content')][] = __('Your event has neither attributes nor objects, whilst this can have legitimate reasons (such as purely creating an event with an event report or galaxy clusters), in most cases it\'s a sign that the event has yet to be fleshed out.');
        }
    }

    private function __contextCheck($event)
    {
        if (empty($event['Galaxy']) && empty($event['EventTag'])) {
            $this->__warnings[__('Contextualisation')][] = __('Your event has neither tags nor galaxy clusters attached - generally adding context to an event allows for quicker decision making and more accurate filtering, it is highly recommended that you label your events to the best of your ability.');
        }
    }

    private function __tlpDistributionCheck($event)
    {
        if (!empty($event['EventTag'])) {
            foreach ($event['EventTag'] as $eT) {
                $this->__tlpTaxonomyCheck($eT, $this->__warnings);
                if ($eT['Tag']['name'] === 'tlp:white' && $event['Event']['distribution'] !== 3) {
                    $this->__warnings[__('Distribution')][] = __('The event is tagged as tlp:white, yet the distribution is not set to all. Change the distribution setting to something more lax if you wish for the event to propagate further.');
                } else if ($eT['Tag']['name'] === 'tlp:green' && !in_array($event['Event']['distribution'], [1, 2, 3])) {
                    $this->__warnings[__('Distribution')][] = __('The event is tagged as tlp:green, yet the distribution is not set to community, connected communities or all. tlp:green assumes sharing with your entire community - make sure that the selected distribution setting covers that.');
                } else if (in_array($eT['Tag']['name'], ['tlp:amber', 'tlp:red']) && $event['Event']['distribution'] !== 4) {
                    $this->__warnings[__('Distribution')][] = __('The event is tagged as %s, yet the distribution is set to all, be aware of potential information leakage.', $eT['Tag']['name']);
                }
            }
        }
    }

    private function __tlpTaxonomyCheck($eventTag)
    {
        $lowerTagName = trim(strtolower($eventTag['Tag']['name']));
        if (substr($lowerTagName, 0, 4) === 'tlp:') {
            if (!in_array($lowerTagName, ['tlp:white', 'tlp:green', 'tlp:amber', 'tlp:red', 'tlp:ex:chr'])) {
                $this->__warnings['TLP'][] = __('Unknown TLP tag, please refer to the TLP taxonomy as to what is valid, otherwise filtering rules created by your partners may miss your intent.');
            } else if ($lowerTagName !== $eventTag['Tag']['name']) {
                    $this->__warnings['TLP'][] = __('TLP tag with invalid formating: Make sure that you only use TLP tags from the taxonomy. Custom tags with invalid capitalisation, white spaces or other artifacts will break synchronisation and filtering rules intended for the correct taxonomy derived tags.');
            }
        }
    }
}
