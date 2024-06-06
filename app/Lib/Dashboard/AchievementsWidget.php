<?php
class AchievementsWidget
{

    public $render = 'Achievements';
    public $title = 'Achievements of my organization';
    public $description = 'Earn badges and improve your usage of MISP.';
    public $width = 4;
    public $height = 10;
    public $cacheLifetime = false;
    public $autoRefreshDelay = false;
    public $params = array(
            'past_days' => 'The past number of days considered to look for criteria satisfaction (default 180)'
    );
    public $placeholder =
'{
    "past_days": "180"
}';


    /*
    * To add a new badge:    add a new item to the list below and write a function check_<name>.
    *
    * The check function returns true if the badge is granted
    */

    private $badges;
    private $unlocked_badges;

    public function __construct(){
        $this->badges = array(
           "events" => array(
               "icon" => "/img/ach_misp_event.png",
               "title" => __("MISP is all about sharing relevant data with each other. Start by creating your first event."),
               "help_page" => "https://www.circl.lu/doc/misp/using-the-system/#creating-an-event"
           ),
           "tags" => array(
               "icon" => "/img/ach_tlp_green.png",
               "title" => __("By adding tags to your events, they can be categorized more easily."),
               "help_page" => "https://www.circl.lu/doc/misp/using-the-system/#tagging"
           ),
           "objects" => array(
               "icon" => "/img/ach_misp_object.png",
               "title" => __("To enhance the structure of your events, use MISP Objects."),
               "help_page" => "https://github.com/MISP/misp-objects/blob/main/README.md"
           ),
           "taxonomies" => array(
               "icon" => "/img/ach_taxonomy.png",
               "title" => __("Make sure to speak the same language as your counterparts by using taxonomies for your tags."),
               "help_page" => "https://www.circl.lu/doc/misp/taxonomy/"
           ),
           "galaxies" => array (
               "icon" => "/img/ach_galaxy.png",
               "title" => __("Go above and beyond tags and taxonomies, and start using galaxies."),
               "help_page" => "https://www.circl.lu/doc/misp/galaxy/"
           ),
           "attack" => array(
               "icon" => "/img/ach_attack.png",
               "title" => __("Add the TTPs following the MITRE ATT&CK framework to make your events even more interesting."),
               "help_page" => "https://www.misp-project.org/2018/06/27/MISP.2.4.93.released.html"
           )
      );

        // The title is modified if the badge is unlocked
        $this->unlocked_badges = array(
            "objects" => __("The data you share has now a better structure thanks to the MISP Objects you used."),
            "events" => __("Congratulations, you have shared your first event!"),
            "tags" => __("You have been using tags, good job!"),
            "taxonomies" => __("Taxonomies have been used in your events."),
            "galaxies" => __("Galaxies have no secrets for you in this Threat Sharing universe."),
            "attack" => __("MISP & MITRE ATT&CK is a great combo.")
        );
    }





    private function check_taxonomies($org_id) {
        return $this->lookup_tag_name_value($org_id, '%:%');
    }

    private function check_galaxies($org_id) {
        return $this->lookup_tag_name_value($org_id, 'misp-galaxy:%');
    }

    private function check_attack($org_id) {
        return $this->lookup_tag_name_value($org_id, 'misp-galaxy:mitre%');
    }


    private function check_tags($org_id) {
        $options['joins'] = array(
                array('table' => 'event_tags',
                        'alias' => 'EventTag',
                        'type' => 'INNER',
                        'conditions' => array(
                                'EventTag.event_id = Event.id',
                        )
                )
        );
        $options['fields'] = 'Event.id';
        $options['limit'] = 1;
        $conditions = array('Event.orgc_id' => $org_id, 'Event.published' => 1, 'Event.timestamp >=' => $this->start_timestamp);
        $options['conditions'] = array('AND' => $conditions);
        $events = $this->Event->find('all', $options);
        return count($events) > 0;
    }

    private function check_events($org_id) {
        $conditions = array('Event.orgc_id' => $org_id, 'Event.published' => 1, 'Event.timestamp >=' => $this->start_timestamp);
        $events = $this->Event->find('all', array('limit' => 1, 'conditions' => array('AND' => $conditions)));
        return count($events) > 0;
    }

    private function check_objects($org_id) {
        $options['joins'] = array(
                array('table' => 'objects',
                        'alias' => 'Objects',
                        'type' => 'INNER',
                        'conditions' => array(
                                'Objects.event_id = Event.id',
                        )
                )
        );
        $options['fields'] = 'Event.id';
        $options['limit'] = 1;
        $conditions = array('Event.orgc_id' => $org_id, 'Event.published' => 1, 'Event.timestamp >=' => $this->start_timestamp);
        $options['conditions'] = array('AND' => $conditions);
        $events = $this->Event->find('all', $options);
        return count($events) > 0;
    }

    private function lookup_tag_name_value($org_id, $value) {
        $options['joins'] = array(
                array('table' => 'event_tags',
                        'alias' => 'EventTag',
                        'type' => 'INNER',
                        'conditions' => array(
                                'EventTag.event_id = Event.id',
                        )
                ),
                array('table' => 'tags',
                            'alias' => 'Tag',
                            'type' => 'INNER',
                            'conditions' => array(
                                'Tag.id = EventTag.tag_id'
                            )
                )
        );
        $options['fields'] = 'Event.id';
        $options['limit'] = 1;
        $conditions = array('Event.orgc_id' => $org_id, 'Event.published' => 1, 'Event.timestamp >=' => $this->start_timestamp, 'Tag.name LIKE' => $value);
        $options['conditions'] = array('AND' => $conditions);
        $events = $this->Event->find('all', $options);
        return count($events) > 0;
    }

    public function handler($user, $options = array())
    {
        $this->Org = ClassRegistry::init('Organisation');
        $this->Event = ClassRegistry::init('Event');

        $days = 180;
        if(!empty($options['past_days'])) {
            $days = (int) $options['past_days'];
        }
        $this->start_timestamp = $this->Event->resolveTimeDelta($days.'d');

        $org_id = $user['Organisation']['id'];
        $locked = array();
        $unlocked = array();

        // We look through each badge and evaluate the condition
        foreach ($this->badges as $key => $item) {
            $fun = 'check_'.$key;
            if($this->$fun($org_id)) { // Condition for badge is met
                //we replace the text to the unlocked one
                if(isset($this->unlocked_badges[$key])) {
                    $item['title'] = $this->unlocked_badges[$key];
                }
                $unlocked[] = $item;
            } else {
                $locked[] = $item;
            }
        }

        $result = array();
        $result['locked'] = $locked;
        $result['unlocked'] = $unlocked;
        return $result;
    }
}
