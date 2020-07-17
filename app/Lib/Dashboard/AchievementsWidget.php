<?php
class AchievementsWidget
{
  /*
  * Note: for this widget to display as expected, you need all icons to be accessible in your webroot. (img/custom)
  * Icons used:
  * - relationship.png --> https://raw.githubusercontent.com/MISP/intelligence-icons/master/simple_png/64/relationship.png
  * - report.png --> https://raw.githubusercontent.com/MISP/intelligence-icons/master/square_png/64/report.png
  * - tlp_green.png --> https://raw.githubusercontent.com/MISP/intelligence-icons/master/square_png/64/tlp_green.png
  */

	public $render = 'Achievements';
  public $title = 'Achievements of my organization';
  public $description = 'Earn badges and improve your usage of MISP.';
  public $width = 4;
  public $height = 8;
  public $params = array();
  public $cacheLifetime = false;
  public $autoRefreshDelay = false;


  /*
  * To add a new badge:  add a new item to the list below and write a function check_<name>.
  *
  * The check function returns true if the badge is granted
  */

  private $badges = array(
    "objects" => array(
      "icon" => "/img/custom/relationship.png",
      "title" => "To enhance the structure of your events, use MISP Objects.",
      "help_page" => "https://github.com/MISP/misp-objects/blob/main/README.md"
    ),
     "events" => array(
       "icon" => "/img/custom/report.png",
       "title" => "MISP is all about sharing relevant data with each other. Start by creating your first event",
       "help_page" => "https://www.circl.lu/doc/misp/using-the-system/#creating-an-event"
     ),
     "tags" => array(
       "icon" => "/img/custom/tlp_green.png",
       "title" => "By adding tags to your events, they can be categorized more easily.",
       "help_page" => "https://www.circl.lu/doc/misp/using-the-system/#tagging"
     )
  );

  // The title is modified if the badge is unlocked
  private $unlocked_badges = array(
    "objects" => "The data you share has now a better structure thanks to the MISP Objects you used.",
    "events" => "Congratulations, you have shared your first event!",
    "tags" => "You have been using tags, good job!"
  );

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
    $conditions = array('Event.orgc_id' => $org_id, 'Event.published' => 1, 'Event.timestamp >=' => $this->start_timestamp);
    $options['conditions'] = array('AND' => $conditions);
    $events = $this->Event->find('count', $options);
    return $events > 0;
  }

  private function check_events($org_id) {
    $conditions = array('Event.orgc_id' => $org_id, 'Event.published' => 1, 'Event.timestamp >=' => $this->start_timestamp);
    $events = $this->Event->find('count', array('conditions' => array('AND' => $conditions)));
    return $events > 0;
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
    $conditions = array('Event.orgc_id' => $org_id, 'Event.published' => 1, 'Event.timestamp >=' => $this->start_timestamp);
    $options['conditions'] = array('AND' => $conditions);
    $events = $this->Event->find('count', $options);
    return $events > 0;
  }

  public function handler($user, $options = array())
  {
    $this->Org = ClassRegistry::init('Organisation');
    $this->Event = ClassRegistry::init('Event');
    //TODO take it from config
    $this->start_timestamp = $this->Event->resolveTimeDelta('180d');

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
?>
