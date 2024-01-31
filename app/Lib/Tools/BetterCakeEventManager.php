<?php
class BetterCakeEventManager extends CakeEventManager
{
    /**
     * This method is similar as original dispatch, but do not return newly created event. With returning event, there is
     * big memory leak in PHP at least for PHP version 7.4.19.
     * @param CakeEvent $event
     */
    public function dispatch($event)
    {
        $listeners = $this->listeners($event->name());
        if (empty($listeners)) {
            return null;
        }

        foreach ($listeners as $listener) {
            if ($event->isStopped()) {
                break;
            }
            if ($listener['passParams'] === true) {
                $result = call_user_func_array($listener['callable'], $event->data);
            } else {
                $result = $listener['callable']($event);
            }
            if ($result === false) {
                $event->stopPropagation();
            }
            if ($result !== null) {
                $event->result = $result;
            }
        }
    }

    /**
     * @param $eventKey
     * @return array
     */
    public function listeners($eventKey)
    {
        if ($this->_isGlobal) {
            $localListeners = [];
        } else {
            $localListeners = $this->_listeners[$eventKey] ?? [];
        }

        $globalListeners = static::instance()->prioritisedListeners($eventKey);

        $priorities = array_merge(array_keys($globalListeners), array_keys($localListeners));
        $priorities = array_unique($priorities, SORT_REGULAR);
        asort($priorities);

        $result = [];
        foreach ($priorities as $priority) {
            if (isset($globalListeners[$priority])) {
                array_push($result, ...$globalListeners[$priority]);
            }
            if (isset($localListeners[$priority])) {
                array_push($result, ...$localListeners[$priority]);
            }
        }
        return $result;
    }
}
