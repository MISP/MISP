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
}
