<?php
App::uses('RailCard', 'Tools/RailCards');

/**
 * A producer some of whose cards load after first paint, through one
 * `<controller>/railCard/<record id>/<card id>` action.
 */
abstract class LazyRailCards
{
    /**
     * @return string app-relative, e.g. '/feeds/railCard/'
     */
    abstract protected function railCardUrl();

    /**
     * @return array card id => [shape, title, icon, producer method]
     */
    abstract protected function lazyCards();

    /**
     * @param string $cardId
     * @return array [shape, title, icon, method]
     */
    protected function head($cardId)
    {
        return $this->lazyCards()[$cardId];
    }

    /**
     * A lazy card before it is computed.
     *
     * @param string $cardId
     * @param int $recordId
     * @return array
     */
    public function slot($cardId, $recordId)
    {
        list($shape, $title, $icon) = $this->head($cardId);
        return RailCard::slot($shape, $cardId, $title, $icon,
            $this->railCardUrl() . (int)$recordId . '/' . $cardId);
    }

    /**
     * The lazy card $cardId, built by its producer method from the rest of
     * the arguments.
     *
     * @param string $cardId
     * @param mixed ...$args
     * @return array
     * @throws NotFoundException
     */
    public function lazy($cardId, ...$args)
    {
        $cards = $this->lazyCards();
        if (!isset($cards[$cardId])) {
            throw new NotFoundException(__('Invalid rail card.'));
        }
        return $this->{$cards[$cardId][3]}(...$args);
    }
}
