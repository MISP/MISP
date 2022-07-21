<?php

App::uses('LightPagination', 'Model');

/**
 * Behavior to change default pagination to a lighter one
 */
class LightPaginatorBehavior extends ModelBehavior
{
    // Avoid getting the count of the whole result set
    public function paginateCount(
        Model $model,
        $conditions = null,
        $recursive = 0,
        $extra = []
    ) {
        return PHP_INT_MAX; // Hack to make PaginatorComponent::paginate() think there is a next page
    }
}
