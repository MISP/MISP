<?php

/**
 * Prevents a record from being deleted when deletion would result in orphaned related records; if deletion is prevented, an explanatory error message is stored in the model's attribute $deletionError.
 *
 * Example: A user has written many posts. Now somebody tries to delete the user - which would result in orphaned posts with no user! So this behavior prevents deletion of the user.
 *
 * Notice: This behavior has only an effect when 'dependent' is set to false (otherwise the records are all deleted anyway and no orphans would be left behind).
 *
 * @author      Joshua Muheim (Incense.ch)
 * @copyright   Joshua Muheim, 2011
 * @package     magic_tools
 * @subpackage  behaviors
 */
App::import('core', 'ModelBehavior');

class OrphansProtectableBehavior extends ModelBehavior {
	/**
	 * Prepares the behavior.
	 *
	 * @param $model Model
	 * @param $settings array
	 */
	function setup(&$model, $settings) {
		$Model->_deletionError = null; // Stores the deletion error message
		$Model->orphansProtectableOptions = array_merge(array(
			'listPossibleOrphans' => true,
			'htmlError' => false
		), $settings);
	}

	/**
	 * Checks if there would be orphaned record left behind after deletion of this record; if so, deletion is prevented.
	 *
	 * @param $model Model
	 * @param $cascade boolean
	 * @return boolean
	 */
	function beforeDelete(&$model, $cascade) {
		if ($cascade) return true;
		return !$Model->wouldLeaveOrphanedRecordsBehind();
	}

	/**
	 * Checks if deletion of this record would leave orphaned associated records behind.
	 *
	 * @param $model Model
	 * @return boolean
	 */
	function wouldLeaveOrphanedRecordsBehind(&$model) {
		$possibleOrphans = array();

		foreach ($Model->hasMany as $model => $settings) {
		// Is relationship is dependent?
			if ($settings['dependent']) { // Yes! Possible orphans are deleted, too!
				// Do nothing
			} else { // No! Possible orphans should be protected!
				// Is there a possible orphan for this relation?
				$Model->{$model}->recursive = -1;
				$objects = $Model->{$model}->find('all', array('conditions' => array($settings['className'].'.'.$settings['foreignKey'] => $Model->id), 'order' => 'id asc'));
				if (count($objects) > 0) { // Yes, there is at least one possible orphan!
					$objectIds = array();
					foreach ($objects as $object) {
						$objectIds[] = $object[$model]['id'];
					}
					$possibleOrphans[$model] = $objectIds;
				}
			}
		}

		// Would orphans be left behind?
		if (count($possibleOrphans) > 0) { // Yes! Create deletion error message!
			$Model->_deletionError = $Model->createDeletionError($possibleOrphans);
			return true;
		} else { // No!
			return false;
		}
	}

	/**
	 * Returns the deletion error message (if there is one).
	 *
	 * @param $model Model
	 * @return string
	 */
	function getDeletionError(&$model) {
		return $Model->_deletionError;
	}

	/**
	 * Creates the deletion error message and returns it.
	 *
	 * @param $model Model
	 * @param $possibleOrphans array
	 * @return string
	 */
	function createDeletionError(&$model, $possibleOrphans) {
		$errorParts = array();
		foreach ($possibleOrphans as $model => $ids) {
			$count = count($ids);
			$modelName = $count > 1 ? Inflector::pluralize($model) : $model;
			$errorParts[] = $count.' '.$modelName.' (ID: '.$Model->createDeletionErrorIds($model, $ids).')';
		}
		return __('it has the following dependent items', true).': '.implode($errorParts, ', ');
	}

	/**
	 * Creates a string containing HTML-links to comma separated IDs of the potentially orphaned records of the specified model.
	 *
	 * @param $model Model
	 * @param $orphanModel string
	 * @param $ids array
	 * @return string
	 */
	function createDeletionErrorIds(&$model, $orphanModel, $ids) {
		$messageParts = array();
		if ($Model->orphansProtectableOptions['htmlError']) {
		foreach ($ids as $id) {
			$messageParts[] = '<a href="'.Inflector::pluralize(strtolower($orphanModel)).'/view/'.$id.'">'.$id.'</a>'; // TODO: Noch unschÃ¶n! --zivi-muh
		}
		} else {
		$messageParts = $ids;
		}
		return implode($messageParts, ', ');
	}
}
