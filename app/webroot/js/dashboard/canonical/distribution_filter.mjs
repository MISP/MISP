// `distribution_filter` canonical type (PRD §5.5).
//
// Multi-select picker for MISP's six event-distribution levels.
// Wire shape is an int array (subset of {0..5}) matching
// `Event::fetchEvent`'s `distribution` option — CakePHP's IN
// coercion accepts the array directly, so consumer widgets pass it
// through without a post-filter step.
//
// Picker behaviour is shared with threat_level_filter and
// analysis_filter via the enum_picker factory; only the level
// vocabulary differs here.

import { makeEnumPicker } from './enum_picker.mjs';

// Canonical MISP distribution semantics. Order mirrors the
// dropdown users see in the event edit form so bulk-edit feels
// familiar.
const LEVELS_DEFINITION = [
  { value: 0, label: 'Org only',    hint: 'Your organisation' },
  { value: 1, label: 'Community',   hint: 'This community only' },
  { value: 2, label: 'Connected',   hint: 'Connected communities' },
  { value: 3, label: 'All',         hint: 'All communities' },
  { value: 4, label: 'Sharing grp', hint: 'Sharing group' },
  { value: 5, label: 'Inherit',     hint: 'Inherit from event' },
];

const picker = makeEnumPicker({
  key: 'distribution_filter',
  label: 'Distribution',
  levels: LEVELS_DEFINITION,
  valueAttr: 'data-distribution-level',
  rootClass: 'misp-distribution-filter',
  togglesClass: 'misp-enum-toggles',
  toggleClass: 'misp-enum-toggle',
  helpText: 'Filter events by distribution level. Empty selection = no filter (any level matches).',
});

export const KEY = picker.KEY;
export const LABEL = picker.LABEL;
export const LEVELS = picker.LEVELS;
export const equal = picker.equal;
export const displayLabel = picker.displayLabel;
export const buildField = picker.buildField;
export const readValue = picker.readValue;
