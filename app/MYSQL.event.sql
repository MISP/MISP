alter table events add column attribute_count int(11) UNSIGNED DEFAULT NULL;

alter table events add column hop_count int(11) UNSIGNED DEFAULT 0;