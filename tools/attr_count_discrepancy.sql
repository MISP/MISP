-- Show discrepancies in attributes count
select
    event_id,
    attribute_count wrong_count,
    c as correct_count
from
    events e
inner join (
    select
        event_id, 
        count(event_id) c
    from
        attributes
    where
        deleted=0
    group by
        event_id
    ) a
on
    e.id=a.event_id
where
    attribute_count!=c
order by
    id desc
;

-- Fix discrepancies in attributes count
update
    events e
inner join (
    select
        event_id,
        count(event_id) c
    from
        attributes
    where
        deleted=0
    group by
        event_id
    ) a
on
    e.id=a.event_id
set
	attribute_count=c
where
    attribute_count!=c
;
