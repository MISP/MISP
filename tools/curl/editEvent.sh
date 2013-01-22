#curl -H "Accept: application/xml" -H "content-type: text/xml" -H "Authorization: vlf4o42bYSVVWLm28jLB85my4HBZWXTri8vGdySb" \
#--data "@input/event.xml" -X PUT http://localhost/events/14'

# POST can be used as well..
curl -i -H "Accept: application/xml" -H "content-type: text/xml" -H "Authorization: vlf4o42bYSVVWLm28jLB85my4HBZWXTri8vGdySb" \
--data "@input/event.xml" -X POST http://localhost/events/$1
