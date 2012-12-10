#curl -H "Accept: application/xml" -H "content-type: text/xml" -H "Authorization: vlf4o42bYSVVWLm28jLB85my4HBZWXTri8vGdySb" \
#--data "@input/event.xml" -X PUT http://localhost/events/14'
#http://bel_mod1.local.net:80/events/29

# POST can be used as well..
curl -H "Accept: application/xml" -H "content-type: text/xml" -H "Authorization: vlf4o42bYSVVWLm28jLB85my4HBZWXTri8vGdySb" \
--data "@input/33529.xml" -X POST http://localhost/attributes/33529
