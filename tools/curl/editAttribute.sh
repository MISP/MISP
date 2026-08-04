#curl -H "Accept: application/xml" -H "content-type: text/xml" -H "Authorization: vlf4o42bYSVVWLm28jLB85my4HBZWXTri8vGdySb" \
#--data "@input/event.xml" -X PUT http://localhost/attributes/14'

# POST can be used as well..
curl -i -H "Accept: application/xml" -H "content-type: text/xml" -H "Authorization: vlf4o42bYSVVWLm28jLB85my4HBZWXTri8vGdySb" \
--data "@input/215.xml" -X POST http://localhost/attributes/215	# 116	# 33525
