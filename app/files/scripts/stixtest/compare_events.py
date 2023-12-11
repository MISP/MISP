import json
import sys
from collections import defaultdict
from pymisp import MISPEvent

class Comparer():
    def __init__(self, filename1, filename2):
        event1 = MISPEvent()
        event1.load_file(filename1)
        event2 = MISPEvent()
        event2.load_file(filename2)
        self.__jq_misp_event(filename2)
        self.tags1 = defaultdict(set)
        self.tags2 = defaultdict(set)
        self.galaxies1 = defaultdict(set)
        self.galaxies2 = defaultdict(set)
        self.references1 = {}
        self.references2 = {}
        self.pe1 = defaultdict(list)
        self.attributes1 = self._get_attributes(event1, '1')
        self.attributes2 = self._get_attributes(event2, '2')
        self.objects1 = self._get_objects(event1, '1')
        self.objects2 = self._get_objects(event2, '2')
        self._get_galaxies_and_tags(event1, '1')
        self._get_galaxies_and_tags(event2, '2')

    def _analyse_object(self, object, uuid, first, second):
        for object_relation, values in object['attributes'].items():
            if object_relation not in getattr(self, f'objects{second}')[uuid]['attributes']:
                print(f'Object attribute(s) {object_relation} from object {object["name"]} is in the object from the event {first} but not in the object from the event {second}.')
                continue
            if any(value not in getattr(self, f'objects{second}')[uuid]['attributes'][object_relation] for value in values):
                print(f'Differences in object {object["name"]} for object relation {object_relation}:\nthe following values are in the event {first}: {values},\nwhere the following ones are in the event {second}: {getattr(self, f"objects{second}")[uuid]["attributes"][object_relation]}')

    def compare_attributes(self):
        self._compare_attributes('2', '1')
        self._compare_attributes('1', '2')

    def _compare_attributes(self, first, second):
        print(f'Comparing attributes from event {second}')
        for uuid, attribute in getattr(self, f'attributes{first}').items():
            if uuid not in getattr(self, f'attributes{second}'):
                print(f'Attribute identified by {uuid}, {attribute[1]} of type {attribute[0]} is in the event {first} event but not in the event {second}.')
        print()

    def compare_galaxies(self):
        self._compare_galaxies('2', '1')
        self._compare_galaxies('1', '2')

    def _compare_galaxies(self, first, second):
        print(f'Comparing galaxies from event {second}:')
        for uuid, galaxies in getattr(self, f'galaxies{first}').items():
            if uuid not in getattr(self, f'galaxies{second}'):
                print(f'Galaxies attached to object with uuid {uuid} in event {first} do not exist in event {second}.')
                continue
            for galaxy in galaxies:
                if galaxy not in getattr(self, f'galaxies{second}')[uuid]:
                    print(f'Galaxy {galaxy} attached to object with uuid {uuid} is missing in event {second}.')
        print()

    def compare_objects(self):
        self._compare_objects('2', '1')
        self._compare_objects('1', '2')

    def _compare_objects(self, first, second):
        print(f'Comparing object from event {second}:')
        for uuid, object in getattr(self, f'objects{first}').items():
            if uuid not in getattr(self, f'objects{second}'):
                print(f'Object identified by {uuid}, {object["name"]} is in the event {first} but not in the event {second}.')
                continue
            if object['name'] == 'file' and uuid in getattr(self, f'references{first}'):
                self._iterate_through_pe_and_sections(uuid, first, second)
            self._analyse_object(object, uuid, first, second)
        print()

    def compare_references(self):
        self._compare_references('2', '1')
        self._compare_references('1', '2')

    def _compare_references(self, first, second):
        print(f'Comparing references from event {second}:')
        for uuid, references in getattr(self, f'references{first}').items():
            if uuid not in getattr(self, f'references{second}'):
                print(f'References from MISPObject with uuid {uuid} is in the event {first} but not in the event {second}.')
                continue
            for reference in references:
                if reference not in getattr(self, f'references{second}'):
                    print(f'Reference {reference} from MISPObject with uuid {uuid} is missing in event {second}.')
        print()

    def compare_tags(self):
        self._compare_tags('2', '1')
        self._compare_tags('1', '2')

    def _compare_tags(self, first, second):
        print(f'Comparing tags from event {second}:')
        for uuid, tags in getattr(self, f'tags{first}').items():
            if uuid not in getattr(self, f'tags{second}'):
                print(f'Tags attached to object with uuid {uuid} in event {first} do not exist in event {second}.')
                continue
            for tag in tags:
                if tag not in getattr(self, f'tags{second}')[uuid]:
                    print(f'Tag {tag} attached to object with uuid {uuid} is missing in event {second}.')
        print()

    def _get_attributes(self, event, n):
        attributes = {}
        for attribute in event.attributes:
            attributes[attribute.uuid] = (attribute.type, attribute.value)
            self._get_galaxies_and_tags(attribute, n)
        return attributes

    def _get_galaxies_and_tags(self, level, n):
        if 'Tag' in level:
            for tag in level['Tag']:
                tag_name = tag['name']
                if tag_name.startswith('misp-galaxy:'):
                    getattr(self, f'galaxies{n}')[level.uuid].add(tag_name)
                else:
                    getattr(self, f'tags{n}')[level.uuid].add(tag_name)
        if 'Galaxy' in level:
            for galaxy in level['Galaxy']:
                for cluster in galaxy['GalaxyCluster']:
                    getattr(self, f'galaxies{n}')[level.uuid].add(cluster['tag_name'])

    def _get_objects(self, event, n):
        to_return = {}
        for object in event.objects:
            object_dict = {'name': object.name}
            attributes = defaultdict(list)
            for attribute in object.attributes:
                attributes[attribute.object_relation].append(attribute.value)
            object_dict['attributes'] = attributes
            to_return[object.uuid] = object_dict
            if 'ObjectReference' in object and object['ObjectReference']:
                getattr(self, f'references{n}')[object.uuid] = tuple((reference['referenced_uuid'], reference['relationship_type']) for reference in object['ObjectReference'])
        return to_return

    def _iterate_through_pe_and_sections(self, origin_uuid, first, second, uuid2=None):
        if uuid2 is None:
            uuid2 = origin_uuid
        included_types = ('pe', 'pe-section')
        for reference1, reference2 in zip(getattr(self, f'references{first}')[origin_uuid], getattr(self, f'references{second}')[uuid2]):
            uuid1, relationship1 = reference1
            uuid2, relationship2 = reference2
            if uuid1 in getattr(self, f'objects{first}') and getattr(self, f'objects{first}')[uuid1]['name'] in included_types:
                if uuid2 not in getattr(self, f'objects{second}') or getattr(self, f'objects{second}')[uuid2]['name'] not in included_types:
                    print(f'The references of the object {origin_uuid} are not the same in event {first} and {second}')
                    continue
                if relationship1 != relationship2:
                    print(f'The references of the object {origin_uuid} do not have the same relationship type: {relationship1} in event {first} and {relationship2} in event {second}')
                    continue
                object = getattr(self, f'objects{first}')[uuid1]
                self._analyse_object(object, uuid2, first, second)
                if object['name'] == 'pe' and uuid1 in getattr(self, f'references{first}'):
                    self._iterate_through_pe_and_sections(uuid1, first, second, uuid2)

    @staticmethod
    def __jq_misp_event(filename):
        with open(filename, 'rt', encoding='utf-8') as f:
            json_event = json.loads(f.read())
        with open(filename, 'wt', encoding='utf-8') as f:
            f.write(json.dumps(json_event, indent=4))

def main(args):
    comparer = Comparer(*args[1:])
    comparer.compare_attributes()
    comparer.compare_objects()
    comparer.compare_tags()
    comparer.compare_galaxies()
    comparer.compare_references()

if __name__ == '__main__':
    main(sys.argv)
