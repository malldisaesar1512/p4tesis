import collections
import routeros_api
from routeros_api.api_structure import StringField

connection = routeros_api.RouterOsApiPool('10.10.1.1', username='admin', password='123', plaintext_login=True)
api = connection.get_api()
# This part here is important:
default_structure = collections.defaultdict(lambda: StringField(encoding='windows-1250'))
api.get_resource('/system/identity', structure=default_structure).get()