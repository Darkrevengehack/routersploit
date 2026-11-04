import importlib.resources as resources

defaults = 'file://' + str(resources.files(__name__) / 'defaults.txt')
passwords = 'file://' + str(resources.files(__name__) / 'passwords.txt')
usernames = 'file://' + str(resources.files(__name__) / 'usernames.txt')
snmp = 'file://' + str(resources.files(__name__) / 'snmp.txt')
