import os
import subprocess
import crypt

GROUPS_PATH = '/etc/group'
PASSWD_PATH = '/etc/passwd'
SHADOW_PATH = '/etc/shadow'

_group_by_gid = {}
_group_by_name = {}
_user_by_uid = {}
_user_by_name = {}

## Helpers

def _obs_get(key):
    def _getter(self):
        return getattr(self, key)

    return _getter

def _obs_set(key, on_change):
    def _setter(self, value):
        old = getattr(self, key)
        if value != old:
            setattr(self, key, value)
            self._dirty = True

            if on_change:
                _obs_change = on_change.__get__(self)
            elif hasattr(self, '_obs_change'):
                _obs_change = getattr(self, '_obs_change')
            
            if _obs_change:
                _obs_change(key, old, value)


    return _setter

def obs_property(key, on_change=None):
    """Simple observer property wrapper and wrist saver.
    Returns a property with generated getter and setter which
    tracks when a property value changes. A _dirty field flag
    will be set on value changes."""

    return property(_obs_get(key), _obs_set(key, on_change), None, '')


## Group Module API

def _groups_reader(fn):
    global _group_by_gid, _group_by_name
    """Reads and caches the /etc/group file containing system groups
    while allowing the fn callback to process group information"""

    # process group file
    name_found = []
    with open(GROUPS_PATH, 'r') as gh:
        for line in gh.readlines():
            name, passwd, gid, users = line.strip().split(':')
            name_found.append(name)

            # check if we've already cached this group
            grp = _group_by_gid.get(gid, False)

            # else create a new Group instance
            if not grp:
                grp = Group(name, passwd, int(gid), users.split(','))
            
            if fn:
                fn(grp)

    # let callback know about new groups
    for name, grp in _group_by_name.items():
        if grp.gid is None:
            name_found.append(grp.name)
            if fn:
                fn(grp)

    # find groups removed by system since last read
    to_delete = [ grp for name, grp in _group_by_name.items() \
            if name not in name_found and \
                grp.gid is not None and \
                _group_by_gid.get(grp.gid, False) \
            ]

    # remove from cache
    for grp in to_delete:
        del _group_by_gid[grp.gid]
        del _group_by_name[grp.name]


def refresh_groups():
    """Forces recreating group caches"""
    _groups_reader(None)

def groups_as_list():
    """Reloads groups cache and creates a list of groups.
    Groups which are not saved yet are also included.
    """

    groups = []
    def _create_list(grp):
        groups.append(grp)

    _groups_reader(_create_list)
    return groups
    
def groups_as_dict(key="name"):
    """Reloads groups cache and creates a dictionary of groups.
    Groups which are not saved yet are also included."""

    groups = {}
    def _create_dict(grp):
        groups[getattr(grp, key)] = grp
        return True

    _groups_reader(_create_dict)
    return groups

def group_by_gid(gid):
    """Gets a group by its gid"""

    refresh_groups()
    return _group_by_gid.get(gid, None)

def group_by_name(name, create=False):
    """Gets a group by its name"""

    refresh_groups()
    grp = _group_by_name.get(name, None)
    if grp is None and create:
        grp = Group.new_group(name)

    return grp

def _groups_writer():
    """Saves all groups in cache"""

    refresh_groups()
    group_list = groups_as_list()

    for grp in group_list:
        if grp.gid == None:
            # find latest available gid
            gid = -1
            for tmp_grp in group_list:
                # get largest group id except the 'nogroup' gid
                if tmp_grp.gid is not None and \
                    tmp_grp.gid > gid and \
                    tmp_grp.gid != 65534:
                    gid = tmp_grp.gid

            grp.gid = gid + 1 # next gid

    new_group_src = []
    with open("/tmp/group", "w") as gh:
        for grp in group_list:
            line = "{0}:{1}:{2}:{3}\n".format(grp.name, grp.passwd, grp.gid, ','.join(grp.users))
            gh.write(line)

## User Module API

def _passwd_reader(fn):

    name_found = []
    with open(PASSWD_PATH, 'r') as gh:
        for line in gh.readlines():
            name, passwd, uid, gid, description, home_path, shell = line.strip().split(':')
            name_found.append(name)
            usr = _user_by_uid.get(uid, None)
            if not usr:
                usr = User(name, passwd, uid, gid, description, home_path, shell)

            if fn:
                fn(usr)

    for name, usr in _user_by_name.items():
        if usr.uid is None:
            name_found.append(usr.name)
            if fn:
                fn(usr)
    
    to_delete = [ usr for name, usr in _user_by_name.items() \
            if name not in name_found and \
                usr.gid is not None and \
                _user_by_uid.get(usr.uid, False) \
            ]

    for usr in to_delete:
        del _user_by_uid[usr.uid]
        del _user_by_name[usr.name]

def refresh_users():
    _user_reader(None)

def users_as_list():

    users = []
    def _create_list(usr):
        users.append(usr)

    _user_reader(_create_list)

    return users

def users_as_dict(key='name'):

    users = {}
    def _create_dict(usr):
        users[getattr(usr, key)] = usr

    _user_reader(_create_dict)

    return users

def user_by_uid(uid):

    refresh_users()
    return _user_by_uid.get(uid, None)

def user_by_name(name, create_homedir=False, create=False):

    refresh_users()
    usr = _user_by_name.get(name, None)
    if usr is None and create:
        usr = User.new_user(name)
        if not os.path.exists(usr.home_path):
            mkhomedir(usr.name)

    return usr

def mkhomedir(username):
    p = subprocess.Popen(['mkhomedir_helper', username])
    p.wait()
    return os.path.exists('/home/%s' % username):

def _user_writer():
    pass

## OO API

class Group:

    @classmethod
    def new_group(cls, name):
        """Creates a new group"""
        group = Group(name)
        group.save()

        return group

    def __init__(self, name, passwd='x', gid=None, users=[]):
        """Do not directly create a group instance unless you know 
        what you are doing."""

        assert gid is None or isinstance(gid, int), "GID must be an int"
        assert isinstance(users, list), "users parameter must be a list of str names"
        assert _group_by_name.get(name, False), "Group already exists"
        assert gid is None or _group_by_gid.get(gid, False), "GID Must not already exist in cache"

        self.name = name
        self.passwd = passwd
        self.gid = gid
        self.users=users

        _group_by_name[name] = self
        if self.gid is not None:
            _group_by_gid[gid] = self

    def save(self):
        _groups_writer()

class User:

    @staticmethod
    def new_user(name, create_homedir):
        usr = User(name)
        usr.save()

        return usr

    name = obs_property('_name')
    uid = obs_property('_uid')
    pid = obs_property('_pid')
    description = obs_property('_description')
    home_path = obs_property('_home_path')
    shell = obs_property('_shell')

    def __init__(self, name, passwd='x', uid=None, gid=None, description=None, home_path=None, shell=None):

        assert uid is None or isinstance(gid, int), "UID must be an int"
        assert _user_by_name.get(name, False), "User alrady exists"
        assert uid is None or _user_by_uid.get(uid, False), "UID Must not already exist in cache"

        self._name = name
        self._passwd = passwd
        self._uid = uid
        self._gid = gid
        self._description = None
        self._home_path = home_path
        self._dirty = False

        if self._home_path is None:
            self._home_path = os.path.abspath(os.path.join('home', self.name))

        self._shell = shell

    def disable(self):
        self._passwd = '*'
        self._dirty = True

    def enable(self):
        self._passwd = 'x'
        self._dirty = True

    def set_passwd(self, passwd):
        self._passwd = 'x'
        self._passwd_hash = crypt.crypt(passwd, crypt.mksalt(crypt.METHOD_SHA512))

    def save(self):
        _user_writer()
        self._dirty = False
