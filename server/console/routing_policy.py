"""Pure service-routing policy. No network, filesystem or privileged operations."""
from copy import deepcopy

SERVICES = {'hysteria': 'Hysteria 2', 'trusttunnel': 'TrustTunnel / R-TrustTunnel', 'cdn': 'VLESS через CDN',
            'amnezia': 'AmneziaWG'}
# Exception-mirroring services: they copy the Hysteria ACL into their own router.
RELAYS = ('trusttunnel', 'cdn', 'amnezia')
EXITS = ('primary', 'reserve')


class PolicyError(ValueError):
    """A safe, user-facing validation or concurrency error."""


def validate_request(data):
    if not isinstance(data, dict) or set(data) != {'revision', 'group_exit', 'services'}:
        raise PolicyError('Некорректные параметры маршрутизации')
    revision = data['revision']
    if not isinstance(revision, str) or len(revision) != 64 or any(c not in '0123456789abcdef' for c in revision):
        raise PolicyError('Обновите состояние маршрутов')
    if data['group_exit'] not in EXITS:
        raise PolicyError('Неизвестный общий выход')
    if not isinstance(data['services'], dict) or not set(data['services']) <= SERVICES.keys():
        raise PolicyError('Неизвестный сервис; системные маршруты менять нельзя')
    for value in data['services'].values():
        validate_mode(value)
    return deepcopy(data)


def validate_mode(value):
    if not isinstance(value, dict):
        raise PolicyError('Некорректный режим сервиса')
    mode = value.get('mode')
    if mode in ('follow', 'direct') and set(value) == {'mode'}:
        return
    if mode == 'pinned' and set(value) == {'mode', 'exit'} and value['exit'] in EXITS:
        return
    raise PolicyError('Выберите общий маршрут, свой выход или прямое подключение')


def target(value, group_exit):
    return group_exit if value['mode'] == 'follow' else value.get('exit', 'direct')


def initial_policy(actual):
    group = actual.get('hysteria') if actual.get('hysteria') in EXITS else 'primary'
    services = {}
    for name in SERVICES:
        current = actual.get(name, 'unknown')
        if name == 'hysteria' and current in EXITS:
            services[name] = {'mode': 'follow'}
        elif current in EXITS:
            services[name] = {'mode': 'pinned', 'exit': current}
        elif current == 'direct':
            services[name] = {'mode': 'direct'}
        else:
            services[name] = {'mode': 'unmanaged'}
    return {'schema': 1, 'group_exit': group, 'services': services}


def validate_saved(policy, defaults=None):
    """`defaults` (an initial policy) fills services added after the policy was saved."""
    if not isinstance(policy, dict) or set(policy) != {'schema', 'group_exit', 'services'} or policy['schema'] != 1:
        raise PolicyError('Повреждена сохранённая политика; требуется проверка оператора')
    if policy['group_exit'] not in EXITS or not isinstance(policy['services'], dict) or not set(policy['services']) <= set(SERVICES):
        raise PolicyError('Повреждена сохранённая политика; требуется проверка оператора')
    policy = deepcopy(policy)
    for name in SERVICES.keys() - policy['services'].keys():
        if defaults is None:
            raise PolicyError('Повреждена сохранённая политика; требуется проверка оператора')
        policy['services'][name] = deepcopy(defaults['services'][name])
    for value in policy['services'].values():
        if value != {'mode': 'unmanaged'}:
            validate_mode(value)
    return deepcopy(policy)


def make_plan(data, snapshot):
    """A policy edit never silently reconciles an excluded service's drift."""
    data = validate_request(data)
    if data['revision'] != snapshot['revision']:
        raise PolicyError('Маршруты изменились. Обновите страницу и подтвердите новый план.')
    before = validate_saved(snapshot['saved'])
    after = deepcopy(before)
    after['group_exit'] = data['group_exit']
    after['services'].update(data['services'])
    changes, untouched = [], []
    for name, title in SERVICES.items():
        old_mode, new_mode = before['services'][name], after['services'][name]
        service = snapshot['services'][name]
        # Only a changed setting or a changed shared route enrolls a service.
        enrolled = old_mode != new_mode or (new_mode['mode'] == 'follow' and before['group_exit'] != after['group_exit'])
        desired = target(new_mode, after['group_exit']) if new_mode['mode'] != 'unmanaged' else service['actual_exit']
        enrolled = enrolled or (name in data['services'] and desired != service['actual_exit'])
        if enrolled:
            if not service['configurable']:
                raise PolicyError(title + ': ' + service['reason'])
            if desired not in service['available_exits']:
                raise PolicyError(title + ': выход не подготовлен')
            changes.append({'id': name, 'title': title, 'before': service['actual_exit'], 'after': desired,
                            'mode_before': old_mode['mode'], 'mode_after': new_mode['mode'],
                            'restart': service['actual_exit'] != desired})
        else:
            untouched.append({'id': name, 'title': title, 'exit': service['actual_exit']})
    if after == before and not changes:
        raise PolicyError('Изменений нет. Выбранные маршруты уже используются.')
    return {'policy': after, 'changes': changes, 'untouched': untouched,
            'control_plane': 'direct', 'revision': snapshot['revision']}
