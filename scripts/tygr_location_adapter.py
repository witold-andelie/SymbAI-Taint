"""Python 3.8 external DWARF4 list-base adapter; no model or project imports."""

REVISION = 'dwarf4_cu_or_selected_base_v22_1'
VARIANT = 'external_dwarf4_location_base_adapter_v22_1'
LEGACY_ENTRY_FIELDS = ('entry_offset', 'begin_offset', 'end_offset', 'loc_expr')
MODERN_ENTRY_FIELDS = ('entry_offset', 'entry_length', 'begin_offset', 'end_offset', 'loc_expr', 'is_absolute')
LEGACY_BASE_FIELDS = ('entry_offset', 'base_address')
MODERN_BASE_FIELDS = ('entry_offset', 'entry_length', 'base_address')


def validate_api(api):
    if (not isinstance(api, dict) or set(api) != {'location_fields', 'base_fields', 'expression_fields'}
            or any(type(value) is not list for value in api.values())
            or api['expression_fields'] != ['loc_expr']
            or (tuple(api['location_fields']), tuple(api['base_fields'])) not in (
                (LEGACY_ENTRY_FIELDS, LEGACY_BASE_FIELDS), (MODERN_ENTRY_FIELDS, MODERN_BASE_FIELDS))):
        raise ValueError('Unsupported pyelftools location entry layout')
    return api


def location_api(location_type, base_type, expression_type):
    return validate_api({'location_fields': list(getattr(location_type, '_fields', ())),
        'base_fields': list(getattr(base_type, '_fields', ())),
        'expression_fields': list(getattr(expression_type, '_fields', ()))})


def resolve_entries(entries, cu_base, address_size, location_type, base_type):
    """Retain entry order/overlap; explicit base selections affect only this list."""
    fields = tuple(getattr(location_type, '_fields', ()))
    pair = fields, tuple(getattr(base_type, '_fields', ()))
    if pair not in ((LEGACY_ENTRY_FIELDS, LEGACY_BASE_FIELDS), (MODERN_ENTRY_FIELDS, MODERN_BASE_FIELDS)):
        raise ValueError('Unsupported pyelftools location entry layout')
    if type(address_size) is not int or address_size not in (4, 8):
        raise ValueError('Unsupported DWARF address size')
    limit = 1 << (8 * address_size)

    def address(value):
        if type(value) is not int or not 0 <= value < limit:
            raise ValueError('Invalid location address')
        return value

    base = address(cu_base) if cu_base is not None else None
    resolved, trace = [], []
    for item in entries:
        if isinstance(item, base_type):
            base = address(item.base_address)
            trace.append({'kind': 'base_selection', 'base': base})
            continue
        if not isinstance(item, location_type):
            raise ValueError('Unrecognized DWARF4 location entry')
        # pyelftools 0.27 represents .debug_loc entries as relative four-field tuples.
        absolute = item.is_absolute if fields == MODERN_ENTRY_FIELDS else False
        if type(absolute) is not bool:
            raise ValueError('Invalid absolute location flag')
        begin, end = address(item.begin_offset), address(item.end_offset)
        if end < begin:
            raise ValueError('Reversed location range')
        if not absolute and base is None:
            raise ValueError('Relative location entry has no CU or selected base')
        start = address(begin if absolute else base + begin)
        stop = address(end if absolute else base + end)
        trace.append({'kind': 'location', 'raw_range': [begin, end], 'is_absolute': absolute,
                      'active_base': base, 'resolved_range': [start, stop], 'zero_length': start == stop})
        if start != stop:
            updates = {'begin_offset': start, 'end_offset': stop}
            if fields == MODERN_ENTRY_FIELDS:
                updates['is_absolute'] = True
            resolved.append(item._replace(**updates))
    return resolved, trace


class _ParsedList:
    def __init__(self, parsed):
        self.parsed = parsed

    def parse_from_attribute(self, *args, **kwargs):
        return self.parsed


def install(location, lookup, record, record_error=None):
    """Delegate to unchanged expression handlers with already-absolute list ranges.

    For lists only, pass zero as the legacy heuristic base so it cannot add the
    function start again. A LocationExpr uses the original parser and bounds.
    """
    api = location_api(location.LocationEntry, location.BaseAddressEntry, location.LocationExpr)
    for name in ('die_location_list', 'struct_die_location_list'):
        original = getattr(location, name)
        if getattr(lookup, name) is not original:
            raise ValueError('Unexpected original location lookup binding')

    def wrap(original, structured):
        def translate(*args):
            die_index = 1 if structured else 0
            die, parser = args[die_index:die_index + 2]
            if 'DW_AT_location' not in die.attributes:
                return original(*args)
            # Preserve the unchanged struct-member early-return condition too.
            if structured and 'DW_AT_data_member_location' not in args[0].attributes:
                return original(*args)
            if die.cu['version'] != 4:
                raise ValueError('Adapter scope is DWARF4 only')
            parsed = parser.parse_from_attribute(die.attributes['DW_AT_location'], 4)
            if not isinstance(parsed, list):
                if not isinstance(parsed, location.LocationExpr):
                    raise ValueError('Unrecognized location description')
                record({'kind': 'single_expression', 'die_offset': die.offset,
                        'function_range': list(args[-1]), 'unchanged': True})
                return original(*args)
            attr = die.cu.get_top_DIE().attributes.get('DW_AT_low_pc')
            cu_base = attr.value if attr is not None else None
            resolved, trace = resolve_entries(parsed, cu_base, die.cu['address_size'],
                location.LocationEntry, location.BaseAddressEntry)
            record({'kind': 'location_list', 'die_offset': die.offset, 'cu_offset': die.cu.cu_offset,
                    'cu_base': cu_base, 'function_range': list(args[-1]), 'entries': trace})
            delegated = list(args)
            delegated[die_index + 1] = _ParsedList(resolved)
            delegated[-1] = (0, 0)
            return original(*delegated)

        def adapted(*args):
            try:
                return translate(*args)
            except Exception as error:
                if record_error is not None:
                    die = args[1 if structured else 0]
                    record_error({'die_offset': getattr(die, 'offset', None),
                        'function_range': list(args[-1]), 'structured': structured,
                        'error_type': type(error).__name__, 'message': str(error)})
                raise
        return adapted

    for name, structured in (('die_location_list', False), ('struct_die_location_list', True)):
        adapted = wrap(getattr(location, name), structured)
        setattr(location, name, adapted)
        setattr(lookup, name, adapted)
    return api
