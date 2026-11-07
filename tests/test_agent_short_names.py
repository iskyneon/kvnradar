"""Agent label behavior and DB persistence."""
import importlib.util
import sqlite3
from pathlib import Path

spec = importlib.util.spec_from_file_location('agent_aliases', Path(__file__).parents[1] / 'central' / 'agent_aliases.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_defaults():
    assert mod.default_short('timeweb') == 'TI'
    assert mod.default_short('1cloud') == 'CL'
    assert mod.default_short('h3llo') == 'HL'
    assert mod.default_short('reg-ru') == 'RE'


def test_persist_and_reset():
    c=sqlite3.connect(':memory:')
    c.row_factory=sqlite3.Row
    c.executescript('''CREATE TABLE agent_seen(agent TEXT PRIMARY KEY);
    CREATE TABLE agent_short_names(agent TEXT PRIMARY KEY, short_name TEXT NOT NULL UNIQUE);''')
    c.executemany('INSERT INTO agent_seen(agent) VALUES(?)',[('timeweb',),('hetzner',)])
    assert mod.aliases_for_agents(c,['timeweb']) == {'timeweb':'TI'}
    assert mod.set_alias(c,'timeweb','tw') == 'TW'
    assert mod.aliases_for_agents(c,['timeweb']) == {'timeweb':'TW'}
    try: mod.set_alias(c,'hetzner','TW')
    except ValueError: pass
    else: raise AssertionError('collision accepted')
    assert mod.set_alias(c,'timeweb','') == 'TI'
    assert mod.aliases_for_agents(c,['timeweb']) == {'timeweb':'TI'}
    try: mod.set_alias(c,'other','OT')
    except ValueError: pass
    else: raise AssertionError('unknown agent accepted')
    c.close()

if __name__=='__main__':
    test_defaults();test_persist_and_reset();print('agent short name tests OK')
