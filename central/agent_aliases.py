"""Two-character display names for registered agents. IDs remain immutable."""
import re
import sqlite3

SHORT_RE = re.compile(r"^[A-Z0-9]{2}$")


def default_short(agent_id):
    letters = ''.join(ch for ch in str(agent_id).upper() if 'A' <= ch <= 'Z')
    return (letters[:2] if len(letters) >= 2 else (letters + 'XX')[:2])


def read_aliases(conn):
    try:
        return {row['agent']: row['short_name'] for row in conn.execute(
            'SELECT agent,short_name FROM agent_short_names')}
    except sqlite3.OperationalError as exc:
        if 'no such table' not in str(exc):
            raise
        return {}


def aliases_for_agents(conn, agent_ids):
    stored = read_aliases(conn)
    return {agent: stored.get(agent, default_short(agent)) for agent in agent_ids}


def set_alias(conn, agent, short_name):
    if not isinstance(agent, str) or not agent or len(agent) > 128:
        raise ValueError('Invalid agent ID')
    if not isinstance(short_name, str):
        raise ValueError('Short name must be a string')
    short_name = short_name.strip().upper()
    if short_name and not SHORT_RE.fullmatch(short_name):
        raise ValueError('Short name must be exactly two letters or digits')
    found = conn.execute('SELECT 1 FROM agent_seen WHERE agent=?', (agent,)).fetchone()
    if not found:
        raise ValueError('Unknown agent')
    if short_name:
        conflict = conn.execute('SELECT agent FROM agent_short_names WHERE short_name=? AND agent<>?',
                                (short_name, agent)).fetchone()
        # Also avoid clashes with automatic aliases of other active agents.
        all_agents = [row['agent'] for row in conn.execute('SELECT agent FROM agent_seen')]
        effective = aliases_for_agents(conn, all_agents)
        for other, value in effective.items():
            if other != agent and value == short_name:
                raise ValueError('Short name is already used by ' + other)
        if conflict:
            raise ValueError('Short name is already assigned')
        conn.execute('INSERT INTO agent_short_names(agent,short_name) VALUES(?,?) '
                     'ON CONFLICT(agent) DO UPDATE SET short_name=excluded.short_name',
                     (agent, short_name))
    else:
        conn.execute('DELETE FROM agent_short_names WHERE agent=?', (agent,))
    return short_name or default_short(agent)
