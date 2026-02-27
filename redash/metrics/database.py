import logging
import time

from flask import g, has_request_context
from sqlalchemy.engine import Engine
from sqlalchemy.event import listens_for
from sqlalchemy.orm.util import _ORMJoin
from sqlalchemy.sql.selectable import Alias, Join, Subquery

from redash import statsd_client

metrics_logger = logging.getLogger("metrics")


def _first_from(froms):
    """Return froms[0], or raise AttributeError if the list is empty.

    Both get_final_froms() and .froms always return sequences, so IndexError
    (empty list) is the only failure mode. We convert it to AttributeError so
    all "can't extract table name" cases surface as a single exception type to
    the caller.
    """
    if not froms:
        raise AttributeError("Cannot extract table name from this query type")
    return froms[0]


def _table_name_from_select_element(elt):
    froms = elt.get_final_froms() if hasattr(elt, 'get_final_froms') else elt.froms
    t = _first_from(froms)

    # Unwrap nested Subqueries and Aliases - keep processing until we get to a Table
    # Add iteration limit to prevent infinite loops on pathological queries
    max_unwrap_depth = 10
    unwrap_iterations = 0

    while isinstance(t, (Alias, Subquery)) and unwrap_iterations < max_unwrap_depth:
        unwrap_iterations += 1

        # Handle Subquery (either direct or as t in the loop)
        if isinstance(t, Subquery):
            if hasattr(t, 'element'):
                element = t.element
                if hasattr(element, 'get_final_froms'):
                    t = _first_from(element.get_final_froms())
                elif hasattr(element, 'froms'):
                    t = _first_from(element.froms)
                else:
                    raise AttributeError("Cannot extract table name from this query type")
            else:
                raise AttributeError("Cannot extract table name from this query type")
        # Handle Alias types (e.g., table aliases)
        elif isinstance(t, Alias):
            if hasattr(t.original, 'get_final_froms'):
                t = _first_from(t.original.get_final_froms())
            elif hasattr(t.original, 'froms'):
                t = _first_from(t.original.froms)
            else:
                # For table aliases, t.original is the table itself
                t = t.original
                break  # Exit the loop since we've extracted the table

    if unwrap_iterations >= max_unwrap_depth:
        raise AttributeError(f"Cannot extract table name - query nested too deeply (>{max_unwrap_depth} levels)")

    while isinstance(t, _ORMJoin) or isinstance(t, Join):
        t = t.left

    return t.name


@listens_for(Engine, "before_execute")
def before_execute(conn, elt, multiparams, params, execution_options):
    conn.info.setdefault("query_start_time", []).append(time.time())


@listens_for(Engine, "after_execute")
def after_execute(conn, elt, multiparams, params, execution_options, result):
    duration = 1000 * (time.time() - conn.info["query_start_time"].pop(-1))
    action = elt.__class__.__name__

    if action == "Select":
        name = "unknown"
        try:
            name = _table_name_from_select_element(elt)
        except AttributeError:
            # Expected for subqueries and other query types without extractable table names
            pass
        except Exception:
            logging.exception("Failed finding table name.")
    elif action in ["Update", "Insert", "Delete"]:
        name = elt.table.name
    else:
        # create/drop tables, sqlalchemy internal schema queries, etc
        return

    action = action.lower()

    statsd_client.timing("db.{}.{}".format(name, action), duration)
    metrics_logger.debug("table=%s query=%s duration=%.2f", name, action, duration)

    if has_request_context():
        g.setdefault("queries_count", 0)
        g.setdefault("queries_duration", 0)
        g.queries_count += 1
        g.queries_duration += duration

    return result
