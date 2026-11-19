"""C2: database-per-tenant isolation. A user in tenant X cannot see tenant Y's data."""
import re

from soc.agent.incidents import Incident
from soc.agent.store import connect, connect_tenant, create_user, save_incidents, tenant_db_path
from soc.decision.models import Proposal
from soc.web.auth import hash_password
from tests.test_web import make_client


def _incident(base, tenant, title):
    conn = connect_tenant(base, tenant)
    inc = Incident(f"k-{tenant}", title, "high", "2026-11-17T10:00:00.000+0000", "2026-11-17T10:01:00.000+0000",
                   ["a1"], [Proposal("investigate", "x", "high", "brute_force", "why")], [], [])
    save_incidents(conn, [inc]); conn.close()
    return inc.id


def test_tenants_are_separate_files(tmp_path):
    base = tmp_path / "soc.db"
    assert tenant_db_path(base, "default") == base                       # default keeps the main DB
    assert tenant_db_path(base, "acme") == base.parent / "tenants" / "acme.db"
    assert tenant_db_path(base, "../evil") == base                       # invalid name falls back, no traversal


def test_incidents_do_not_leak_across_tenants(tmp_path):
    base = tmp_path / "soc.db"
    # seed users in the shared control DB (both tenants), then put one incident in each tenant's DB
    c = connect(base)
    create_user(c, "dana", hash_password("pw-dana"), "analyst", "default")
    create_user(c, "amir", hash_password("pw-amir"), "analyst", "acme")
    c.close()
    def_id = _incident(base, "default", "DEFAULT brute force")
    acme_id = _incident(base, "acme", "ACME brute force")

    dana = make_client(base, name="dana", tenant="default")
    amir = make_client(base, name="amir", tenant="acme")

    dpage = dana.get("/queue?all=1").get_data(as_text=True)
    apage = amir.get("/queue?all=1").get_data(as_text=True)
    assert "DEFAULT brute force" in dpage and "ACME brute force" not in dpage
    assert "ACME brute force" in apage and "DEFAULT brute force" not in apage
    # and you can't reach the other tenant's incident by id
    assert dana.get(f"/incident/{acme_id}").status_code == 404
    assert amir.get(f"/incident/{def_id}").status_code == 404


def test_auth_is_shared_but_data_is_not(tmp_path):
    base = tmp_path / "soc.db"
    c = connect(base); create_user(c, "amir", hash_password("pw-amir"), "analyst", "acme"); c.close()
    # amir authenticates against the shared control DB even though his data lives in acme.db
    amir = make_client(base, name="amir", tenant="acme", login=True)
    assert amir.get("/").status_code == 200
    # his tenant DB is a different file from the control/default DB
    assert tenant_db_path(base, "acme") != base
