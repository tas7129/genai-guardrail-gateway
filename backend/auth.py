"""Demo identities and role-based access.

Hackathon simplification: users pick a demo identity in the sidebar and the
browser sends it in the `X-Demo-User` header. Every permission check below is
still enforced on the server – the UI only hides what the server would refuse.
In production this module would be replaced by SSO (OIDC/SAML) claims.
"""
from __future__ import annotations

from typing import List, Optional

USERS = {
    "asha": {"id": "asha", "name": "Asha Rao", "role": "employee", "team": "Engineering",
             "title": "Software Engineer", "manager": "rahul"},
    "vikram": {"id": "vikram", "name": "Vikram Shah", "role": "employee", "team": "Sales",
               "title": "Account Executive", "manager": "priya"},
    "rahul": {"id": "rahul", "name": "Rahul Mehta", "role": "manager", "team": "Engineering",
              "title": "Engineering Manager", "manager": "meera"},
    "priya": {"id": "priya", "name": "Priya Nair", "role": "manager", "team": "Sales",
              "title": "Sales Manager", "manager": "meera"},
    "meera": {"id": "meera", "name": "Meera Iyer", "role": "admin", "team": "Governance",
              "title": "Head of AI Governance", "manager": None},
}

DEFAULT_USER = "asha"


class AuthError(Exception):
    status = 403


def get_user(user_id: Optional[str]) -> dict:
    user = USERS.get((user_id or "").strip().lower())
    if not user:
        err = AuthError("unknown demo user")
        err.status = 401
        raise err
    return user


def direct_reports(manager_id: str) -> List[str]:
    return [u["id"] for u in USERS.values() if u.get("manager") == manager_id]


def scope_user_ids(user: dict) -> Optional[List[str]]:
    """Which users' records this user may see. None = everyone (admin)."""
    if user["role"] == "admin":
        return None
    if user["role"] == "manager":
        return direct_reports(user["id"]) + [user["id"]]
    return [user["id"]]


def require_role(user: dict, *roles: str) -> None:
    if user["role"] not in roles:
        raise AuthError("this action requires role: %s" % " or ".join(roles))


def public_user(user: dict) -> dict:
    mgr = USERS.get(user.get("manager") or "")
    return dict(user, manager_name=mgr["name"] if mgr else None)
