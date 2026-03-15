#!/usr/bin/env python3
"""
SCIM 2.0 Provisioning Server for Okta Integration

A production-ready SCIM 2.0 server implementation that handles user and group
lifecycle management from Okta. Supports user CRUD, group push, filtering,
pagination, and PATCH operations per RFC 7644.

Requirements:
    pip install flask sqlalchemy
"""

import uuid
import re
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, g
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Table, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

app = Flask(__name__)

DATABASE_URL = "sqlite:///scim_users.db"
SCIM_BEARER_TOKEN = "replace-with-secure-token"
SCIM_BASE_URL = "https://your-app.example.com/scim/v2"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Association table for user-group membership
user_group = Table(
    "user_group", Base.metadata,
    Column("user_id", String, ForeignKey("users.id"), primary_key=True),
    Column("group_id", String, ForeignKey("groups.id"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    userName = Column(String, unique=True, nullable=False)
    givenName = Column(String, default="")
    familyName = Column(String, default="")
    email = Column(String, default="")
    displayName = Column(String, default="")
    active = Column(Boolean, default=True)
    department = Column(String, default="")
    title = Column(String, default="")
    created = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    lastModified = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                          onupdate=lambda: datetime.now(timezone.utc))
    groups = relationship("Group", secondary=user_group, back_populates="members")

    def to_scim(self):
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User",
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
            "id": self.id,
            "userName": self.userName,
            "name": {
                "givenName": self.givenName or "",
                "familyName": self.familyName or "",
                "formatted": f"{self.givenName or ''} {self.familyName or ''}".strip()
            },
            "displayName": self.displayName or f"{self.givenName or ''} {self.familyName or ''}".strip(),
            "emails": [{"value": self.email, "type": "work", "primary": True}] if self.email else [],
            "active": self.active,
            "title": self.title or "",
            "groups": [{"value": g.id, "display": g.displayName} for g in self.groups],
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "department": self.department or ""
            },
            "meta": {
                "resourceType": "User",
                "created": self.created.isoformat() + "Z" if self.created else "",
                "lastModified": self.lastModified.isoformat() + "Z" if self.lastModified else "",
                "location": f"{SCIM_BASE_URL}/Users/{self.id}"
            }
        }


class Group(Base):
    __tablename__ = "groups"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    displayName = Column(String, unique=True, nullable=False)
    created = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    lastModified = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                          onupdate=lambda: datetime.now(timezone.utc))
    members = relationship("User", secondary=user_group, back_populates="groups")

    def to_scim(self):
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": self.id,
            "displayName": self.displayName,
            "members": [{"value": m.id, "display": m.displayName or m.userName} for m in self.members],
            "meta": {
                "resourceType": "Group",
                "created": self.created.isoformat() + "Z" if self.created else "",
                "lastModified": self.lastModified.isoformat() + "Z" if self.lastModified else "",
                "location": f"{SCIM_BASE_URL}/Groups/{self.id}"
            }
        }


Base.metadata.create_all(engine)


def get_db():
    if "db" not in g:
        g.db = SessionLocal()
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def scim_error(detail, status, scim_type=None):
    body = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "detail": detail,
        "status": str(status)
    }
    if scim_type:
        body["scimType"] = scim_type
    return jsonify(body), status


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != SCIM_BEARER_TOKEN:
            return scim_error("Authentication required", 401)
        return f(*args, **kwargs)
    return wrapper


def parse_scim_filter(filter_str):
    """Parse simple SCIM filter expressions like: userName eq 'value'"""
    match = re.match(r'(\w+)\s+eq\s+"([^"]*)"', filter_str)
    if not match:
        match = re.match(r"(\w+)\s+eq\s+'([^']*)'", filter_str)
    if match:
        return match.group(1), match.group(2)
    return None, None


def list_response(resources, total, start_index, count):
    return jsonify({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": count,
        "Resources": resources
    })


# ---- User Endpoints ----

@app.route("/scim/v2/Users", methods=["POST"])
@require_auth
def create_user():
    data = request.json
    db = get_db()

    username = data.get("userName")
    if not username:
        return scim_error("userName is required", 400)

    existing = db.query(User).filter(User.userName == username).first()
    if existing:
        return scim_error(f"User with userName '{username}' already exists", 409, "uniqueness")

    name = data.get("name", {})
    emails = data.get("emails", [])
    enterprise = data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {})

    user = User(
        userName=username,
        givenName=name.get("givenName", ""),
        familyName=name.get("familyName", ""),
        displayName=data.get("displayName", ""),
        email=emails[0].get("value", "") if emails else "",
        active=data.get("active", True),
        department=enterprise.get("department", ""),
        title=data.get("title", ""),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return jsonify(user.to_scim()), 201


@app.route("/scim/v2/Users", methods=["GET"])
@require_auth
def list_users():
    db = get_db()
    start_index = int(request.args.get("startIndex", 1))
    count = int(request.args.get("count", 100))
    filter_str = request.args.get("filter", "")

    query = db.query(User)

    if filter_str:
        attr, value = parse_scim_filter(filter_str)
        if attr == "userName":
            query = query.filter(User.userName == value)
        elif attr == "id":
            query = query.filter(User.id == value)

    total = query.count()
    users = query.offset(start_index - 1).limit(count).all()

    return list_response([u.to_scim() for u in users], total, start_index, count)


@app.route("/scim/v2/Users/<user_id>", methods=["GET"])
@require_auth
def get_user(user_id):
    db = get_db()
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return scim_error("User not found", 404)
    return jsonify(user.to_scim())


@app.route("/scim/v2/Users/<user_id>", methods=["PUT"])
@require_auth
def replace_user(user_id):
    db = get_db()
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return scim_error("User not found", 404)

    data = request.json
    name = data.get("name", {})
    emails = data.get("emails", [])
    enterprise = data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {})

    user.userName = data.get("userName", user.userName)
    user.givenName = name.get("givenName", user.givenName)
    user.familyName = name.get("familyName", user.familyName)
    user.displayName = data.get("displayName", user.displayName)
    user.email = emails[0].get("value", user.email) if emails else user.email
    user.active = data.get("active", user.active)
    user.department = enterprise.get("department", user.department)
    user.title = data.get("title", user.title)
    user.lastModified = datetime.now(timezone.utc)

    db.commit()
    db.refresh(user)
    return jsonify(user.to_scim())


@app.route("/scim/v2/Users/<user_id>", methods=["PATCH"])
@require_auth
def patch_user(user_id):
    db = get_db()
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return scim_error("User not found", 404)

    data = request.json
    operations = data.get("Operations", [])

    for op in operations:
        operation = op.get("op", "").lower()
        path = op.get("path", "")
        value = op.get("value", {})

        if operation == "replace":
            if isinstance(value, dict):
                if "active" in value:
                    user.active = value["active"]
                if "userName" in value:
                    user.userName = value["userName"]
                if "name" in value:
                    user.givenName = value["name"].get("givenName", user.givenName)
                    user.familyName = value["name"].get("familyName", user.familyName)
            elif path == "active":
                user.active = value
            elif path == "userName":
                user.userName = value

    user.lastModified = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    return jsonify(user.to_scim())


@app.route("/scim/v2/Users/<user_id>", methods=["DELETE"])
@require_auth
def delete_user(user_id):
    db = get_db()
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return scim_error("User not found", 404)
    db.delete(user)
    db.commit()
    return "", 204


# ---- Group Endpoints ----

@app.route("/scim/v2/Groups", methods=["POST"])
@require_auth
def create_group():
    data = request.json
    db = get_db()

    display_name = data.get("displayName")
    if not display_name:
        return scim_error("displayName is required", 400)

    existing = db.query(Group).filter(Group.displayName == display_name).first()
    if existing:
        return scim_error(f"Group '{display_name}' already exists", 409, "uniqueness")

    group = Group(displayName=display_name)

    for member_data in data.get("members", []):
        user = db.query(User).filter(User.id == member_data.get("value")).first()
        if user:
            group.members.append(user)

    db.add(group)
    db.commit()
    db.refresh(group)
    return jsonify(group.to_scim()), 201


@app.route("/scim/v2/Groups", methods=["GET"])
@require_auth
def list_groups():
    db = get_db()
    start_index = int(request.args.get("startIndex", 1))
    count = int(request.args.get("count", 100))
    filter_str = request.args.get("filter", "")

    query = db.query(Group)

    if filter_str:
        attr, value = parse_scim_filter(filter_str)
        if attr == "displayName":
            query = query.filter(Group.displayName == value)

    total = query.count()
    groups = query.offset(start_index - 1).limit(count).all()

    return list_response([g.to_scim() for g in groups], total, start_index, count)


@app.route("/scim/v2/Groups/<group_id>", methods=["GET"])
@require_auth
def get_group(group_id):
    db = get_db()
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        return scim_error("Group not found", 404)
    return jsonify(group.to_scim())


@app.route("/scim/v2/Groups/<group_id>", methods=["PATCH"])
@require_auth
def patch_group(group_id):
    db = get_db()
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        return scim_error("Group not found", 404)

    data = request.json
    for op in data.get("Operations", []):
        operation = op.get("op", "").lower()
        path = op.get("path", "")
        value = op.get("value", [])

        if operation == "add" and "members" in path:
            members_to_add = value if isinstance(value, list) else [value]
            for member_data in members_to_add:
                user = db.query(User).filter(User.id == member_data.get("value")).first()
                if user and user not in group.members:
                    group.members.append(user)

        elif operation == "remove" and "members" in path:
            member_filter = re.search(r'members\[value eq "([^"]+)"\]', path)
            if member_filter:
                uid = member_filter.group(1)
                user = db.query(User).filter(User.id == uid).first()
                if user and user in group.members:
                    group.members.remove(user)

        elif operation == "replace" and path == "displayName":
            group.displayName = value

    group.lastModified = datetime.now(timezone.utc)
    db.commit()
    db.refresh(group)
    return jsonify(group.to_scim())


@app.route("/scim/v2/Groups/<group_id>", methods=["DELETE"])
@require_auth
def delete_group(group_id):
    db = get_db()
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        return scim_error("Group not found", 404)
    db.delete(group)
    db.commit()
    return "", 204


# ---- Service Provider Config ----

@app.route("/scim/v2/ServiceProviderConfig", methods=["GET"])
def service_provider_config():
    return jsonify({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://developer.okta.com/docs/concepts/scim/",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Authentication scheme using the OAuth Bearer Token Standard",
            "specUri": "https://www.rfc-editor.org/info/rfc6750"
        }]
    })


@app.route("/scim/v2/ResourceTypes", methods=["GET"])
def resource_types():
    return jsonify({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "Resources": [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:User"
            },
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:Group"
            }
        ]
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
