"""
tests/test_injection_extended.py
====================================
Tests for extended SQL and NoSQL injection detection.

Covers:
- JS/TS template literal SQL injection
- NoSQL: direct user input to MongoDB methods (JS/TS + Python)
- NoSQL: $where with variable input
- NoSQL: MongoDB operators from user-controlled data
- NoSQL: JSON.parse / json.loads passed to queries
- False-positive checks for safe patterns
"""

import pytest
from core.scanner import SecurityScanner

scanner = SecurityScanner()


# ---- SQL: JS/TS template literal injection ----

def test_detects_sql_template_literal_select_js():
    code = 'const rows = db.query(`SELECT * FROM users WHERE id = ${userId}`);'
    result = scanner.scan(code=code, filename="db.js", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "injection_risk" for v in result["violations"])


def test_detects_sql_template_literal_delete_ts():
    code = 'await pool.query(`DELETE FROM sessions WHERE token = ${token}`);'
    result = scanner.scan(code=code, filename="db.ts", language="typescript")
    assert result["approved"] is False
    assert any("template literal" in v["description"] for v in result["violations"])


def test_detects_sql_template_literal_insert_js():
    code = 'db.execute(`INSERT INTO logs (msg) VALUES (${userMsg})`);'
    result = scanner.scan(code=code, filename="db.js", language="javascript")
    assert result["approved"] is False


def test_detects_sql_template_literal_update_ts():
    code = 'client.query(`UPDATE users SET name = ${name} WHERE id = ${id}`);'
    result = scanner.scan(code=code, filename="db.ts", language="typescript")
    assert result["approved"] is False


def test_safe_template_literal_no_sql_passes():
    code = 'const msg = `Hello ${userName}, welcome!`;'
    result = scanner.scan(code=code, filename="app.js", language="javascript")
    injection_violations = [v for v in result["violations"] if v["type"] == "injection_risk"]
    assert len(injection_violations) == 0


# ---- NoSQL: Direct user input to MongoDB (JS/TS) ----

def test_detects_nosql_find_req_body_js():
    code = 'const user = await collection.find(req.body);'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    assert result["approved"] is False
    assert any("MongoDB" in v["description"] for v in result["violations"])


def test_detects_nosql_findOne_req_body_ts():
    code = 'const doc = await db.collection("users").findOne(req.body);'
    result = scanner.scan(code=code, filename="api.ts", language="typescript")
    assert result["approved"] is False
    assert any("NoSQL" in v["description"] for v in result["violations"])


def test_detects_nosql_updateOne_req_query_js():
    code = 'await users.updateOne(req.query, { $set: { active: true } });'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    assert result["approved"] is False


def test_detects_nosql_deleteMany_request_params_ts():
    code = 'await logs.deleteMany(request.params);'
    result = scanner.scan(code=code, filename="api.ts", language="typescript")
    assert result["approved"] is False


def test_detects_nosql_aggregate_req_body_js():
    code = 'const results = await collection.aggregate(req.body);'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    assert result["approved"] is False


# ---- NoSQL: Direct user input to MongoDB (Python) ----

def test_detects_nosql_find_request_json_py():
    code = 'results = collection.find(request.json)'
    result = scanner.scan(code=code, filename="api.py", language="python")
    assert result["approved"] is False
    assert any("MongoDB" in v["description"] for v in result["violations"])


def test_detects_nosql_find_one_request_args_py():
    code = 'doc = db.users.find_one(request.args)'
    result = scanner.scan(code=code, filename="api.py", language="python")
    assert result["approved"] is False


def test_detects_nosql_update_one_request_form_py():
    code = 'db.users.update_one(request.form, {"$set": {"verified": True}})'
    result = scanner.scan(code=code, filename="api.py", language="python")
    assert result["approved"] is False


def test_detects_nosql_delete_many_request_json_py():
    code = 'collection.delete_many(request.json)'
    result = scanner.scan(code=code, filename="api.py", language="python")
    assert result["approved"] is False


# ---- NoSQL: $where with variable input ----

def test_detects_nosql_where_variable_js():
    code = 'db.users.find({ "$where": userFunction });'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    assert result["approved"] is False
    assert any("$where" in v["description"] for v in result["violations"])


def test_detects_nosql_where_variable_py():
    code = 'collection.find({"$where": user_script})'
    result = scanner.scan(code=code, filename="api.py", language="python")
    assert result["approved"] is False


def test_safe_where_string_literal_passes():
    code = 'db.users.find({ "$where": "this.age > 18" });'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    where_violations = [
        v for v in result["violations"]
        if "$where" in v.get("description", "")
    ]
    assert len(where_violations) == 0


# ---- NoSQL: MongoDB operators from user data ----

def test_detects_nosql_ne_operator_from_req_body_js():
    code = 'db.users.findOne({ password: { "$ne": req.body } });'
    result = scanner.scan(code=code, filename="auth.js", language="javascript")
    assert result["approved"] is False


def test_detects_nosql_gt_operator_from_input_py():
    code = 'collection.find({"age": {"$gt": user_input}})'
    result = scanner.scan(code=code, filename="api.py", language="python")
    assert result["approved"] is False


def test_detects_nosql_in_operator_from_query_js():
    code = 'db.products.find({ category: { "$in": query } });'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    assert result["approved"] is False


def test_detects_nosql_regex_operator_from_input_ts():
    code = 'collection.find({ name: { "$regex": input } });'
    result = scanner.scan(code=code, filename="api.ts", language="typescript")
    assert result["approved"] is False


# ---- NoSQL: JSON.parse / json.loads to query ----

def test_detects_nosql_json_parse_to_find_js():
    code = 'const docs = await collection.find(JSON.parse(rawBody));'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    assert result["approved"] is False
    assert any("Parsed JSON" in v["description"] for v in result["violations"])


def test_detects_nosql_json_parse_to_findOne_ts():
    code = 'const doc = await db.users.findOne(JSON.parse(req.body));'
    result = scanner.scan(code=code, filename="api.ts", language="typescript")
    assert result["approved"] is False


def test_detects_nosql_json_loads_to_find_py():
    code = 'results = collection.find(json.loads(request.data))'
    result = scanner.scan(code=code, filename="api.py", language="python")
    assert result["approved"] is False
    assert any("Parsed JSON" in v["description"] for v in result["violations"])


def test_detects_nosql_json_loads_to_find_one_py():
    code = 'doc = db.users.find_one(json.loads(raw_data))'
    result = scanner.scan(code=code, filename="api.py", language="python")
    assert result["approved"] is False


# ---- Bug-fix regression: JSON.parse/json.loads must cover all methods ----

def test_detects_nosql_json_parse_findOneAndDelete_js():
    code = 'await collection.findOneAndDelete(JSON.parse(rawBody));'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    assert result["approved"] is False
    assert any("Parsed JSON" in v["description"] for v in result["violations"])


def test_detects_nosql_json_parse_findOneAndReplace_js():
    code = 'await collection.findOneAndReplace(JSON.parse(rawBody), replacement);'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    assert result["approved"] is False


def test_detects_nosql_json_parse_replaceOne_js():
    code = 'await collection.replaceOne(JSON.parse(filter), newDoc);'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    assert result["approved"] is False


def test_detects_nosql_json_loads_find_one_and_update_py():
    code = 'collection.find_one_and_update(json.loads(raw_data), {"$set": {"x": 1}})'
    result = scanner.scan(code=code, filename="api.py", language="python")
    assert result["approved"] is False
    assert any("Parsed JSON" in v["description"] for v in result["violations"])


def test_detects_nosql_json_loads_find_one_and_delete_py():
    code = 'collection.find_one_and_delete(json.loads(raw_data))'
    result = scanner.scan(code=code, filename="api.py", language="python")
    assert result["approved"] is False


def test_detects_nosql_json_loads_find_one_and_replace_py():
    code = 'collection.find_one_and_replace(json.loads(raw_data), new_doc)'
    result = scanner.scan(code=code, filename="api.py", language="python")
    assert result["approved"] is False


def test_detects_nosql_json_loads_replace_one_py():
    code = 'collection.replace_one(json.loads(raw_data), new_doc)'
    result = scanner.scan(code=code, filename="api.py", language="python")
    assert result["approved"] is False


# ---- False positives: safe NoSQL patterns ----

def test_safe_mongodb_find_with_literal_passes_js():
    code = 'const user = await db.users.findOne({ email: "admin@test.com" });'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    injection_violations = [v for v in result["violations"] if v["type"] == "injection_risk"]
    assert len(injection_violations) == 0


def test_safe_mongodb_find_with_literal_passes_py():
    code = 'user = db.users.find_one({"email": "admin@test.com"})'
    result = scanner.scan(code=code, filename="api.py", language="python")
    injection_violations = [v for v in result["violations"] if v["type"] == "injection_risk"]
    assert len(injection_violations) == 0


def test_safe_mongodb_validated_input_passes_js():
    code = 'const user = await db.users.findOne({ _id: ObjectId(sanitizedId) });'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    injection_violations = [v for v in result["violations"] if v["type"] == "injection_risk"]
    assert len(injection_violations) == 0


# ---- Fix hints ----

def test_nosql_fix_hint_js_mentions_schema_validation():
    code = 'const user = await collection.findOne(req.body);'
    result = scanner.scan(code=code, filename="api.js", language="javascript")
    nosql_violations = [v for v in result["violations"] if "MongoDB" in v.get("description", "") or "NoSQL" in v.get("description", "")]
    assert len(nosql_violations) > 0
    assert any("Joi" in v["fix_hint"] or "Zod" in v["fix_hint"] for v in nosql_violations)


def test_nosql_fix_hint_py_mentions_pydantic():
    code = 'doc = collection.find_one(request.json)'
    result = scanner.scan(code=code, filename="api.py", language="python")
    nosql_violations = [v for v in result["violations"] if "MongoDB" in v.get("description", "") or "NoSQL" in v.get("description", "")]
    assert len(nosql_violations) > 0
    assert any("Pydantic" in v["fix_hint"] for v in nosql_violations)


def test_template_literal_sql_fix_hint_ts():
    code = 'const rows = db.query(`SELECT * FROM users WHERE id = ${userId}`);'
    result = scanner.scan(code=code, filename="db.ts", language="typescript")
    sql_violations = [v for v in result["violations"] if "template literal" in v.get("description", "")]
    assert len(sql_violations) > 0
    assert any("Prisma" in v["fix_hint"] or "parameterized" in v["fix_hint"] for v in sql_violations)
