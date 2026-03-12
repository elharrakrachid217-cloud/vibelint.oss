"""
tests/test_cors.py
==================
Tests for the CorsDetector - verifies that wildcard CORS configurations
are flagged across multiple frameworks.
"""

import pytest
from core.scanner import SecurityScanner

scanner = SecurityScanner()


# ─────────────────────────────────────────
# EXPRESS.JS TESTS
# ─────────────────────────────────────────

def test_express_explicit_wildcard_cors_flagged():
    code = '''
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({ origin: '*' }));

app.get('/api/data', (req, res) => res.json({}));
'''
    result = scanner.scan(code=code, filename="server.js", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "cors_misconfiguration" for v in result["violations"])


def test_express_implicit_wildcard_cors_flagged():
    code = '''
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors()); // defaults to *
'''
    result = scanner.scan(code=code, filename="server.js", language="javascript")
    assert result["approved"] is False
    assert any(v["type"] == "cors_misconfiguration" for v in result["violations"])


def test_express_origin_true_flagged():
    code = "app.use(cors({ origin: true }))"
    result = scanner.scan(code=code, filename="server.js", language="javascript")
    assert any(v["type"] == "cors_misconfiguration" for v in result["violations"])


def test_express_origin_true_string_not_flagged():
    code = "app.use(cors({ origin: 'true' }))"
    result = scanner.scan(code=code, filename="server.js", language="javascript")
    cors_violations = [v for v in result["violations"] if v["type"] == "cors_misconfiguration"]
    assert len(cors_violations) == 0


def test_express_clean_cors_passes():
    code = '''
const express = require('express');
const cors = require('cors');
const app = express();

const whitelist = ['http://localhost:3000', 'https://myapp.com'];
app.use(cors({
  origin: function (origin, callback) {
    if (whitelist.indexOf(origin) !== -1) {
      callback(null, true)
    } else {
      callback(new Error('Not allowed by CORS'))
    }
  }
}));
'''
    result = scanner.scan(code=code, filename="server.js", language="javascript")
    cors_violations = [v for v in result["violations"] if v["type"] == "cors_misconfiguration"]
    assert len(cors_violations) == 0


# ─────────────────────────────────────────
# FASTAPI TESTS
# ─────────────────────────────────────────

def test_fastapi_wildcard_cors_flagged():
    code = '''
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
'''
    result = scanner.scan(code=code, filename="main.py", language="python")
    assert result["approved"] is False
    assert any(v["type"] == "cors_misconfiguration" for v in result["violations"])


def test_fastapi_clean_cors_passes():
    code = '''
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("FRONTEND_URL")],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
'''
    result = scanner.scan(code=code, filename="main.py", language="python")
    cors_violations = [v for v in result["violations"] if v["type"] == "cors_misconfiguration"]
    assert len(cors_violations) == 0


# ─────────────────────────────────────────
# DJANGO TESTS
# ─────────────────────────────────────────

def test_django_cors_allow_all_flagged():
    code = '''
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
]

CORS_ORIGIN_ALLOW_ALL = True
'''
    result = scanner.scan(code=code, filename="settings.py", language="python")
    assert result["approved"] is False
    assert any(v["type"] == "cors_misconfiguration" for v in result["violations"])


def test_django_cors_allowed_origins_wildcard_flagged():
    code = '''
CORS_ALLOWED_ORIGINS = [
    "*",
]
'''
    result = scanner.scan(code=code, filename="settings.py", language="python")
    assert any(v["type"] == "cors_misconfiguration" for v in result["violations"])


def test_django_clean_cors_passes():
    code = '''
CORS_ALLOWED_ORIGINS = [
    "https://example.com",
    "https://sub.example.com",
    "http://localhost:8080",
    "http://127.0.0.1:9000"
]
'''
    result = scanner.scan(code=code, filename="settings.py", language="python")
    cors_violations = [v for v in result["violations"] if v["type"] == "cors_misconfiguration"]
    assert len(cors_violations) == 0


# ─────────────────────────────────────────
# MANUAL HEADERS TESTS
# ─────────────────────────────────────────

def test_manual_header_wildcard_flagged():
    code = '''
def handle_request(request):
    response = make_response("Hello")
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response
'''
    result = scanner.scan(code=code, filename="app.py", language="python")
    assert any(v["type"] == "cors_misconfiguration" for v in result["violations"])


def test_nodejs_manual_header_wildcard_flagged():
    code = '''
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    next();
});
'''
    result = scanner.scan(code=code, filename="server.js", language="javascript")
    assert any(v["type"] == "cors_misconfiguration" for v in result["violations"])


# ─────────────────────────────────────────
# REMEDIATION TESTS
# ─────────────────────────────────────────

def test_remediation_adds_warning_comment():
    code = '''
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
)
'''
    result = scanner.scan(code=code, filename="app.py", language="python")
    assert "VIBELINT" in result["remediated_code"]
    assert "cors_misconfiguration" in str(result["violations"])
