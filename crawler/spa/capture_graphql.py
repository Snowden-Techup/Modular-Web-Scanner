"""GraphQL capture and schema/form synthesis."""

from __future__ import annotations

import html
import json
import logging
from urllib.parse import urlparse

from crawler.spa.capture_core import GQL_OP_RE, INTROSPECTION_QUERY, MAX_GRAPHQL_SCHEMAS

logger = logging.getLogger(__name__)


def graphql_endpoint_key(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def record_graphql_capture(engine, url: str, post_data: str | None) -> None:
    if not post_data:
        return
    key = graphql_endpoint_key(url)
    engine.graphql_endpoint_paths.add(key)
    bucket = engine.graphql_captures.setdefault(key, [])
    if len(bucket) >= 15 or any(item.get("post_data") == post_data for item in bucket):
        return
    bucket.append({"url": url, "post_data": post_data})


def unwrap_graphql_type(type_node: dict | None) -> str:
    if not type_node:
        return "String"
    kind = type_node.get("kind")
    if kind == "NON_NULL":
        inner = unwrap_graphql_type(type_node.get("ofType"))
        return inner if inner.endswith("!") else f"{inner}!"
    if kind == "LIST":
        return f"[{unwrap_graphql_type(type_node.get('ofType'))}]"
    return type_node.get("name") or "String"


def build_graphql_forms_from_captures(engine, gql_key: str, captures: list[dict[str, str]]) -> str:
    forms_html = ""
    seen_ops: set[str] = set()
    for item in captures:
        if engine.metrics["graphql_schemas"] >= MAX_GRAPHQL_SCHEMAS:
            break
        try:
            body = json.loads(item.get("post_data") or "")
        except (json.JSONDecodeError, TypeError) as exc:
            logger.debug("[SPA Crawler] Skipping non-JSON GraphQL capture on %s: %s", gql_key, exc)
            continue
        if not isinstance(body, dict) or not str(body.get("query") or "").strip():
            continue
        query = str(body["query"])
        op_match = GQL_OP_RE.search(query)
        op_type = op_match.group(1).lower() if op_match else "query"
        op_name = body.get("operationName") or (op_match.group(2) if op_match else "CapturedOperation")
        sig = f"{gql_key}:{op_type}:{op_name}"
        if sig in seen_ops:
            continue
        seen_ops.add(sig)
        gql_url = item.get("url") or gql_key
        variables = body.get("variables") or {}
        inputs, arg_types = "", {}
        if isinstance(variables, dict):
            for var_name, var_val in variables.items():
                arg_types[str(var_name)] = "String"
                inputs += f'<input name="{html.escape(str(var_name))}" value="{html.escape(str(var_val))}">\n'
        arg_types_json = html.escape(json.dumps(arg_types, ensure_ascii=False), quote=True)
        forms_html += (
            f'<form action="{html.escape(gql_url, quote=True)}" method="POST" '
            f'data-content-type="application/json" data-graphql-type="{html.escape(op_type)}" '
            f'data-graphql-operation="{html.escape(str(op_name))}" data-graphql-arg-types="{arg_types_json}">\n'
            f"{inputs}</form>\n"
        )
        engine.metrics["graphql_schemas"] += 1
    return forms_html


async def extract_graphql_schema(engine, context) -> str:
    if not engine.graphql_endpoint_paths:
        return ""
    forms_html = ""
    for gql_key in engine.graphql_endpoint_paths:
        captures = engine.graphql_captures.get(gql_key, [])
        post_url = captures[0]["url"] if captures else gql_key
        introspection_ok = False
        try:
            resp = await context.request.post(
                post_url,
                headers={"Content-Type": "application/json"},
                data=json.dumps({"query": INTROSPECTION_QUERY}),
            )
            if resp.ok:
                data = await resp.json()
                if "errors" not in data and data.get("data", {}).get("__schema"):
                    introspection_ok = True
                    schema = data["data"]["__schema"]
                    q_name = schema.get("queryType", {}).get("name") or "Query"
                    m_name = schema.get("mutationType", {}).get("name") or "Mutation"
                    for t in schema.get("types", []):
                        if engine.metrics["graphql_schemas"] >= MAX_GRAPHQL_SCHEMAS:
                            break
                        t_name = t.get("name")
                        if t_name not in (q_name, m_name) or not t.get("fields"):
                            continue
                        op_type = "query" if t_name == q_name else "mutation"
                        for field in t["fields"]:
                            if engine.metrics["graphql_schemas"] >= MAX_GRAPHQL_SCHEMAS:
                                break
                            arg_types = {}
                            inputs = ""
                            for arg in field.get("args") or []:
                                if arg_name := arg.get("name"):
                                    arg_types[arg_name] = unwrap_graphql_type(arg.get("type"))
                                    inputs += f'<input name="{html.escape(arg_name)}" value="FUZZ">\n'
                            arg_json = html.escape(json.dumps(arg_types, ensure_ascii=False), quote=True)
                            forms_html += (
                                f'<form action="{html.escape(post_url, quote=True)}" method="POST" '
                                f'data-content-type="application/json" data-graphql-type="{op_type}" '
                                f'data-graphql-operation="{html.escape(field["name"])}" '
                                f'data-graphql-arg-types="{arg_json}">\n{inputs}</form>\n'
                            )
                            engine.metrics["graphql_schemas"] += 1
        except Exception as e:
            logger.debug("[SPA Crawler] GraphQL introspection failed on %s: %s", post_url, e)
        if not introspection_ok and captures:
            forms_html += build_graphql_forms_from_captures(engine, gql_key, captures)
    return forms_html
