from __future__ import annotations

from typing import List, Dict, Any, Optional
from pathlib import Path
from urllib.parse import urljoin, quote
import requests
import urllib3

from app.config import CISO_BASE_URL, CISO_API_TOKEN, VERIFY_SSL
from schemas.evidence_models import (
    RawEvidence,
    ClassificationResult,
    ImportResult,
    RequirementCatalogItem,
)


class CisoApiError(Exception):
    pass


def _first_non_empty(*values):
    for v in values:
        if v not in (None, "", [], {}):
            return v
    return None


def _safe_placeholder_link(name: str) -> str:
    """
    某些 CISO Assistant 实例 evidence.link 不能为空。
    这里统一给一个合法占位 URL，后续再补传文件。
    """
    safe_name = quote(name or "evidence")
    return f"https://localhost/evidence/{safe_name}"


class CisoApiClient:
    def __init__(
        self,
        base_url: str = CISO_BASE_URL,
        api_token: str = CISO_API_TOKEN,
        verify_ssl: bool = VERIFY_SSL,
        timeout: int = 90,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()

        if api_token:
            self.session.headers.update({"Authorization": f"Token {api_token}"})

        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _absolute_url(self, url_or_path: str) -> str:
        if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
            return url_or_path
        return urljoin(self.base_url + "/", url_or_path)

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        resp = self.session.request(
            method,
            self._absolute_url(path),
            verify=self.verify_ssl,
            timeout=self.timeout,
            **kwargs,
        )
        return resp

    def _get_all_pages(self, path: str, params: Optional[dict] = None) -> List[dict]:
        params = dict(params or {})
        params.setdefault("limit", 100)

        url = self._absolute_url(path)
        results: List[dict] = []

        while url:
            resp = self.session.get(
                url,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )

            if resp.status_code >= 400:
                raise CisoApiError(f"分页查询失败: {resp.status_code} {resp.text}")

            data = resp.json()

            if isinstance(data, list):
                results.extend(data)
                break

            if isinstance(data, dict) and "results" in data:
                results.extend(data.get("results", []))
                next_url = data.get("next")
                url = self._absolute_url(next_url) if next_url else None
                params = {}
            else:
                if isinstance(data, dict):
                    results.append(data)
                break

        return results

    # =========================
    # Compliance Assessment
    # =========================

    def list_compliance_assessments(self) -> List[dict]:
        return self._get_all_pages("compliance-assessments/")

    def resolve_assessment(
        self,
        assessment_id: Optional[str] = None,
        assessment_name: Optional[str] = None,
        assessment_framework: Optional[str] = None,
        assessment_version: Optional[str] = None,
    ) -> dict:
        items = self.list_compliance_assessments()

        if assessment_id:
            for item in items:
                if str(item.get("id")) == str(assessment_id):
                    return item
            raise CisoApiError(f"找不到 assessment_id={assessment_id}")

        if not assessment_name:
            raise CisoApiError("必须提供 assessment_id，或 assessment_name")

        matches = []

        for item in items:
            name = str(item.get("name") or "").strip()

            framework_name = str(
                _first_non_empty(
                    item.get("framework_name"),
                    (item.get("framework") or {}).get("name")
                    if isinstance(item.get("framework"), dict)
                    else None,
                    item.get("framework"),
                )
                or ""
            ).strip()

            version = str(item.get("version") or "").strip()

            if name != assessment_name:
                continue

            if assessment_framework and assessment_framework not in framework_name:
                continue

            if assessment_version and assessment_version != version:
                continue

            matches.append(item)

        if not matches:
            raise CisoApiError(
                f"找不到 assessment。name={assessment_name}, "
                f"framework={assessment_framework}, version={assessment_version}"
            )

        if len(matches) > 1:
            choices = [
                {
                    "id": x.get("id"),
                    "name": x.get("name"),
                    "framework": _first_non_empty(
                        x.get("framework_name"),
                        (x.get("framework") or {}).get("name")
                        if isinstance(x.get("framework"), dict)
                        else None,
                        x.get("framework"),
                    ),
                    "version": x.get("version"),
                }
                for x in matches
            ]

            raise CisoApiError(
                "assessment 同名冲突，请补充 --assessment-framework 或 --assessment-id。"
                f"候选: {choices}"
            )

        return matches[0]

    # =========================
    # Requirement Assessment
    # =========================

    def list_requirement_assessments(self, compliance_assessment_id: str) -> List[dict]:
        try:
            items = self._get_all_pages(
                "requirement-assessments/",
                params={"compliance_assessment": compliance_assessment_id},
            )

            if items:
                filtered = [
                    x
                    for x in items
                    if str(
                        _first_non_empty(
                            x.get("compliance_assessment"),
                            (x.get("assessment") or {}).get("id")
                            if isinstance(x.get("assessment"), dict)
                            else None,
                            x.get("compliance_assessment_id"),
                        )
                    )
                    == str(compliance_assessment_id)
                ]

                return filtered or items

        except Exception:
            pass

        items = self._get_all_pages("requirement-assessments/")
        filtered = []

        for x in items:
            ca_id = _first_non_empty(
                x.get("compliance_assessment"),
                x.get("compliance_assessment_id"),
                (x.get("assessment") or {}).get("id")
                if isinstance(x.get("assessment"), dict)
                else None,
            )

            if str(ca_id) == str(compliance_assessment_id):
                filtered.append(x)

        return filtered

    def build_requirement_catalog(self, compliance_assessment: dict) -> List[RequirementCatalogItem]:
        ca_id = str(compliance_assessment.get("id"))

        framework_name = str(
            _first_non_empty(
                compliance_assessment.get("framework_name"),
                (compliance_assessment.get("framework") or {}).get("name")
                if isinstance(compliance_assessment.get("framework"), dict)
                else None,
                compliance_assessment.get("framework"),
            )
            or ""
        )

        items = self.list_requirement_assessments(ca_id)
        catalog: List[RequirementCatalogItem] = []

        for item in items:
            req = item.get("requirement") if isinstance(item.get("requirement"), dict) else {}
            req_node = item.get("requirement_node") if isinstance(item.get("requirement_node"), dict) else {}

            requirement_id = _first_non_empty(
                item.get("requirement_id"),
                item.get("ref_id"),
                req.get("urn") if req else None,
                req.get("ref_id") if req else None,
                req.get("id") if req else None,
                req_node.get("urn") if req_node else None,
                req_node.get("ref_id") if req_node else None,
                req_node.get("id") if req_node else None,
            )

            title = str(
                _first_non_empty(
                    item.get("name"),
                    item.get("title"),
                    req.get("name") if req else None,
                    req.get("title") if req else None,
                    req_node.get("name") if req_node else None,
                    req_node.get("title") if req_node else None,
                    requirement_id,
                )
            )

            description = str(
                _first_non_empty(
                    item.get("description"),
                    req.get("description") if req else None,
                    req_node.get("description") if req_node else None,
                    "",
                )
            )

            if not item.get("id"):
                continue

            catalog.append(
                RequirementCatalogItem(
                    requirement_assessment_id=str(item["id"]),
                    framework_name=framework_name,
                    requirement_id=str(requirement_id or ""),
                    title=title,
                    description=description,
                )
            )

        return catalog

    # =========================
    # Evidence
    # =========================

    def search_existing_evidence(self, name: str) -> Dict[str, Any]:
        try:
            resp = self._request("GET", f"evidences/?search={name}")

            if resp.status_code < 400:
                return resp.json()

        except Exception:
            pass

        return {"results": []}

    def create_evidence(self, name: str, description: str = "", link: str = "") -> Dict[str, Any]:
        final_link = link.strip() if link and link.strip() else _safe_placeholder_link(name)

        payload = {
            "name": name,
            "description": description or "",
            "link": final_link,
        }

        resp = self._request("POST", "evidences/", json=payload)

        if resp.status_code >= 400:
            raise CisoApiError(f"创建 evidence 失败: {resp.status_code} {resp.text}")

        return resp.json()

    def upload_evidence_file(self, evidence_id: str, file_path: str) -> Dict[str, Any]:
        path = Path(file_path)

        attempts = [
            ("POST", f"evidences/{evidence_id}/upload/", "file"),
            ("POST", f"evidences/{evidence_id}/attachment/", "file"),
            ("PATCH", f"evidences/{evidence_id}/", "attachment"),
            ("PATCH", f"evidences/{evidence_id}/", "file"),
        ]

        last_error = None

        for method, endpoint, field_name in attempts:
            try:
                with path.open("rb") as f:
                    files = {field_name: (path.name, f)}

                    # 传文件时不能强行用 application/json
                    headers_backup = dict(self.session.headers)
                    self.session.headers.pop("Content-Type", None)

                    resp = self._request(method, endpoint, files=files)

                    self.session.headers.clear()
                    self.session.headers.update(headers_backup)

                if resp.status_code < 400:
                    try:
                        return resp.json()
                    except Exception:
                        return {"ok": True, "status_code": resp.status_code}

                last_error = f"{method} {endpoint} => {resp.status_code} {resp.text}"

            except Exception as e:
                last_error = str(e)

                try:
                    self.session.headers.update({"Content-Type": "application/json"})
                except Exception:
                    pass

        raise CisoApiError(f"上传 evidence 文件失败: {last_error}")

    def attach_evidence_to_requirement(
        self,
        requirement_assessment_id: str,
        evidence_ids: List[str],
    ) -> Dict[str, Any]:
        payloads = [
            {"evidences": evidence_ids},
            {"evidence_ids": evidence_ids},
            {"evidence": evidence_ids[0] if evidence_ids else None},
        ]

        last_error = None

        for payload in payloads:
            resp = self._request(
                "PATCH",
                f"requirement-assessments/{requirement_assessment_id}/",
                json=payload,
            )

            if resp.status_code < 400:
                try:
                    return resp.json()
                except Exception:
                    return {"ok": True, "status_code": resp.status_code}

            last_error = f"{resp.status_code} {resp.text}"

        raise CisoApiError(f"绑定 evidence 到 requirement-assessment 失败: {last_error}")

    # =========================
    # Observation / Review Note
    # =========================

    def add_review_note(self, requirement_assessment_id: str, note: str) -> Dict[str, Any]:
        payload_candidates = [
            {"observation": note},
            {"review_note": note},
            {"comment": note},
            {"description": note},
        ]

        last_error = None

        for payload in payload_candidates:
            resp = self._request(
                "PATCH",
                f"requirement-assessments/{requirement_assessment_id}/",
                json=payload,
            )

            if resp.status_code < 400:
                try:
                    return resp.json()
                except Exception:
                    return {"ok": True, "status_code": resp.status_code}

            last_error = f"{resp.status_code} {resp.text}"

        raise CisoApiError(f"回写 AI 初审备注失败: {last_error}")

    # =========================
    # AI review decision update
    # review_and_import.py 会调用下面 3 个方法名
    # =========================

    def _status_value_candidates(self, status_cn: str) -> List[str]:
        s = str(status_cn or "").strip()

        mapping = {
            "待办": [
                "to_do",
                "todo",
                "pending",
                "new",
                "not_started",
                "待办",
            ],
            "进行中": [
                "in_progress",
                "progress",
                "ongoing",
                "进行中",
            ],
            "审核中": [
                "in_progress",
                "in_review",
                "reviewing",
                "under_review",
                "progress",
                "进行中",
                "审核中",
            ],
            "已完成": [
                "done",
                "completed",
                "finished",
                "complete",
                "已完成",
            ],
        }

        return mapping.get(s, [s] if s else [])

    def _result_value_candidates(self, result_cn: str) -> List[str]:
        s = str(result_cn or "").strip()

        mapping = {
            "未评估": [
                "not_assessed",
                "not_evaluated",
                "unassessed",
                "not_reviewed",
                "undefined",
                "未评估",
            ],
            "部分合规": [
                "partially_compliant",
                "partial_compliant",
                "partly_compliant",
                "partial",
                "部分合规",
            ],
            "合规": [
                "compliant",
                "conform",
                "conformant",
                "ok",
                "passed",
                "合规",
            ],
            "不合规": [
                "non_compliant",
                "not_compliant",
                "nonconform",
                "non_conform",
                "failed",
                "不合规",
            ],
            "不适用": [
                "not_applicable",
                "na",
                "n/a",
                "not_applicable",
                "不适用",
            ],
        }

        return mapping.get(s, [s] if s else [])

    def _patch_requirement_assessment_decision(
        self,
        requirement_assessment_id: str,
        status: str = "",
        result: str = "",
        score: Optional[int] = None,
    ) -> Dict[str, Any]:
        status_values = self._status_value_candidates(status) or [None]
        result_values = self._result_value_candidates(result) or [None]

        score_int = None
        if score is not None:
            try:
                score_int = int(round(float(score)))
                score_int = max(0, min(100, score_int))
            except Exception:
                score_int = None

        payloads: List[Dict[str, Any]] = []

        # 一次性同时写 status/result/score
        for status_value in status_values:
            for result_value in result_values:
                payload: Dict[str, Any] = {}

                if status_value:
                    payload["status"] = status_value

                if result_value:
                    payload["result"] = result_value

                if score_int is not None:
                    payload["score"] = score_int
                    payload["is_scored"] = True
                    payload["scoring_enabled"] = True

                if payload:
                    payloads.append(payload)

        # 兜底：分开写状态
        if status:
            for status_value in status_values:
                if status_value:
                    payloads.extend(
                        [
                            {"status": status_value},
                            {"review_status": status_value},
                            {"assessment_status": status_value},
                        ]
                    )

        # 兜底：分开写结果
        if result:
            for result_value in result_values:
                if result_value:
                    payloads.extend(
                        [
                            {"result": result_value},
                            {"compliance_result": result_value},
                            {"assessment_result": result_value},
                        ]
                    )

        # 兜底：分开写分数
        if score_int is not None:
            payloads.extend(
                [
                    {"score": score_int},
                    {"score_value": score_int},
                    {"rating": score_int},
                    {"maturity": score_int},
                    {"maturity_score": score_int},
                    {"is_scored": True, "score": score_int},
                ]
            )

        # 去重
        dedup_payloads: List[Dict[str, Any]] = []
        seen = set()

        for payload in payloads:
            key = tuple(sorted(payload.items()))
            if key in seen:
                continue
            seen.add(key)
            dedup_payloads.append(payload)

        last_error = None

        for payload in dedup_payloads:
            resp = self._request(
                "PATCH",
                f"requirement-assessments/{requirement_assessment_id}/",
                json=payload,
            )

            if resp.status_code < 400:
                try:
                    return {
                        "ok": True,
                        "status_code": resp.status_code,
                        "payload": payload,
                        "response": resp.json(),
                    }
                except Exception:
                    return {
                        "ok": True,
                        "status_code": resp.status_code,
                        "payload": payload,
                    }

            last_error = f"payload={payload} => {resp.status_code} {resp.text}"

        raise CisoApiError(f"更新 requirement-assessment 状态/结果/分数失败: {last_error}")

    def update_requirement_assessment_review(
        self,
        requirement_assessment_id: str,
        status: str = "",
        result: str = "",
        score: Optional[int] = None,
    ) -> Dict[str, Any]:
        return self._patch_requirement_assessment_decision(
            requirement_assessment_id=requirement_assessment_id,
            status=status,
            result=result,
            score=score,
        )

    def update_requirement_assessment_decision(
        self,
        requirement_assessment_id: str,
        status: str = "",
        result: str = "",
        score: Optional[int] = None,
    ) -> Dict[str, Any]:
        return self._patch_requirement_assessment_decision(
            requirement_assessment_id=requirement_assessment_id,
            status=status,
            result=result,
            score=score,
        )

    def update_requirement_assessment(
        self,
        requirement_assessment_id: str,
        status: str = "",
        result: str = "",
        score: Optional[int] = None,
    ) -> Dict[str, Any]:
        return self._patch_requirement_assessment_decision(
            requirement_assessment_id=requirement_assessment_id,
            status=status,
            result=result,
            score=score,
        )

    # 兼容你原来旧方法名
    def update_requirement_review_decision(
        self,
        requirement_assessment_id: str,
        status_cn: str = "",
        result_cn: str = "",
        score: Optional[int] = None,
        enable_score: bool = True,
    ) -> Dict[str, Any]:
        return self._patch_requirement_assessment_decision(
            requirement_assessment_id=requirement_assessment_id,
            status=status_cn,
            result=result_cn,
            score=score if enable_score else None,
        )


def import_evidence_with_optional_reuse(
    client: CisoApiClient,
    raw: RawEvidence,
    classification: ClassificationResult,
    reuse_existing: bool = True,
) -> ImportResult:
    existing_id = None

    if reuse_existing:
        try:
            existing = client.search_existing_evidence(raw.file_name)

            if isinstance(existing, dict):
                results = existing.get("results") or existing.get("data") or []

                for item in results:
                    if item.get("name") == raw.file_name:
                        existing_id = item.get("id")
                        break

        except Exception:
            existing_id = None

    if existing_id:
        evidence_id = existing_id
        reused = True
    else:
        created = client.create_evidence(
            name=raw.file_name,
            description=f"sha256={raw.sha256 or ''}",
        )
        evidence_id = created.get("id")
        reused = False
        client.upload_evidence_file(evidence_id, raw.file_path)

    linked_req_ids = []
    linked_req_assessment_ids = []
    seen_ra_ids = set()

    for match in classification.matches:
        if match.requirement_assessment_id in seen_ra_ids:
            continue

        client.attach_evidence_to_requirement(match.requirement_assessment_id, [evidence_id])

        seen_ra_ids.add(match.requirement_assessment_id)
        linked_req_ids.append(match.requirement_id)
        linked_req_assessment_ids.append(match.requirement_assessment_id)

    return ImportResult(
        success=True,
        evidence_id=str(evidence_id),
        reused_existing=reused,
        linked_requirement_ids=linked_req_ids,
        linked_requirement_assessment_ids=linked_req_assessment_ids,
        message="evidence 导入/复用并完成 requirement 关联",
    )