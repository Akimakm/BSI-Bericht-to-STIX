import json
import re
from pathlib import Path
from datetime import datetime, timezone

from stix2 import (
    Bundle,
    Report,
    ExternalReference,
    Identity,
    Vulnerability,
    Malware,
    ThreatActor,
    Software,
    Indicator,
)

# ---------------- Paths ----------------
INPUT_FILE = Path(
    "Extracted_entities/_combined/subsections_all.json"
)
OUTPUT_FILE = Path(
    "stix_output.json"
)

# A single identity to satisfy created_by_ref + can also be referenced
PIPELINE_IDENTITY_NAME = "BSI Pipeline (Local)"
PIPELINE_IDENTITY_CLASS = "organization"

# ---------------- Helpers ----------------
def parse_date_ddmmyyyy(d: str | None):
    """
    Input is expected as 'DD.MM.YYYY'. Return timezone-aware datetime (UTC) or None.
    """
    if not d:
        return None
    return datetime.strptime(d.strip(), "%d.%m.%Y").replace(tzinfo=timezone.utc)


def ext_refs_from_sources(urls):
    out = []
    for u in (urls or []):
        if isinstance(u, str) and u.strip():
            out.append(ExternalReference(source_name="source", url=u.strip()))
    return out


def safe_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


HASH_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
HASH_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


def indicator_for_url(url: str) -> Indicator:
    return Indicator(
        name=f"IOC URL: {url}",
        pattern_type="stix",
        pattern=f"[url:value = '{url}']",
    )


def indicator_for_ipv4(ip: str) -> Indicator:
    return Indicator(
        name=f"IOC IPv4: {ip}",
        pattern_type="stix",
        pattern=f"[ipv4-addr:value = '{ip}']",
    )


def indicator_for_domain(domain: str) -> Indicator:
    return Indicator(
        name=f"IOC Domain: {domain}",
        pattern_type="stix",
        pattern=f"[domain-name:value = '{domain}']",
    )


def indicator_for_email(email: str) -> Indicator:
    return Indicator(
        name=f"IOC Email: {email}",
        pattern_type="stix",
        pattern=f"[email-addr:value = '{email}']",
    )


def indicator_for_hash(h: str) -> Indicator:
    """
    Use STIX file hash pattern. Pick hash type by length.
    """
    h_clean = h.strip().lower()

    if HASH_SHA256.match(h_clean):
        # STIX expects hash key names like 'SHA-256'
        pat = f"[file:hashes.'SHA-256' = '{h_clean}']"
        name = f"IOC SHA-256: {h_clean}"
    elif HASH_SHA1.match(h_clean):
        pat = f"[file:hashes.'SHA-1' = '{h_clean}']"
        name = f"IOC SHA-1: {h_clean}"
    elif HASH_MD5.match(h_clean):
        pat = f"[file:hashes.MD5 = '{h_clean}']"
        name = f"IOC MD5: {h_clean}"
    else:
        # If it's not a known hash length, still store as an indicator string pattern
        pat = f"[x-opencti-text:value = '{h_clean}']"
        name = f"IOC Hash: {h_clean}"

    return Indicator(
        name=name,
        pattern_type="stix",
        pattern=pat,
        allow_custom=True,
    )


# ---------------- Main export ----------------
def main():
    data = json.loads(INPUT_FILE.read_text(encoding="utf-8"))

    objects = []

    # Dedup caches by name/value so we don't create duplicates across reports
    identity_by_name = {}
    vuln_by_name = {}
    software_by_name = {}
    malware_by_name = {}
    ta_by_name = {}
    indicator_by_pattern = {}

    # Pipeline identity (created_by_ref)
    pipeline_identity = Identity(
        name=PIPELINE_IDENTITY_NAME,
        identity_class=PIPELINE_IDENTITY_CLASS,
    )
    objects.append(pipeline_identity)

    def get_or_create_identity(name: str) -> Identity:
        key = name.strip()
        if key in identity_by_name:
            return identity_by_name[key]
        obj = Identity(name=key, identity_class="organization")
        identity_by_name[key] = obj
        objects.append(obj)
        return obj

    def get_or_create_vuln(cve: str) -> Vulnerability:
        key = cve.strip().upper()
        if key in vuln_by_name:
            return vuln_by_name[key]
        obj = Vulnerability(name=key)
        vuln_by_name[key] = obj
        objects.append(obj)
        return obj

    def get_or_create_software(name: str) -> Software:
        key = name.strip()
        if key in software_by_name:
            return software_by_name[key]
        obj = Software(name=key)
        software_by_name[key] = obj
        objects.append(obj)
        return obj

    def get_or_create_malware(name: str) -> Malware:
        key = name.strip()
        if key in malware_by_name:
            return malware_by_name[key]
        obj = Malware(name=key, is_family=True)
        malware_by_name[key] = obj
        objects.append(obj)
        return obj

    def get_or_create_threat_actor(name: str) -> ThreatActor:
        key = name.strip()
        if key in ta_by_name:
            return ta_by_name[key]
        obj = ThreatActor(name=key)
        ta_by_name[key] = obj
        objects.append(obj)
        return obj

    def get_or_create_indicator(ind: Indicator) -> Indicator:
        pat = ind.pattern
        if pat in indicator_by_pattern:
            return indicator_by_pattern[pat]
        indicator_by_pattern[pat] = ind
        objects.append(ind)
        return ind

    for item in data:
        e = item.get("entities", {})

        section = item.get("section")
        subsection = item.get("subsection")
        report_name = f"{section} – {subsection}"

        # Build object_refs with native objects
        obj_refs = []

        # Always reference pipeline identity so object_refs is never empty
        obj_refs.append(pipeline_identity.id)

        # ---- organizations -> Identity
        for org in safe_list(e.get("organizations")):
            if isinstance(org, str) and org.strip():
                org_obj = get_or_create_identity(org)
                obj_refs.append(org_obj.id)

        # ---- CVEs -> Vulnerability
        for cve in safe_list(e.get("cve_ids")):
            if isinstance(cve, str) and cve.strip():
                v = get_or_create_vuln(cve)
                obj_refs.append(v.id)

        # ---- products -> Software
        for p in safe_list(e.get("products")):
            if isinstance(p, str) and p.strip():
                s = get_or_create_software(p)
                obj_refs.append(s.id)

        # ---- malware -> Malware
        for m in safe_list(e.get("malware")):
            if isinstance(m, str) and m.strip():
                mw = get_or_create_malware(m)
                obj_refs.append(mw.id)

        # ---- threat actors -> ThreatActor
        for ta in safe_list(e.get("threat_actors")):
            if isinstance(ta, str) and ta.strip():
                t = get_or_create_threat_actor(ta)
                obj_refs.append(t.id)

        # ---- indicators (IOCs)
        for u in safe_list(e.get("ioc_urls")):
            if isinstance(u, str) and u.strip():
                ind = get_or_create_indicator(indicator_for_url(u.strip()))
                obj_refs.append(ind.id)

        for ip in safe_list(e.get("ioc_ipv4")):
            if isinstance(ip, str) and ip.strip():
                ind = get_or_create_indicator(indicator_for_ipv4(ip.strip()))
                obj_refs.append(ind.id)

        for dmn in safe_list(e.get("ioc_domains")):
            if isinstance(dmn, str) and dmn.strip():
                ind = get_or_create_indicator(indicator_for_domain(dmn.strip()))
                obj_refs.append(ind.id)

        for em in safe_list(e.get("ioc_emails")):
            if isinstance(em, str) and em.strip():
                ind = get_or_create_indicator(indicator_for_email(em.strip()))
                obj_refs.append(ind.id)

        for h in safe_list(e.get("ioc_hashes")):
            if isinstance(h, str) and h.strip():
                ind = get_or_create_indicator(indicator_for_hash(h.strip()))
                obj_refs.append(ind.id)

        # Dedup object refs while preserving order
        seen = set()
        obj_refs_unique = []
        for rid in obj_refs:
            if rid not in seen:
                seen.add(rid)
                obj_refs_unique.append(rid)

        # ---- Report (native fields + custom fields)
        report = Report(
            name=report_name,
            description=item.get("text_de") or "",
            published=parse_date_ddmmyyyy(item.get("report_date")),
            report_types=["threat-report"],
            external_references=ext_refs_from_sources(item.get("sources", [])),
            object_refs=obj_refs_unique,
            created_by_ref=pipeline_identity.id,
            allow_custom=True,

            # ===== Custom fields (everything not mapped natively) =====
            x_section=item.get("section"),
            x_subsection=item.get("subsection"),
            x_subsection_id=item.get("subsection_id"),
            x_subsection_title=item.get("subsection_title"),
            x_report_file=item.get("report_file"),
            x_period_from=item.get("period_from"),
            x_period_to=item.get("period_to"),
            x_tlp=item.get("tlp"),
            x_llm_model=item.get("llm_model"),

            # Keep raw extracted lists as fields too (even if mapped) – ensures nothing is lost
            x_cve_ids=safe_list(e.get("cve_ids")),
            x_cvss_scores=safe_list(e.get("cvss_scores")),
            x_ioc_urls=safe_list(e.get("ioc_urls")),
            x_ioc_domains=safe_list(e.get("ioc_domains")),
            x_ioc_ipv4=safe_list(e.get("ioc_ipv4")),
            x_ioc_emails=safe_list(e.get("ioc_emails")),
            x_ioc_hashes=safe_list(e.get("ioc_hashes")),
            x_organizations=safe_list(e.get("organizations")),
            x_products=safe_list(e.get("products")),
            x_threat_actors=safe_list(e.get("threat_actors")),
            x_malware=safe_list(e.get("malware")),

            # Semantic fields (German free text) – custom
            x_attack_types=safe_list(e.get("attack_types")),
            x_status_phrases=safe_list(e.get("status_phrases")),
            x_measures=safe_list(e.get("measures")),
        )

        objects.append(report)

    bundle = Bundle(objects=objects, allow_custom=True)
    OUTPUT_FILE.write_text(bundle.serialize(pretty=True), encoding="utf-8")
    print(f"[✓] STIX exported (native + custom) → {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
