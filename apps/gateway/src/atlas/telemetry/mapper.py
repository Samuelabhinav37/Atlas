"""
Threat taxonomy mapping engine for MITRE ATLAS, OWASP Agentic, and NIST AI RMF.
"""

from pathlib import Path

import yaml
from atlas.models import SecurityTaxonomyMapping


class TaxonomyMapper:
    """Resolves and decorates security violations with framework metadata."""

    def __init__(self, taxonomy_dir: Path | None = None):
        if taxonomy_dir is None:
            # Walk up to find taxonomy directory
            current = Path(__file__).resolve().parent
            for _ in range(4):
                candidate = current / "taxonomy"
                if candidate.exists():
                    taxonomy_dir = candidate
                    break
                current = current.parent

        self.taxonomy_dir = taxonomy_dir
        self.atlas_data = self._load_yaml("atlas_matrix.yaml")
        self.owasp_data = self._load_yaml("owasp_agentic.yaml")
        self.nist_data = self._load_yaml("nist_caisi.yaml")

    def _load_yaml(self, filename: str) -> dict:
        if not self.taxonomy_dir:
            return {}
        file_path = self.taxonomy_dir / filename
        if not file_path.exists():
            return {}
        try:
            with open(file_path, encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def enrich(
        self,
        atlas_id: str | None,
        owasp_id: str | None,
        nist_id: str | None,
        reason: str,
    ) -> SecurityTaxonomyMapping:
        """Create an enriched taxonomy mapping object with descriptions."""
        atlas_name = None
        if atlas_id and "techniques" in self.atlas_data:
            technique = self.atlas_data["techniques"].get(atlas_id, {})
            atlas_name = technique.get("name")

        owasp_name = None
        if owasp_id and "categories" in self.owasp_data:
            category = self.owasp_data["categories"].get(owasp_id, {})
            owasp_name = category.get("name")

        return SecurityTaxonomyMapping(
            atlas_technique=atlas_id,
            atlas_name=atlas_name,
            owasp_category=owasp_id,
            owasp_name=owasp_name,
            nist_control=nist_id,
            reason=reason,
        )


# Global instance
taxonomy_mapper = TaxonomyMapper()
