import pytest
from pydantic import ValidationError

from cti.models import Document


def test_document_is_immutable_and_ids_are_namespaced():
    doc = Document(
        id=Document.make_id("kev", "CVE-2024-0001"),
        source="kev",
        source_id="CVE-2024-0001",
        title="t",
        cves=("CVE-2024-0001",),
    )
    assert doc.id == "kev:CVE-2024-0001"
    with pytest.raises(ValidationError):
        doc.title = "changed"
