"""FedRAMP Certification Package Overview import: the package's authorization with the services it certifies, its level
when the provider states one, what the record adds kept on a refresh, other files named and not read."""
import datetime as dt
import json

import pytest

from opsdir.core.directory import get
from opsdir_adapter_fedramp.cpo import cpo_row, read_cpo
from network_fixtures import model


def _cpo(package="F0000000001", services=("Service A", "Service B"), category="High (FedRAMP Certification Level "
                                                                               "Class D)"):
    return {"serviceIdentification": {"fedRampPackageId": package, "providerName": "Example Cloud, Inc.",
                                      "serviceName": "Example Gov Cloud", "serviceAcronym": "EGC",
                                      "serviceDescription": "x", "certificationType": "Rev5", "website": "https://x",
                                      "logo": "https://x/logo.png"},
            "serviceProperties": {"serviceType": ["IaaS"], "deploymentModel": "Government-Only Cloud",
                                  **({"securityCategorization": category} if category else {})},
            "cpoMetadata": {"version": "2026.08.26", "lastUpdated": "2026-08-26T18:21:24.548Z"},
            "contactInformation": [],
            "certifiedServices": [{"serviceName": s, "serviceDescription": s} for s in services]}


def test_a_package_overview_is_read_as_an_authorization_with_its_services():
    row = cpo_row(_cpo())
    assert (row.package_id, row.offering, row.provider, row.certification_type, row.deployment_model, row.level,
            row.services, row.as_of) == ("F0000000001", "Example Gov Cloud", "Example Cloud, Inc.", "Rev5",
                                         "Government-Only Cloud", "fedramp-high", ("Service A", "Service B"),
                                         "20260826182124Z")
    assert cpo_row(_cpo(category=None)).level is None and cpo_row({"x": 1}) is None


def test_the_import_keeps_what_the_record_adds_and_names_changes():
    d, _, _ = model(tree=("dn: ou=authorizations,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\n"
                          "ou: authorizations\n",
                          "dn: cn=F0000000001,ou=authorizations,dc=ciam-ops\nobjectClass: top\n"
                          "objectClass: ciamCloudAuthorization\ncn: F0000000001\nciamPackageId: F0000000001\n"
                          "ciamAuthorizationStatus: certified\nciamCrmRef: CRM v3\nciamInScopeService: Service A\n"
                          "ciamInScopeService: Service Z\n"))
    imported = read_cpo({"egc.json": json.dumps(_cpo()), "notes.txt": "hello"}, d, (), at="20260920000000Z")
    ((scope, (entry,)),) = imported.groups
    assert scope == "cn=F0000000001,ou=authorizations,dc=ciam-ops"
    assert entry.attrs["ciamInScopeService"] == ("Service A", "Service B")
    assert entry.attrs["ciamAuthorizationStatus"] == ("certified",) and entry.attrs["ciamCrmRef"] == ("CRM v3",)
    assert entry.attrs["ciamRetrievedAt"] == ("20260920000000Z",) and "ciamSourceUrl" not in entry.attrs
    assert imported.notices == ("F0000000001 (Example Gov Cloud): 2 service(s) in scope",
                                "F0000000001: added Service B", "F0000000001: no longer in scope: Service Z",
                                "notes.txt: not a FedRAMP Certification Package Overview; not read")
    assert get(d, scope) is not None


def test_nothing_to_import_is_refused():
    d, _, _ = model()
    with pytest.raises(SystemExit):
        read_cpo({"x.json": "{}"}, d, ())


def test_the_import_time_may_be_a_datetime():
    d, _, _ = model()
    imported = read_cpo({"egc.json": json.dumps(_cpo())}, d, (), at=dt.datetime(2026, 9, 23, 9, tzinfo=dt.timezone.utc))
    assert imported.groups[0][1][0].attrs["ciamRetrievedAt"] == ("20260923090000Z",)
