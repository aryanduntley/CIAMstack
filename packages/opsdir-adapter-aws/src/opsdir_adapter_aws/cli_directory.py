"""The Directory Service outputs of the AWS CLI, normalized to the attribute names of the matching Terraform resource
(opsdir_adapter_aws.directory reads both). Pure.

  ds describe-directories               DirectoryDescriptions  -> aws_directory_service_directory: its ID, type, domain,
    (projected: --query)                                          NetBIOS name, edition, VPC, further regions
                                                                  (additional_regions)
  ds list-tags-for-resource             Tags                   -> its tags; saved as directory-tags/<directory ID>.json

The collector projects describe-directories to those fields (an allowlist): a directory's RADIUS settings carry a
shared secret, and nothing else is needed. Directory Service never returns the Admin password.
"""
from .cli_outputs import folder_tags, items

KEYS = ("DirectoryDescriptions",)
TAGS_FOLDER = "directory-tags"
# the describe-directories fields the reader uses (what collect.py's --query keeps)
DIRECTORY_QUERY = ("{DirectoryDescriptions: DirectoryDescriptions[].{DirectoryId: DirectoryId, Type: Type, Name: Name, "
                   "ShortName: ShortName, Edition: Edition, VpcSettings: {VpcId: VpcSettings.VpcId}, "
                   "RegionsInfo: {AdditionalRegions: RegionsInfo.AdditionalRegions}}}")


def _directory(o, tags):
    return "aws_directory_service_directory", {
        "id": o.get("DirectoryId"), "type": o.get("Type"), "name": o.get("Name"), "short_name": o.get("ShortName"),
        "edition": o.get("Edition"), "vpc_id": (o.get("VpcSettings") or {}).get("VpcId"),
        "additional_regions": list((o.get("RegionsInfo") or {}).get("AdditionalRegions") or ()),
        "tags": tags.get(o.get("DirectoryId"), {})}


def directory_pairs(outs):
    """The (Terraform type, attributes) pairs of the managed Microsoft AD directories among the recognized CLI outputs
    (Simple AD and AD Connector aren't managed directories the record holds)."""
    tags = folder_tags(outs, TAGS_FOLDER)
    return [_directory(o, tags) for o in items(outs, "DirectoryDescriptions")
            if isinstance(o, dict) and o.get("Type") == "MicrosoftAD"]
