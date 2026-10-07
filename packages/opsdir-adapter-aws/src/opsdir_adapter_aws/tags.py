"""The tags an AWS resource carries as Terraform state reports them: its own tags and those the provider adds to every
resource (default_tags), which state keeps only in tags_all. Pure."""


def state_tags(a):
    """{key: value} of a Terraform state resource's tags: tags_all (the provider's default tags included) with its own
    tags over them."""
    return {**(a.get("tags_all") or {}), **(a.get("tags") or {})}
