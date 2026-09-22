import json
from functools import lru_cache
from django.conf import settings


@lru_cache(maxsize=1)
def dataset():
    return json.loads(
        (settings.BASE_DIR / "data" / "attack.json").read_text(encoding="utf-8")
    )


@lru_cache(maxsize=1)
def indexes():
    children, tactics = {}, {}
    for row in dataset()["techniques"]:
        if row.get("parent"):
            children.setdefault(row["parent"], []).append(row)
    for row in dataset()["tactics"]:
        tactics[row["slug"]] = row["name"]
    return children, tactics


def children_of(technique_id):
    import copy
    return copy.deepcopy(indexes()[0].get(technique_id, []))


def tactic_name_and_slug(slug):
    name = indexes()[1].get(slug)
    return {"name": name or slug, "slug": slug if name else None}
