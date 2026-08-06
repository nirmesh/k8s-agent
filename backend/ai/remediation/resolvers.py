from __future__ import annotations


# Curated, verified tags for well-known public images. The first tag in each
# list is the default safe suggestion when the current tag is not recognised.
WELL_KNOWN_TAGS: dict[str, list[str]] = {
    "nginx": ["1.27", "stable", "alpine", "mainline", "perl", "latest"],
    "redis": ["7.4", "7.2", "alpine", "latest"],
    "busybox": ["1.36", "musl", "glibc", "latest"],
    "postgres": ["16.2", "15.6", "alpine", "latest"],
    "mysql": ["8.3", "8.0", "latest"],
    "ubuntu": ["24.04", "22.04", "latest"],
    "alpine": ["3.20", "3.19", "latest"],
}


def _repo_and_tag(image: str):
    repo = image.split(":")[0].split("@")[0].split("/")[-1].lower()
    tag = image.split(":")[1] if ":" in image else "latest"
    return repo, tag


def resolve_safe_tag(image: str) -> str | None:
    """Return a verified safe tag for a well-known public image.

    For unknown or private repositories this returns None so the engine does not
    hallucinate tags.
    """
    if not image:
        return None
    repo, _ = _repo_and_tag(image)
    tags = WELL_KNOWN_TAGS.get(repo)
    if not tags:
        return None
    return f"{repo}:{tags[0]}"


def is_known_tag(image: str) -> bool:
    """Return True when the image tag is in the curated known-good list."""
    if not image:
        return False
    repo, tag = _repo_and_tag(image)
    tags = WELL_KNOWN_TAGS.get(repo)
    return bool(tags and tag in tags)
