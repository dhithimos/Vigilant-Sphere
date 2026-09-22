from django.conf import settings
from urllib.parse import urlsplit


def site_context(request):
    def link(name):
        value = getattr(settings, name, "")
        return (
            value
            if urlsplit(value).scheme in {"http", "https"} and urlsplit(value).hostname
            else ""
        )

    from .models import FeatureFlag, CMSDeveloperProfile

    chatbot_enabled = (
        request.user.is_authenticated
        and not FeatureFlag.objects.filter(
            key="OFFLINE_SECURITY_CHATBOT", enabled=False
        ).exists()
    )
    profile=CMSDeveloperProfile.objects.order_by("pk").first()
    return {
        "site_developer_name":profile.developer_name if profile else "Dhithimos E J",
        "chatbot_launcher": chatbot_enabled and request.path != "/chatbot/",
        "can_inspect_host": can_inspect_host(request.user),
        "developer_github": profile.github if profile and urlsplit(profile.github).scheme in {"http","https"} else link("DEVELOPER_GITHUB_URL"),
        "developer_linkedin": profile.linkedin if profile and urlsplit(profile.linkedin).scheme in {"http","https"} else link("DEVELOPER_LINKEDIN_URL"),
        "project_github": link("VIGILANT_SPHERE_GITHUB_URL"),
    }


def can_inspect_host(user):
    """Host inspection is available to every active signed-in local user."""
    return bool(user.is_authenticated and user.is_active)
