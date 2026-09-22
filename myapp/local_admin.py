"""Shared management for the trusted, local, signed-in user deployment."""
from django.contrib.admin import AdminSite, ModelAdmin
from django.contrib.auth.views import redirect_to_login
from django.urls import reverse


class LocalAdminSite(AdminSite):
    def has_permission(self, request):
        return bool(request.user.is_authenticated and request.user.is_active)

    def login(self, request, extra_context=None):
        if self.has_permission(request):
            from django.shortcuts import redirect
            return redirect(reverse("admin:index"))
        return redirect_to_login(request.get_full_path())


class LocalPermissions:
    def has_module_permission(self, request):
        return self.admin_site.has_permission(request)

    def has_view_permission(self, request, obj=None):
        return self.admin_site.has_permission(request)

    has_add_permission = has_view_permission
    has_change_permission = has_view_permission
    has_delete_permission = has_view_permission


class LocalModelAdmin(LocalPermissions, ModelAdmin):
    pass


local_admin_site = LocalAdminSite(name="admin")
