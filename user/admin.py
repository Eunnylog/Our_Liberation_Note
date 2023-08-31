from django import forms
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError

from user.models import CheckEmail, User, UserGroup


class UserCreationForm(forms.ModelForm):
    """
    새 유저를 생성하기 위한 폼. 비밀번호 재입력 및 모든 요청 필드를 포함한다.
    """

    password1 = forms.CharField(label="비밀번호", widget=forms.PasswordInput)
    password2 = forms.CharField(label="비밀번호 확인", widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = [
            "email",
        ]

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError("비밀번호가 일치하지 않습니다.")
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    """
    유저 정보를 업데이트하기 위함 폼. 유저의 모든 데이터필드를 포함한다.
    그러나 비밀번호 필드는 관리자가 비활성화한 비밀번호해시 필드로 대체됩니다.
    """

    password = ReadOnlyPasswordHashField(label="비밀번호")

    class Meta:
        model = User
        fields = ["email", "password", "is_active", "is_admin"]


class UserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm

    list_display = ["id", "email", "is_admin"]
    list_display_links = ["email"]
    list_filter = ["is_admin", "is_active"]
    fieldsets = [
        (
            None,
            {
                "fields": [
                    "email",
                ]
            },
        ),
        (
            "Personal info",
            {
                "fields": [
                    "is_active",
                ]
            },
        ),
        ("Permissions", {"fields": ["is_admin"]}),
    ]
    add_fieldsets = [
        (
            None,
            {
                "classes": ["wide"],
                "fields": ["email", "password1", "password2"],
            },
        ),
    ]
    search_fields = ["email"]
    ordering = ["id"]
    filter_horizontal = []

    # 닉네임과 가입날짜는 어드민 페이지에서 수정할 수 없도록 설정
    def get_readonly_fields(self, request, obj=None):
        if obj:
            return (
                "email",
                "join_date",
            )
        else:
            return ("join_date",)


class UserGroupAdmin(admin.ModelAdmin):
    list_display = ("id", "master", "name", "status", "created_at", "updated_at")
    list_display_links = ("name",)
    search_fields = ("name",)
    ordering = ("id",)
    filter_horizontal = ("members",)


class CheckEmailGroupAdmin(admin.ModelAdmin):
    ordering = ("id",)
    list_display_links = ("id",)
    list_display = ("id", "email", "code", "created_at", "expired_at", "is_verified")
    list_filter = ("is_verified",)

admin.site.register(User, UserAdmin)
admin.site.register(UserGroup, UserGroupAdmin)
admin.site.register(CheckEmail, CheckEmailGroupAdmin)
