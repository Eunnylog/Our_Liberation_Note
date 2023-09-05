from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from user import views

urlpatterns = [
    path("signup/", views.SignUpAPI.as_view(), name="signup"),
    path("login/", views.SignInAPI.as_view(), name="login"),
    path("refresh/", TokenRefreshView.as_view(), name='token-refresh'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path("send-email/", views.SendEmailAPI.as_view(), name="send_email"),
    path("change-password/", views.ChangePassword.as_view(), name="changepassword"),

    path("social/", views.SocialUrlView.as_view(), name="social_login"),
    path("kakao/", views.KakaoLoginView.as_view(), name="kakao_login"),
    path("naver/", views.NaverLoginView.as_view(), name="naver_login"),
    path("google/", views.GoogleLoginView.as_view(), name="google_login"),

    path("", views.UserView.as_view(), name="user_view"),
    path("my-page/", views.MyPageView.as_view(), name="my_page"),
    path("user-list/", views.UserListView.as_view(), name="user_list"),

    path("group/", views.GroupView.as_view(), name="group"),
    path("group/<int:group_id>/", views.GroupDetailView.as_view(), name="group_detail"),
]
