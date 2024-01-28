import os
from datetime import timedelta
from pathlib import Path

import environ

import mysettings

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(DEBUG=(bool, True))
env_file = os.path.join(BASE_DIR, '.env')
env.read_env(env_file)

SECRET_KEY = env("SECRET_KEY")


DEBUG = env('DEBUG')


ALLOWED_HOSTS = []

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    "rest_framework_simplejwt",
    "corsheaders",
    "rest_framework_simplejwt.token_blacklist",
    "django_celery_beat",
    "django_celery_results",
    "user",
    "diary",
    "pay",
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    )
}

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "Our_Liberation_Note.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "Our_Liberation_Note.wsgi.application"
GUNICORN_TIMEOUT = 300

CORS_ALLOW_ALL_ORIGINS = True

DATABASES = mysettings.DATABASES


# 이미지 삽입
MEDIA_ROOT = BASE_DIR / 'media'
MEDIA_URL = '/media/'
FILE_UPLOAD_MAX_MEMORY_SIZE = 10485760

STATIC_ROOT = BASE_DIR / "static"
STATIC_URL = '/static/'

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


LANGUAGE_CODE = "en-us"

TIME_ZONE = "Asia/Seoul"

USE_I18N = True

USE_TZ = False  # False 로 설정해야 DB에 변경 된 TIME_ZONE 이 반영 됨



DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_USE_JWT = True
JWT_AUTH_COOKIE = "jwt_token"
JTW_AUTH_REFRESH_COOKIE = "jwt_refresh_token"

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=3),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": False,
    "UPDATE_LAST_LOGIN": False,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "VERIFYING_KEY": "",
    "AUDIENCE": None,
    "ISSUER": None,
    "JSON_ENCODER": None,
    "JWK_URL": None,
    "LEEWAY": 0,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "USER_AUTHENTICATION_RULE": "rest_framework_simplejwt.authentication.default_user_authentication_rule",
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
    "TOKEN_USER_CLASS": "rest_framework_simplejwt.models.TokenUser",
    "JTI_CLAIM": "jti",
    "SLIDING_TOKEN_REFRESH_EXP_CLAIM": "refresh_exp",
    "SLIDING_TOKEN_LIFETIME": timedelta(minutes=5),
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=1),
    "TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainPairSerializer",
    "TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSerializer",
    "TOKEN_VERIFY_SERIALIZER": "rest_framework_simplejwt.serializers.TokenVerifySerializer",
    "TOKEN_BLACKLIST_SERIALIZER": "rest_framework_simplejwt.serializers.TokenBlacklistSerializer",
    "SLIDING_TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainSlidingSerializer",
    "SLIDING_TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSlidingSerializer",
}

AUTH_USER_MODEL = "user.User"


# Email
EMAIL_BACKEND = env("EMAIL_BACKEND")
EMAIL_HOST = env("EMAIL_HOST", default="smtp.gmail.com")  # 메일 호스트 서버
EMAIL_PORT = env.int("EMAIL_PORT", default=587)  # gmail과 통신하는 포트
EMAIL_HOST_USER = env("EMAIL_HOST_USER")  # 발신할 이메일
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD")  # 발신할 메일의 비밀번호
EMAIL_USE_TLS = env("EMAIL_USE_TLS")  # TLS 보안 방법
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
ACCOUNT_EMAIL_REQUIRED = True  # 이메일 필드가 회원가입 시 필수 필드로 지정

# django celery beat
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "localhost://redis:6379")
CELERY_ACCEPT_CONTENT = ["application/json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "Asia/Seoul"
