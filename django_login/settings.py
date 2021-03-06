import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# SESSION_COOKIE_SECURE = True
# SESSION_COOKIE_SAMESITE = None
# SOCIAL_AUTH_REDIRECT_IS_HTTPS = True


ALLOWED_HOSTS = []

REST_FRAMEWORK = {

    'DEFAULT_AUTHENTICATION_CLASSES': (
        'django_login.apps.authentication.backends.Authentication',
    ),

}
# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'rest_framework_swagger',
    'corsheaders',
    'rest_framework',
    'social_django',

    'django_login.apps.authentication',
    'django_login.apps.core'

]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'social_django.middleware.SocialAuthExceptionMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    # 'django_login.middleware.auth_user.authenticate_user'
]

ROOT_URLCONF = 'django_login.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'django_login/templates')
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'django_login.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'PORT': os.getenv('DB_PORT'),
        'HOST': os.getenv('DB_HOST')
    }
}


# Password validation
# https://docs.djangoproject.com/en/2.1/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator', # Noqa E501
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

AUTHENTICATION_BACKENDS = (
    'social_core.backends.twitter.TwitterOAuth',  # for Twitter authentication
    'social_core.backends.facebook.FacebookOAuth2',  # for Facebook authentication
    'social_core.backends.google.GoogleOpenId',  # for Google authentication
    'social_core.backends.google.GoogleOAuth2',  # for Google authentication

    'django.contrib.auth.backends.ModelBackend',
)

# Facebook App Keys
SOCIAL_AUTH_FACEBOOK_KEY = os.getenv('SOCIAL_AUTH_FACEBOOK_KEY')
SOCIAL_AUTH_FACEBOOK_SECRET = os.getenv('SOCIAL_AUTH_FACEBOOK_SECRET')
SOCIAL_AUTH_FACEBOOK_SCOPE = ['email']
SOCIAL_AUTH_FACEBOOK_PROFILE_EXTRA_PARAMS = {
    'fields': 'id, name, email',
}

FACEBOOK_EXTENDED_PERMISSIONS = ['email']

# Twitter App Keys
SOCIAL_AUTH_TWITTER_KEY = os.getenv('SOCIAL_AUTH_TWITTER_KEY')
SOCIAL_AUTH_TWITTER_SECRET = os.getenv('SOCIAL_AUTH_TWITTER_SECRET')

SOCIAL_AUTH_TWITTER_SCOPE = ['email', 'username']
SOCIAL_AUTH_TWITTER_PROFILE_EXTRA_PARAMS = {
    'fields': 'id, name, email',
}

# Google App Keys
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = os.getenv('SOCIAL_AUTH_GOOGLE_OAUTH2_KEY')
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = os.getenv(
    'SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET')

SOCIAL_AUTH_GOOGLE_OAUTH_SCOPE = ['email', 'username']

SOCIAL_AUTH_ADMIN_USER_SEARCH_FIELDS = ['email']

SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.associate_by_email',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'social_core.pipeline.user.create_user',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
)

SOCIAL_AUTH_LOGIN_URL = 'api/user/login'
SOCIAL_AUTH_LOGOUT_URL = 'api/user/login'
SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/home'
SOCIAL_AUTH_LOGIN_ERROR_URL = 'api/user/login'


# Internationalization
# https://docs.djangoproject.com/en/2.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


CORS_ORIGIN_WHITELIST = (
    '0.0.0.0:4000',
    'localhost:4000',
)

# Tell Django about the custom `User` model we created. The string
# `authentication.User` tells Django we are referring to the `User` model in
# the `authentication` module. This module is registered above in a setting
# called `INSTALLED_APPS`.
AUTH_USER_MODEL = 'authentication.User'

SOCIAL_AUTH_USER_MODEL = AUTH_USER_MODEL

REST_FRAMEWORK = {
    'EXCEPTION_HANDLER': 'django_login.apps.core.exceptions.core_exception_handler', # Noqa E501
    'NON_FIELD_ERRORS_KEY': 'error',

    'DEFAULT_AUTHENTICATION_CLASSES': (
        'django_login.apps.authentication.backends.Authentication',
    ),

    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination', # Noqa E501
    'PAGE_SIZE': 10
}

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.9/howto/static-files/
STATIC_ROOT = os.path.join(BASE_DIR, 'django_login/staticfiles')
STATIC_URL = '/static/'

# sets session auth to false and dissables the Session login button
SWAGGER_SETTINGS = {
    'SHOW_REQUEST_HEADERS': True,
    'USE_SESSION_AUTH': False,
    'DOC_EXPANSION': 'list',
    'SECURITY_DEFINITIONS': {
        'api_key': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization'
        }
    }
}

# Email
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST = 'smtp.googlemail.com'
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER