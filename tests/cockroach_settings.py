from django.test.runner import DiscoverRunner


DATABASES = {
    'default': {
        'ENGINE': 'django_cockroachdb',
        'NAME': 'django_tests',
        'USER': 'root',
        'PASSWORD': '',
        'HOST': 'localhost',
        'PORT': 26257,
    },
    'other': {
        'ENGINE': 'django_cockroachdb',
        'NAME': 'django_tests2',
        'USER': 'root',
        'PASSWORD': '',
        'HOST': 'localhost',
        'PORT': 26257,
    },
}
SECRET_KEY = 'django_tests_secret_key'
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]
TEST_RUNNER = '.cockroach_settings.NonDescribingDiscoverRunner'
DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

class NonDescribingDiscoverRunner(DiscoverRunner):
    def get_test_runner_kwargs(self):
        return {
            'failfast': self.failfast,
            'resultclass': self.get_resultclass(),
            'verbosity': self.verbosity,
            'descriptions': False,
        }

USE_TZ = False
