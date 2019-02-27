from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import six


class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    """
    Generate token for activation of account
    """

    def _make_hash_value(self, user, timestamp):
        """
        Make the have value for the activation link
        """

        pk = six.text_type(user.get('pk'))
        timestamp = six.text_type(timestamp)
        is_active = six.text_type(user.get('is_active'))
        return pk + timestamp + is_active


account_activation_token = AccountActivationTokenGenerator()
