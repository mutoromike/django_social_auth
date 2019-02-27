import re
from django.contrib.auth import authenticate

from rest_framework import serializers
from rest_framework.validators import UniqueValidator

# local imports
from django_login.apps.authentication.models import User

from .backends import Authentication


class RegistrationSerializer(serializers.ModelSerializer):
    """Serializes registration requests and creates a new user."""

    # Ensure passwords are at least 8 characters long, no longer than 128
    # characters, and can not be read by the client.
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True,
        required=True,
        error_messages={
            'min_length': 'Please provide a password with at least 8 characters.', # Noqa E501
            'required': 'Please provide a password.'
        }
    )

    # Ensure the password has alphanumeric characters
    def validate_password(self, data):
        """
        Validator function to check for valid password.
        """
        # Ensure the password contains at least one number,
        # at least one uppercase letter
        # at least one lowercase letter
        # at least one special character.
        num = re.match(r"^(?=.*[0-9])", data)
        caps = re.match(r"^(?=.*[A-Z])", data)
        lower = re.match(r"^(?=.*[a-z])", data)
        special = re.match(r"^(?=.*[\!\@#\$%\^&\.])", data)

        if not num or not caps or not lower or not special:
            raise serializers.ValidationError(
                'Password should have at least one number, '
                'an uppercase or lowercase letter or one special character.')
        return data

    # Ensure email entered by the user upon
    # registration has not been used before.
    email = serializers.EmailField(
        validators=[
            UniqueValidator(
                queryset=User.objects.all(),
                message=(
                    'Email is already registered. '
                    'Have you tried logging in?'
                )
            )
        ]
    )

    # token fields
    token = serializers.SerializerMethodField()
    refresh_token = serializers.SerializerMethodField()

    def validate_username(self, data):
        """
        Validator function to check for valid username
        """
        # Ensure the username is at least 4 characters long
        # and does not contain numbers only.
        if re.match(r"^[0-9]*$", data) or len(data) < 4:
            raise serializers.ValidationError(
                'Username should be at least 4 characters long '
                'and should not contain numbers only.'
            )
        return data
    # token fields
    token = serializers.SerializerMethodField()
    refresh_token = serializers.SerializerMethodField()

    # The client should not be able to send a token along with a registration
    # request. Making `token` read-only handles that for us.

    class Meta:
        model = User
        # List all of the fields that could possibly be included in a request
        # or response, including fields specified explicitly above.
        fields = ['email', 'username', 'password', 'token', 'refresh_token']

    def create(self, validated_data):
        # Use the `create_user` method we wrote earlier to create a new user.
        return User.objects.create_user(**validated_data)

    def get_token(self, obj):
        """ Get user access token
        :args
        obj - UserModel instance
        """
        return Authentication.generate_jwt_token(
            user=obj.json(),
            refresh_token=False
        )

    def get_refresh_token(self, obj):
        """ Get user refresh_token
        :args
        obj - UserModel instance
        """
        return Authentication.generate_jwt_token(
            user=obj.json(),
            refresh_token=True
        )


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255)
    username = serializers.CharField(max_length=255, read_only=True)
    password = serializers.CharField(max_length=128, write_only=True)

    # token fields
    token = serializers.SerializerMethodField()
    refresh_token = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'token', 'refresh_token']

    def get_token(self, obj):
        """ get user access token
        :args
        obj - UserModel instance
        """
        return Authentication.generate_jwt_token(
            user=obj,
            refresh_token=False
        )

    def get_refresh_token(self, obj):
        """ get user refresh token
        :args
        obj - UserModel instance
        """
        return Authentication.generate_jwt_token(
            user=obj,
            refresh_token=True
        )

    def validate(self, data):
        # The `validate` method is where we make sure that the current
        # instance of `LoginSerializer` has "valid". In the case of logging a
        # user in, this means validating that they've provided an email
        # and password and that this combination matches one of the users in
        # our database.
        email = data.get('email', None)
        password = data.get('password', None)

        # As mentioned above, an email is required. Raise an exception if an
        # email is not provided.
        if email is None:
            raise serializers.ValidationError(
                'An email address is required to log in.'
            )

        # As mentioned above, a password is required. Raise an exception if a
        # password is not provided.
        if password is None:
            raise serializers.ValidationError(
                'A password is required to log in.'
            )

        # The `authenticate` method is provided by Django and handles checking
        # for a user that matches this email/password combination. Notice how
        # we pass `email` as the `username` value. Remember that, in our User
        # model, we set `USERNAME_FIELD` as `email`.
        user = authenticate(username=email, password=password)
        # If no user was found matching this email/password combination then
        # `authenticate` will return `None`. Raise an exception in this case.
        if user is None:
            raise serializers.ValidationError(
                'A user with this email and password was not found.'
            )

        # Django provides a flag on our `User` model called `is_active`. The
        # purpose of this flag to tell us whether the user has been banned
        # or otherwise deactivated. This will almost never be the case, but
        # it is worth checking for. Raise an exception in this case.
        if not user.is_active:
            raise serializers.ValidationError(
                'This user has been deactivated.'
            )

        # The `validate` method should return a dictionary of validated data.
        # This is the data that is passed to the `create` and `update` methods
        # that we will see later on.
        return {
            'email': user.email,
            'username': user.username,

        }


class UserSerializer(serializers.ModelSerializer):
    """Handles serialization and deserialization of User objects."""

    # Passwords must be at least 8 characters, but no more than 128
    # characters. These values are the default provided by Django. We could
    # change them, but that would create extra work while introducing no real
    # benefit, so let's just stick with the defaults.
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True
    )

    class Meta:
        model = User
        fields = ('email', 'username', 'password')

        # The `read_only_fields` option is an alternative for explicitly
        # specifying the field with `read_only=True` like we did for password
        # above. The reason we want to use `read_only_fields` here is because
        # we don't need to specify anything else about the field. For the
        # password field, we needed to specify the `min_length` and
        # `max_length` properties too, but that isn't the case for the token
        # field.

    def update(self, instance, validated_data):
        """Performs an update on a User."""

        # Passwords should not be handled with `setattr`, unlike other fields.
        # This is because Django provides a function that handles hashing and
        # salting passwords, which is important for security. What that means
        # here is that we need to remove the password field from the
        # `validated_data` dictionary before iterating over it.
        password = validated_data.pop('password', None)

        for (key, value) in validated_data.items():
            # For the keys remaining in `validated_data`, we will set them on
            # the current `User` instance one at a time.
            setattr(instance, key, value)

        if password is not None:
            # `.set_password()` is the method mentioned above. It handles all
            # of the security stuff that we shouldn't be concerned with.
            instance.set_password(password)

        # Finally, after everything has been updated, we must explicitly save
        # the model. It's worth pointing out that `.set_password()` does not
        # save the model.
        instance.save()

        return instance


class ResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField(max_length=255, read_only=True)

    # List the fields that should b

    def validate(self, data):
        """
        Validate the email entered by the user that requests to reset account password # Noqa E501
        """
        email = data.get('email', None)

        # Check if user just posted an empty object.
        # Respond with error message, with description that email is required.
        if email is None:
            raise serializers.ValidationError(
                'An email address is required to send request.'
            )

        # Check if a user is registered with the entered email.
        # If a match is found, retrieve the instance. Use the instance to generate # Noqa E501
        # a token to be used to allow user to change password. Return the email and token # Noqa E501
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            token = Authentication.generate_jwt_token(
                user={'username': user.username},
                refresh_token=False)
            return {
                "email": email,
                "token": token
            }

        # If email is not associated with any account raise an error
        raise serializers.ValidationError(
            'The email address is not registered!. Please enter the email to your account.' # Noqa E501
        )
