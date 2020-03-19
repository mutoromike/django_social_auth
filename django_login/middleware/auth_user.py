# from django.contrib.sessions.models import Session


# # class LoginAPIView(CreateAPIView):
# #     renderer_classes = (UserJSONRenderer,)
# #     serializer_class = LoginSerializer

# #     def post(self, request):
# #         user = request.data.get('user', {})

# #         # Notice here that we do not call `serializer.save()` like we did for
# #         # the registration endpoint. This is because we don't actually have
# #         # anything to save. Instead, the `validate` method on our serializer
# #         # handles everything we need.
        
# #         serializer = self.serializer_class(data=user)
# #         serializer.is_valid(raise_exception=True)
        
# #         return Response(serializer.data, status=status.HTTP_200_OK)


# # def authenticate_user(request):
# #     print(">>>>>>>", request)
# #     # import pdb
# #     # pdb.set_trace()
# #     return request
# # def session_utoken(msg, secret_key, class_name='SessionStore'):
# #     key_salt = "django.contrib.sessions" + class_name
# #     sha1 = hashlib.sha1((key_salt + secret_key).encode('utf-8')).digest()
# #     utoken = hmac.new(sha1, msg=msg, digestmod=hashlib.sha1).hexdigest()
# #     return utoken


# # def decode(session_data, secret_key, class_name='SessionStore'):
# #     encoded_data = base64.b64decode(session_data)
# #     utoken, pickled = encoded_data.split(b':', 1)
# #     expected_utoken = session_utoken(pickled, secret_key, class_name)
# #     if utoken.decode() != expected_utoken:
# #         raise BaseException('Session data corrupted "%s" != "%s"',
# #                             utoken.decode(),
# #                             expected_utoken)
# #     return json.loads(pickled.decode('utf-8'))


# def authenticate_user(get_response):
#     # One-time configuration and initialization.

#     def middleware(request):
#         # Code to be executed for each request before
#         # the view (and later middleware) are called.
#         # print(request.authenticate_user)
#         # s = Session.objects.get(session_key=request.session.session_key)
#         # # daa = decode(s.session_data, os.getenv("SECRET_KEY"))
#         # # session_data = s.get_decoded()
#         # print(s.get_decoded())
#         response = get_response(request)

#         # s = Session.objects.get(session_key=request.session.session_key)
#         # # daa = decode(s.session_data, os.getenv("SECRET_KEY"))
#         # session_data = s.get_decoded()
#         # import pdb
#         # pdb.set_trace()
#         # print(">>>>>>>>>>>>", request)

#         # Code to be executed for each request/response after
#         # the view is called.

#         return response

#     return middleware
