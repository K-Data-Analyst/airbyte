#
# Copyright (c) 2023 Airbyte, Inc., all rights reserved.
#

import hashlib
import hmac
import urllib.parse
from typing import Any, Mapping
from urllib.parse import urlparse
import boto3
from uuid import uuid4

from boto3 import Session
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session

import pendulum
import requests
from airbyte_cdk.sources.streams.http.auth import Oauth2Authenticator
from requests.auth import AuthBase


class AWSAuthenticator(Oauth2Authenticator):
    def __init__(self, host: str, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.host = host

    def get_auth_header(self) -> Mapping[str, Any]:
        return {
            "host": self.host,
            "user-agent": "python-requests",
            "x-amz-access-token": self.get_access_token(),
            "x-amz-date": pendulum.now("utc").strftime("%Y%m%dT%H%M%SZ"),
        }


class RefreshableBotoSession:
    """
    Boto Helper class which lets us create refreshable session, so that we can cache the client or resource.

    Usage
    -----
    session = RefreshableBotoSession().refreshable_session()

    client = session.client("s3") # we now can cache this client object without worrying about expiring credentials
    """

    def __init__(
            self,
            region_name: str = None,
            aws_access_key_id: str = None,
            aws_secret_access_key: str = None,
            sts_arn: str = None,
            session_name: str = None,
            session_ttl: int = 3000
    ):
        """
        Initialize `RefreshableBotoSession`

        Parameters
        ----------
        region_name : str (optional)
            Default region when creating new connection.

        aws_access_key_id : str
        aws_secret_access_key : str

        sts_arn : str (optional)
            The role arn to sts before creating session.

        session_name : str (optional)
            An identifier for the assumed role session. (required when `sts_arn` is given)

        session_ttl : int (optional)
            An integer number to set the TTL for each session. Beyond this session, it will renew the token.
            50 minutes by default which is before the default role expiration of 1 hour
        """

        self.region_name = region_name
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.sts_arn = sts_arn
        self.session_name = session_name or uuid4().hex
        self.session_ttl = session_ttl

    def __get_session_credentials(self):
        """
        Get session credentials
        """
        # session = Session(region_name=self.region_name,
        #                   aws_access_key_id=self.aws_access_key_id,
        #                   aws_secret_access_key=self.aws_secret_access_key)

        # if sts_arn is given, get credential by assuming given role

        sts_client = boto3.client("sts", aws_access_key_id=self.aws_access_key_id, aws_secret_access_key=self.aws_secret_access_key)
        response = sts_client.assume_role(
            RoleArn=self.sts_arn,
            RoleSessionName=self.session_name,
            DurationSeconds=self.session_ttl,
        ).get("Credentials")

        credentials = {
            "access_key": response.get("AccessKeyId"),
            "secret_key": response.get("SecretAccessKey"),
            "token": response.get("SessionToken"),
            "expiry_time": response.get("Expiration").isoformat(),
        }
        return credentials

    def refreshable_session(self) -> Session:
        """
        Get refreshable boto3 session.
        """
        # get refreshable credentials
        refreshable_credentials = RefreshableCredentials.create_from_metadata(
            metadata=self.__get_session_credentials(),
            refresh_using=self.__get_session_credentials,
            method="sts-assume-role",
        )

        # attach refreshable credentials current session
        session = get_session()
        session._credentials = refreshable_credentials
        session.set_config_variable("region", self.region_name)
        autorefresh_session = Session(botocore_session=session)

        return autorefresh_session

    def refreshable_credentials(self):
        return RefreshableCredentials.create_from_metadata(
            metadata=self.__get_session_credentials(),
            refresh_using=self.__get_session_credentials,
            method="sts-assume-role",
        )


class AWSSignature(AuthBase):
    """Source from https://github.com/saleweaver/python-amazon-sp-api/blob/master/sp_api/base/aws_sig_v4.py"""

    def __init__(self, service: str,
                 aws_access_key_id: str, aws_secret_access_key: str, region: str, aws_session_token: str = None, role_arn: str = None):
        self.service = service
        self.refreshable_credentials = RefreshableBotoSession(region_name=region, aws_access_key_id=aws_access_key_id,
                                                              aws_secret_access_key=aws_secret_access_key,
                                                              sts_arn=role_arn).refreshable_credentials()

        self.aws_access_key_id = self.refreshable_credentials.access_key
        self.aws_secret_access_key = self.refreshable_credentials.secret_key

        self.aws_session_token = self.refreshable_credentials.token
        self._token = aws_session_token
        self.region = region

    @staticmethod
    def _sign_msg(key: bytes, msg: str) -> bytes:
        """Sign message using key"""
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def _get_authorization_header(self, prepared_request: requests.PreparedRequest) -> str:
        current_ts = pendulum.now("utc")
        url_parsed = urlparse(prepared_request.url)
        uri = urllib.parse.quote(url_parsed.path)
        host = url_parsed.hostname

        amz_date = current_ts.strftime("%Y%m%dT%H%M%SZ")
        datestamp = current_ts.strftime("%Y%m%d")

        # sort query parameters alphabetically
        if len(url_parsed.query) > 0:
            split_query_parameters = list(map(lambda param: param.split("="), url_parsed.query.split("&")))
            ordered_query_parameters = sorted(split_query_parameters, key=lambda param: (param[0], param[1]))
        else:
            ordered_query_parameters = list()

        canonical_querystring = "&".join(map(lambda param: "=".join(param), ordered_query_parameters))

        headers_to_sign = {"host": host, "x-amz-date": amz_date}
        if self.aws_session_token:
            headers_to_sign["x-amz-security-token"] = self.aws_session_token
        ordered_headers = dict(sorted(headers_to_sign.items(), key=lambda h: h[0]))
        canonical_headers = "".join(map(lambda h: ":".join(h) + "\n", ordered_headers.items()))
        signed_headers = ";".join(ordered_headers.keys())

        if prepared_request.method == "GET":
            payload_hash = hashlib.sha256("".encode("utf-8")).hexdigest()
        else:
            if prepared_request.body:
                payload_hash = hashlib.sha256(prepared_request.body.encode("utf-8")).hexdigest()
            else:
                payload_hash = hashlib.sha256("".encode("utf-8")).hexdigest()

        canonical_request = "\n".join(
            [prepared_request.method, uri, canonical_querystring, canonical_headers, signed_headers, payload_hash]
        )

        credential_scope = "/".join([datestamp, self.region, self.service, "aws4_request"])
        string_to_sign = "\n".join(
            ["AWS4-HMAC-SHA256", amz_date, credential_scope, hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()]
        )

        datestamp_signed = self._sign_msg(("AWS4" + self.aws_secret_access_key).encode("utf-8"), datestamp)
        region_signed = self._sign_msg(datestamp_signed, self.region)
        service_signed = self._sign_msg(region_signed, self.service)
        aws4_request_signed = self._sign_msg(service_signed, "aws4_request")
        signature = hmac.new(aws4_request_signed, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        authorization_header = "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}".format(
            self.aws_access_key_id, credential_scope, signed_headers, signature
        )
        return authorization_header

    def __call__(self, prepared_request: requests.PreparedRequest) -> requests.PreparedRequest:
        prepared_request.headers.update(
            {
                "authorization": self._get_authorization_header(prepared_request),
                "x-amz-security-token": self.aws_session_token,
            }
        )
        return prepared_request
