import logging
import os
import time
from functools import wraps

from saic_ismart_client.constants import AVG_SMS_DELIVERY_TIME
from saic_ismart_client.exceptions import SaicApiException

LOG = logging.getLogger(__name__)
LOG.setLevel(level=os.getenv('LOG_LEVEL_' + __name__, 'INFO').upper())


def saic_api_retry_no_app_data(fun):
    @wraps(fun)
    def decorator(self, *args, **kwargs):
        event_id = None
        if 'event_id' in kwargs:
            event_id = kwargs['event_id']

        rsp_msg = fun(self, *args, **(kwargs | {'event_id': event_id}))

        retry = 1
        while (
                rsp_msg.body.error_message is not None
                and retry <= 3
        ):
            self.handle_error(rsp_msg.body)
            event_id = rsp_msg.body.event_id
            rsp_msg = fun(self, *args, **(kwargs | {'event_id': event_id}))
            retry += 1
        if rsp_msg.body.error_message is not None:
            raise SaicApiException(rsp_msg.body.error_message.decode(), rsp_msg.body.result)

        return rsp_msg

    return decorator


def saic_api_retry(fun):
    @wraps(fun)
    def decorator(self, *args, **kwargs):
        event_id = None
        if 'event_id' in kwargs:
            event_id = kwargs['event_id']

        rsp_msg = fun(self, *args, **(kwargs | {'event_id': event_id}))

        while rsp_msg.application_data is None:
            if rsp_msg.body.error_message is not None:
                self.handle_error(rsp_msg.body)
            else:
                LOG.debug('API request returned no application data and no error message.')
                time.sleep(float(AVG_SMS_DELIVERY_TIME))
            event_id = rsp_msg.body.event_id
            rsp_msg = fun(self, *args, **(kwargs | {'event_id': event_id}))
        return rsp_msg

    return decorator
