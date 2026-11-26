from logging import getLogger
from typing import Optional

from axes.conf import settings
from axes.handlers.base import AxesBaseHandler, AbstractAxesHandler
from axes.helpers import (
    get_cache,
    get_cache_timeout,
    get_client_cache_key_pairs,
    get_client_str,
    get_client_username,
    get_credentials,
    get_failure_limit,
    get_lockout_parameters,
)
from axes.models import AccessAttempt
from axes.signals import user_locked_out

log = getLogger(__name__)


class AxesCacheHandler(AbstractAxesHandler, AxesBaseHandler):
    """
    Signal handler implementation that records user login attempts to cache and locks users out if necessary.
    """

    def __init__(self):
        self.cache = get_cache()

    def reset_attempts(
        self,
        *,
        ip_address: Optional[str] = None,
        username: Optional[str] = None,
        ip_or_username: bool = False,
    ) -> int:
        cache_keys: set = set()
        count = 0

        if ip_address is None and username is None:
            raise NotImplementedError("Cannot clear all entries from cache")
        if ip_or_username:
            raise NotImplementedError(
                "Due to the cache key ip_or_username=True is not supported"
            )

        for cache_key, legacy_cache_key in get_client_cache_key_pairs(
            AccessAttempt(username=username, ip_address=ip_address)
        ):
            cache_keys.add(cache_key)
            cache_keys.add(legacy_cache_key)

        for cache_key in cache_keys:
            deleted = self.cache.delete(cache_key)
            count += int(deleted) if deleted is not None else 1

        log.info("AXES: Reset %d access attempts from database.", count)

        return count

    def get_failures(self, request, credentials: Optional[dict] = None) -> int:
        failures = []
        for cache_key, legacy_cache_key in get_client_cache_key_pairs(
            request, credentials
        ):
            cache_keys = {cache_key, legacy_cache_key}
            failures.append(sum(self.cache.get(key, default=0) for key in cache_keys))
        return max(failures)

    def _increment_cache_failure(
        self,
        cache_key: str,
        legacy_cache_key: str,
        cache_timeout: Optional[int],
    ) -> int:
        added = self.cache.add(key=cache_key, value=1, timeout=cache_timeout)
        if added:
            failures = 1
        else:
            try:
                failures = self.cache.incr(key=cache_key, delta=1)
            except ValueError:
                # The key expired between the add and the incr above, so the
                # cool off period has elapsed and this failure starts a new
                # count.
                self.cache.add(key=cache_key, value=1, timeout=cache_timeout)
                failures = 1
            else:
                self.cache.touch(key=cache_key, timeout=cache_timeout)

        if legacy_cache_key != cache_key:
            failures += self.cache.get(legacy_cache_key, default=0)

        return failures

    def user_login_failed(self, sender, credentials: dict, request=None, **kwargs):
        """
        When user login fails, save attempt record in cache and lock user out if necessary.

        :raises AxesSignalPermissionDenied: if user should be locked out.
        """

        if request is None:
            log.error(
                "AXES: AxesCacheHandler.user_login_failed does not function without a request."
            )
            return

        username = get_client_username(request, credentials)
        lockout_parameters = get_lockout_parameters(request, credentials)
        if lockout_parameters == ["username"] and username is None:
            log.warning(
                "AXES: Username is None and username is the only one lockout parameter, new record will NOT be created."
            )
            return

        # If axes denied access, don't record the failed attempt as that would reset the lockout time.
        if (
            not settings.AXES_RESET_COOL_OFF_ON_FAILURE_DURING_LOCKOUT
            and request.axes_locked_out
        ):
            request.axes_credentials = credentials
            user_locked_out.send(
                "axes",
                request=request,
                username=username,
                ip_address=request.axes_ip_address,
            )
            return

        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        if self.is_whitelisted(request, credentials):
            log.info("AXES: Login failed from whitelisted client %s.", client_str)
            return

        cache_timeout = get_cache_timeout(request)
        failures = []
        for cache_key, legacy_cache_key in get_client_cache_key_pairs(
            request, credentials
        ):
            failures.append(
                self._increment_cache_failure(
                    cache_key, legacy_cache_key, cache_timeout
                )
            )

        failures_since_start = max(failures)
        request.axes_failures_since_start = failures_since_start

        if failures_since_start > 1:
            log.warning(
                "AXES: Repeated login failure by %s. Count = %d of %d. Updating existing record in the cache.",
                client_str,
                failures_since_start,
                get_failure_limit(request, credentials),
            )
        else:
            log.warning(
                "AXES: New login failure by %s. Creating new record in the cache.",
                client_str,
            )

        if (
            settings.AXES_LOCK_OUT_AT_FAILURE
            and failures_since_start >= get_failure_limit(request, credentials)
        ):
            log.warning(
                "AXES: Locking out %s after repeated login failures.", client_str
            )

            request.axes_locked_out = True
            request.axes_credentials = credentials
            user_locked_out.send(
                "axes",
                request=request,
                username=username,
                ip_address=request.axes_ip_address,
            )

    def user_logged_in(self, sender, request, user, **kwargs):
        """
        When user logs in, update the AccessLog related to the user.
        """

        username = user.get_username()
        credentials = get_credentials(username)
        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        log.info("AXES: Successful login by %s.", client_str)

        if settings.AXES_RESET_ON_SUCCESS:
            for cache_key, legacy_cache_key in get_client_cache_key_pairs(
                request, credentials
            ):
                cache_keys = {cache_key, legacy_cache_key}
                failures_since_start = sum(
                    self.cache.get(key, default=0) for key in cache_keys
                )
                for key in cache_keys:
                    self.cache.delete(key)
                log.info(
                    "AXES: Deleted %d failed login attempts by %s from cache.",
                    failures_since_start,
                    client_str,
                )

    def user_logged_out(self, sender, request, user, **kwargs):
        username = user.get_username() if user else None
        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        log.info("AXES: Successful logout by %s.", client_str)
