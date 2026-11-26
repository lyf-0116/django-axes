from django.core.cache import cache
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext

from axes.handlers.database import AxesDatabaseHandler
from axes.helpers import get_client_cache_keys
from axes.models import AccessAttempt
from tests.base import AxesTestCase


@override_settings(AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler")
class DatabaseFailureCacheTestCase(AxesTestCase):
    def setUp(self):
        super().setUp()
        self.handler = AxesDatabaseHandler()
        self.cache_key = get_client_cache_keys(self.request, self.credentials)[0]

    def aggregate_queries(self, capture):
        return [
            query
            for query in capture.captured_queries
            if "SUM(" in query["sql"].upper() and "failures_since_start" in query["sql"]
        ]

    def test_get_failures_caches_aggregate_result(self):
        self.create_attempt(failures_since_start=2)

        with self.assertNumQueries(1):
            self.assertEqual(
                2, self.handler.get_failures(self.request, self.credentials)
            )

        self.assertEqual(2, cache.get(self.cache_key))

        with self.assertNumQueries(0):
            self.assertEqual(
                2, self.handler.get_failures(self.request, self.credentials)
            )

    def test_get_failures_caches_zero_result(self):
        with self.assertNumQueries(1):
            self.assertEqual(
                0, self.handler.get_failures(self.request, self.credentials)
            )

        with self.assertNumQueries(0):
            self.assertEqual(
                0, self.handler.get_failures(self.request, self.credentials)
            )

    def test_post_save_invalidates_cached_failures(self):
        attempt = self.create_attempt(failures_since_start=2)
        self.handler.get_failures(self.request, self.credentials)
        self.assertEqual(2, cache.get(self.cache_key))

        attempt.failures_since_start = 3
        attempt.save()

        self.assertIsNone(cache.get(self.cache_key))
        with self.assertNumQueries(1):
            self.assertEqual(
                3, self.handler.get_failures(self.request, self.credentials)
            )

    def test_user_login_failed_reruns_aggregate_after_invalidation(self):
        self.create_attempt(failures_since_start=2)
        self.handler.get_failures(self.request, self.credentials)

        with CaptureQueriesContext(connection) as capture:
            self.handler.user_login_failed(None, self.credentials, request=self.request)

        self.assertEqual(1, len(self.aggregate_queries(capture)))
        self.assertEqual(3, self.request.axes_failures_since_start)
        self.assertEqual(3, cache.get(self.cache_key))

    def test_shared_cache_invalidation_is_visible_to_other_instances(self):
        first_handler = AxesDatabaseHandler()
        second_handler = AxesDatabaseHandler()
        self.create_attempt(failures_since_start=2)

        first_handler.get_failures(self.request, self.credentials)
        second_handler.invalidate_failure_cache(self.request, self.credentials)

        self.assertIsNone(cache.get(self.cache_key))
        with self.assertNumQueries(1):
            first_handler.get_failures(self.request, self.credentials)

    @override_settings(AXES_RESET_ON_SUCCESS=True)
    def test_successful_login_resets_failure_cache(self):
        self.create_attempt(failures_since_start=2)
        self.handler.get_failures(self.request, self.credentials)

        self.handler.user_logged_in(None, self.request, self.user)

        self.assertIsNone(cache.get(self.cache_key))
        self.assertFalse(AccessAttempt.objects.exists())

        with self.assertNumQueries(1):
            self.assertEqual(
                0, self.handler.get_failures(self.request, self.credentials)
            )

        with self.assertNumQueries(0):
            self.assertEqual(
                0, self.handler.get_failures(self.request, self.credentials)
            )

    def test_reset_attempts_clears_failure_cache(self):
        self.create_attempt(failures_since_start=2)
        self.handler.get_failures(self.request, self.credentials)

        reset_count = self.handler.reset_attempts(username=self.username)

        self.assertEqual(1, reset_count)
        self.assertIsNone(cache.get(self.cache_key))
