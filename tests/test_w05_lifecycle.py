import os, sys, unittest, uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from habitat_state import Conflict
from habitat_state.lifecycle import LifecycleStore, ClockUntrusted

@unittest.skipUnless(os.getenv("HABITAT_TEST_DATABASE_URL"), "live W05 database not configured")
class LifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = LifecycleStore(os.environ["HABITAT_TEST_DATABASE_URL"])
        cls.store.migrate()

    def setUp(self):
        self.store.reset_for_test()

    def test_wake_is_committed_before_notification_and_redelivered_after_signal_loss(self):
        wake = f"wake:{uuid.uuid4()}"
        objective = f"objective:{uuid.uuid4()}"
        observed = []
        self.store.create_wake(wake, objective, "command:create", 100, lambda _: observed.append(wake))
        self.assertEqual(observed, [wake])
        restarted = LifecycleStore(os.environ["HABITAT_TEST_DATABASE_URL"])
        lease = restarted.lease_wake("worker:01", now=101, lease_seconds=10)
        self.assertEqual(lease["wake_id"], wake)
        first = restarted.acknowledge_wake(wake, "command:ack", "worker:01", now=102)
        duplicate = restarted.acknowledge_wake(wake, "command:ack", "worker:01", now=102)
        self.assertEqual(first, duplicate)

    def test_lost_notification_does_not_lose_wake_and_objective_requires_claim(self):
        wake, objective = f"wake:{uuid.uuid4()}", f"objective:{uuid.uuid4()}"
        with self.assertRaises(RuntimeError):
            self.store.create_wake(wake, objective, "command:lost", 10,
                                   lambda _: (_ for _ in ()).throw(RuntimeError("signal lost")))
        self.assertEqual(self.store.lease_wake("worker:02", now=11, lease_seconds=5)["wake_id"], wake)
        self.store.create_objective(objective, "command:objective", "agent:01")
        self.store.transition_objective(objective, "command:active", "agent:01", "ACTIVE")
        with self.assertRaisesRegex(ValueError, "completion claim"):
            self.store.transition_objective(objective, "command:false-success", "agent:01", "SATISFIED")
        result = self.store.transition_objective(objective, "command:complete", "agent:01",
                                                 "SATISFIED", completion_claim_accepted=True)
        self.assertEqual(result["state"], "SATISFIED")

    def test_expired_activation_is_classified_and_untrusted_clock_is_denied(self):
        activation, objective = f"activation:{uuid.uuid4()}", f"objective:{uuid.uuid4()}"
        self.store.create_activation(activation, objective)
        with self.assertRaises(ClockUntrusted):
            self.store.lease_activation(activation, "worker:01", wall_now=100,
                                        monotonic_now=500, lease_seconds=10, clock_skew=6)
        self.store.lease_activation(activation, "worker:01", wall_now=100,
                                    monotonic_now=500, lease_seconds=10)
        self.store.transition_activation(activation, "PREPARING")
        self.store.transition_activation(activation, "RUNNING")
        self.store.transition_activation(activation, "WAITING_EFFECT")
        recovered = LifecycleStore(os.environ["HABITAT_TEST_DATABASE_URL"]).recover_expired(now=111)
        self.assertEqual(recovered, [{"activation_id": activation,
                                     "classification": "RECONCILIATION_REQUIRED",
                                     "state": "FAILED"}])

if __name__ == "__main__":
    unittest.main()
