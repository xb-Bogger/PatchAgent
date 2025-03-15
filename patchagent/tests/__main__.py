import sys
import unittest
from pathlib import Path


def run_all_tests():
    test_dir = Path(__file__).parent

    test_suite = unittest.defaultTestLoader.discover(
        start_dir=str(test_dir),
        pattern="test_*.py",
    )

    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
