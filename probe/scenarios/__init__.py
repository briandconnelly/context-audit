"""Every probe scenario, in run order."""

from __future__ import annotations

from probe.scenario import Scenario
from probe.scenarios.delivery import DELIVERY
from probe.scenarios.replacement import REPLACEMENT
from probe.scenarios.routing import ROUTING

ALL_SCENARIOS: list[Scenario] = [ROUTING, *DELIVERY, *REPLACEMENT]
