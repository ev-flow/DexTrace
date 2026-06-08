# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Heap allocation budget tests for dextrace.vm.heap.ObjectHeap.

The budget is the cross-platform memory guard for untrusted DEX. It is:
  * cumulative — the running total of *all* allocations in a run, not a
    per-allocation cap (reset per vm.run());
  * sized by *actual bytes* — an array costs its real CPython list backbone
    (8 bytes/slot), a string costs its real footprint (sys.getsizeof);
  * predictive — array cost is charged from the length *before* the backing
    list is built, so `new-array v, HUGE` is rejected without committing RAM.

One-liner verification:
  python -c "from dextrace.vm.heap import ObjectHeap; h=ObjectHeap(memory_limit_mb=1); h.allocate_array('[I', 2**40)" \
    ; echo "exit=$?  (nonzero = rejected, good)"
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.engine import DalvikVM
from dextrace.vm.errors import DexTraceVMError
from dextrace.vm.heap import ObjectHeap

MIB = 1024 * 1024

# A committed DEX whose arraySum() does `new int[3]` then sums it to 60.
ARRAYS_DEX = Path(__file__).parent.parent / "fixtures" / "samples" / "arrays.dex"
ARRAYS_ENTRY = "LArraysTest;->arraySum()I"


class TestAllocationBudget:
    def test_unbounded_by_default(self):
        """No memory_limit_mb -> no budget; large arrays allocate normally."""
        heap = ObjectHeap()
        h = heap.allocate_array("[I", 1_000_000)
        assert len(heap.get_array(h)) == 1_000_000

    def test_huge_array_rejected_before_allocation(self):
        """A 2**40-element request (~8 TiB) must be rejected by arithmetic.

        If the check were not predictive, [0] * 2**40 would try to allocate
        terabytes and either MemoryError or hang. We assert it raises the
        budget error *fast* — proof nothing was committed.
        """
        heap = ObjectHeap(memory_limit_mb=64)
        start = time.monotonic()
        with pytest.raises(DexTraceVMError, match="memory budget exceeded"):
            heap.allocate_array("[I", 2 ** 40)
        assert time.monotonic() - start < 1.0, "rejection was not allocation-free"

    def test_within_budget_allocates(self):
        """An array whose byte cost fits the budget allocates normally."""
        heap = ObjectHeap(memory_limit_mb=64)  # 64 MiB
        h = heap.allocate_array("[I", 1_000_000)  # ~8 MB backbone
        assert len(heap.get_array(h)) == 1_000_000

    def test_budget_is_cumulative_total_not_per_allocation(self):
        """Each allocation fits, but their running total trips the cap."""
        heap = ObjectHeap(memory_limit_mb=8)  # 8 MiB total
        per_call = 200_000  # ~1.6 MB each — comfortably under 8 MiB alone
        with pytest.raises(DexTraceVMError, match="memory budget exceeded"):
            for _ in range(100):  # 100 * 1.6 MB = 160 MB >> 8 MiB
                heap.allocate_array("[I", per_call)
        # And it tripped after roughly budget/per_call calls, not on the first.
        assert heap._used_bytes > 4 * MIB

    def test_string_charged_by_actual_size(self):
        """A large string is charged its real byte footprint, not a flat unit."""
        big = "x" * (4 * MIB)
        heap = ObjectHeap(memory_limit_mb=1)  # 1 MiB — smaller than the string
        with pytest.raises(DexTraceVMError, match="memory budget exceeded"):
            heap.allocate("Ljava/lang/String;", value=big)
        # Same string fits comfortably under a budget that exceeds its size.
        roomy = ObjectHeap(memory_limit_mb=64)
        roomy.allocate("Ljava/lang/String;", value=big)
        assert roomy._used_bytes >= sys.getsizeof(big)

    def test_objects_are_charged(self):
        """Plain object allocation also counts against the running total."""
        heap = ObjectHeap(memory_limit_mb=1)
        heap._max_bytes = 3 * heap._ENTRY_OVERHEAD  # room for exactly three
        heap.allocate("Ljava/lang/Object;")
        heap.allocate("Ljava/lang/Object;")
        heap.allocate("Ljava/lang/Object;")
        with pytest.raises(DexTraceVMError, match="memory budget exceeded"):
            heap.allocate("Ljava/lang/Object;")

    def test_object_charge_matches_size(self):
        """The exact bytes charged for an object = overhead (+ value footprint).

        A bare object costs the fixed entry overhead; an object carrying a
        value additionally costs that value's real sys.getsizeof — so the
        running total reflects actual data size, not a flat per-object unit.
        """
        heap = ObjectHeap(memory_limit_mb=64)

        heap.allocate("Ljava/lang/Object;")  # no value
        assert heap._used_bytes == heap._ENTRY_OVERHEAD

        before = heap._used_bytes
        payload = "y" * 1000
        heap.allocate("Ljava/lang/String;", value=payload)
        assert heap._used_bytes - before == heap._ENTRY_OVERHEAD + sys.getsizeof(payload)

    def test_reset_clears_usage(self):
        """reset() (called at each vm.run()) restores the full budget."""
        heap = ObjectHeap(memory_limit_mb=8)
        heap.allocate_array("[I", 500_000)
        heap.reset()
        assert heap._used_bytes == 0
        h = heap.allocate_array("[I", 500_000)
        assert len(heap.get_array(h)) == 500_000

    def test_boundary_exact_fit_allowed_then_one_more_rejected(self):
        """A request that exactly reaches the limit is allowed; the next byte is not.

        Pins the comparison as ``used + n > max`` (exact fit OK), not ``>=``.
        """
        heap = ObjectHeap(memory_limit_mb=1)
        heap._max_bytes = heap._LIST_OVERHEAD + heap._SLOT_BYTES * 10  # fits [I,10] exactly
        heap.allocate_array("[I", 10)
        assert heap._used_bytes == heap._max_bytes  # filled to the brim
        with pytest.raises(DexTraceVMError, match="memory budget exceeded"):
            heap.allocate_array("[I", 1)  # one element over the line


class TestVMIntegration:
    """The budget reaches the heap through DalvikVM and aborts a real run."""

    @staticmethod
    def _build_vm(memory_limit_mb):
        dex = ARRAYS_DEX.read_bytes()
        resolver = DexResolver(dex)
        sig_map = build_sig_to_codeoff_map(dex, resolver)
        return DalvikVM(dex, resolver, sig_map, memory_limit_mb=memory_limit_mb)

    def test_constructor_threads_limit_into_heap(self):
        """DalvikVM(memory_limit_mb=…) configures the heap's byte budget."""
        assert self._build_vm(64)._heap._max_bytes == 64 * MIB
        assert self._build_vm(None)._heap._max_bytes is None

    def test_run_succeeds_under_generous_budget(self):
        """A generous budget does not disturb a normal run."""
        assert self._build_vm(64).run(ARRAYS_ENTRY) == 60

    def test_run_aborts_when_budget_exceeded(self):
        """A heap budget breach propagates out of vm.run() as DexTraceVMError.

        The dispatch loop only catches return/throw signals, so the heap's
        DexTraceVMError surfaces from run(). We force the breach with a 1-byte
        budget (the public MiB knob can't go small enough for this tiny fixture).
        """
        vm = self._build_vm(64)
        vm._heap._max_bytes = 1  # any allocation now over-budget
        with pytest.raises(DexTraceVMError, match="memory budget exceeded"):
            vm.run(ARRAYS_ENTRY)
