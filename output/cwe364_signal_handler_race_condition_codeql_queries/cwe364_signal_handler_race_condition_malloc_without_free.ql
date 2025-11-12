/**
 * @name Cwe364 Signal Handler Race Condition Malloc Without Free
 * @description Memory allocated with malloc should be freed to prevent memory leaks
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/cwe364_signal_handler_race_condition_malloc_without_free
 * @tags security
 *       external/cwe/cwe-364
 */

import cpp
import cpp
import semmle.code.cpp.dataflow.DataFlow

from FunctionCall malloc, Variable v
where malloc.getTarget().getName() = "malloc"
  and v.getAnAssignedValue() = malloc
  and not exists(FunctionCall free |
    free.getTarget().getName() = "free" and
    free.getArgument(0) = v.getAnAccess()
  )
select malloc, "Memory allocated with malloc should be freed to prevent memory leaks"
