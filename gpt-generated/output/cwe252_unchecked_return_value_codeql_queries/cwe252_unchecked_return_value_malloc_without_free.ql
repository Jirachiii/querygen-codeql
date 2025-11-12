/**
 * @name Cwe252 Unchecked Return Value Malloc Without Free
 * @description Memory allocated with malloc should be freed to prevent memory leaks
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/cwe252_unchecked_return_value_malloc_without_free
 * @tags security
 *       external/cwe/cwe-252
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
