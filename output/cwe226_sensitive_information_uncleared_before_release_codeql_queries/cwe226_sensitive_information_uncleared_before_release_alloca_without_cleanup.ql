/**
 * @name Cwe226 Sensitive Information Uncleared Before Release Alloca Without Cleanup
 * @description Memory allocated with ALLOCA should be cleared before function return using SecureZeroMemory
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/cwe226_sensitive_information_uncleared_before_release_alloca_without_cleanup
 * @tags security
 *       external/cwe/cwe-226
 */

import cpp
import semmle.code.cpp.controlflow.Guards

from FunctionCall alloc, Function func
where alloc.getTarget().getName() = "ALLOCA"
  and alloc.getEnclosingFunction() = func
  and not exists(FunctionCall cleanup |
    cleanup.getTarget().getName() = "SecureZeroMemory" and
    cleanup.getEnclosingFunction() = func
  )
select alloc, "Memory allocated with ALLOCA should be cleared before function return using SecureZeroMemory"
