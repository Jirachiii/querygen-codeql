/**
 * @name Cwe226 Sensitive Information Uncleared Before Release Logonuser Without Cleanup
 * @description Passwords used in LogonUserA should be cleared from memory using SecureZeroMemory
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/cwe226_sensitive_information_uncleared_before_release_logonuser_without_cleanup
 * @tags security
 *       external/cwe/cwe-226
 */

import cpp
from FunctionCall auth, Function func
where auth.getTarget().getName().matches("LogonUserA%")
  and auth.getEnclosingFunction() = func
  and not exists(FunctionCall cleanup |
    cleanup.getTarget().getName() = "SecureZeroMemory" and
    cleanup.getEnclosingFunction() = func
  )
select auth, "Passwords used in LogonUserA should be cleared from memory using SecureZeroMemory"
