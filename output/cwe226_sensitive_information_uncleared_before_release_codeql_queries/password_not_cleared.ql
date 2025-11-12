/**
 * @name Password Not Cleared
 * @description Password variable not cleared before function return
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/password_not_cleared
 * @tags security
 *       external/cwe/cwe-226
 */

import cpp
import semmle.code.cpp.controlflow.Guards

from LocalVariable v, Function func
where (v.getName().toLowerCase().matches("%password%")
       or v.getName().toLowerCase().matches("%pwd%"))
  and v.getFunction() = func
  and not exists(FunctionCall cleanup |
    cleanup.getTarget().getName().matches("%Zero%") and
    cleanup.getEnclosingFunction() = func
  )
select v, "Password variable not cleared before function return"
